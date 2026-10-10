/*
 * File: ~/kambos/kambos.c
 * Project: KAMBOS File Encryptor
 *
 * GTK3 + libsodium Argon2id + OpenSSL AES-256-GCM.
 *
 * RINN format version 2:
 *   Magic | Version | Cipher | KDF | Argon2id ops | Argon2id memory
 *   | Salt | Nonce | Filename length | Original filename
 *   | Ciphertext | GCM authentication tag
 *
 * Security properties:
 *   - The complete header is authenticated as AES-GCM AAD.
 *   - File contents are processed in bounded-size chunks.
 *   - Decrypted plaintext is kept in a private temporary file until
 *     AES-GCM authentication succeeds.
 *   - Output is published only after successful processing.
 *   - Temporary and recovered files use owner-only permissions (0600).
 *   - KDF parameters read from a file are validated before use.
 *
 * Build:
 *   make clean && make
 *
 * NOTE:
 *   This implementation uses RINN format version 2 and is not compatible
 *   with files created by the previous format implementation.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <math.h>

#include <gtk/gtk.h>
#include <glib.h>

#include <sodium.h>
#include <openssl/evp.h>

#include "splash/splash.h"

/* -----------------------------------------------------------
 * RINN format and cryptographic constants
 * ----------------------------------------------------------- */

#define RINN_MAGIC "RINN0711"
#define RINN_MAGIC_LEN 8

#define RINN_VERSION 2
#define RINN_CIPHER_AES_256_GCM 1
#define RINN_KDF_ARGON2ID13 1

#define SALT_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32
#define TAG_LEN 16

#define RINN_FIXED_HEADER_LEN 59
#define RINN_MAX_FILENAME_LEN 4096

#define CRYPTO_CHUNK_SIZE 65536

#define RINN_ARGON_OPS_MIN 1ULL
#define RINN_ARGON_OPS_MAX 10ULL

#define RINN_ARGON_MEM_MIN (8ULL * 1024ULL * 1024ULL)
#define RINN_ARGON_MEM_MAX (256ULL * 1024ULL * 1024ULL)

#define RINN_ARGON_OPS_DEFAULT \
    ((uint64_t)crypto_pwhash_OPSLIMIT_INTERACTIVE)

#define RINN_ARGON_MEM_DEFAULT \
    ((uint64_t)crypto_pwhash_MEMLIMIT_INTERACTIVE)

#define RINN_OFF_VERSION 8
#define RINN_OFF_CIPHER 9
#define RINN_OFF_KDF 10
#define RINN_OFF_OPS 11
#define RINN_OFF_MEM 19
#define RINN_OFF_SALT 27
#define RINN_OFF_NONCE 43
#define RINN_OFF_NAME_LEN 55
#define RINN_OFF_NAME 59

/* -----------------------------------------------------------
 * GTK application state
 * ----------------------------------------------------------- */

typedef struct {
    GtkWidget *window;
    GtkWidget *overlay;
    GtkWidget *frame_area;
    GtkWidget *content_box;
    GtkWidget *drag_region;

    GtkWidget *file_button;
    GtkWidget *action_button;
    GtkWidget *status_label;
    GtkWidget *det_title;
    GtkWidget *det_desc;
    GtkWidget *det_magic;
    GtkWidget *progress;

    GtkWidget *minimise_button;
    GtkWidget *restore_button;
    GtkWidget *maximise_button;

    GdkPixbuf *frame_pixbuf;

    gchar *current_path;
    char exe_dir[PATH_MAX];
} AppWidgets;

/* -----------------------------------------------------------
 * RINN header structure
 * ----------------------------------------------------------- */

typedef struct {
    unsigned char *bytes;
    size_t len;

    uint64_t ops;
    uint64_t mem;

    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];

    char *original_name;
} RinnHeader;

/* -----------------------------------------------------------
 * File detection structures
 * ----------------------------------------------------------- */

typedef struct {
    const char *ext;
    const char *desc;
    const char *magic;
} EncFmt;

typedef enum {
    DET_NONE = 0,
    DET_RINN_MAGIC = 1,
    DET_RINN_EXT = 2,
    DET_OTHER_ENC = 3,
    DET_RANSOM = 4
} DetectKind;

static const char *ransom_exts[] = {
    ".xxx", ".locked", ".krab", ".crypt", ".null",
    ".merry", ".locker", ".enc", ".lockedfile",
    NULL
};

static EncFmt enc_fmts[] = {
    { ".rinn", "KAMBOS Encrypted File", RINN_MAGIC },
    { ".gpg", "GPG/PGP Encrypted", NULL },
    { ".asc", "ASCII-armoured PGP", NULL },
    { ".bfa", "Blowfish Encrypted (BFA)", NULL },
    { ".locker", "Locker-style encrypted", NULL },
    { ".rem", "BlackBerry Encrypted Media", NULL },
    { ".sec", "Secure file", NULL },
    { ".edoc", "Electronically Certified Document", NULL },
    { ".sdoc", "Sealed MS Word Document", NULL },
    { NULL, NULL, NULL }
};

/* -----------------------------------------------------------
 * Utility functions
 * ----------------------------------------------------------- */

static char *get_lower_ext(const char *path)
{
    if (!path)
        return NULL;

    const char *dot = strrchr(path, '.');

    if (!dot)
        return NULL;

    return g_ascii_strdown(dot, -1);
}

static ssize_t read_magic_bytes(
    const char *path,
    unsigned char *buf,
    size_t n)
{
    FILE *f = fopen(path, "rb");

    if (!f)
        return -1;

    size_t got = fread(buf, 1, n, f);
    int failed = ferror(f);

    if (fclose(f) != 0)
        failed = 1;

    if (failed)
        return -1;

    return (ssize_t)got;
}

static int is_ransom_ext(const char *ext)
{
    if (!ext)
        return 0;

    for (const char **p = ransom_exts; *p; ++p) {
        if (g_strcmp0(ext, *p) == 0)
            return 1;
    }

    return 0;
}

static EncFmt *find_format_by_ext(const char *ext)
{
    if (!ext)
        return NULL;

    for (EncFmt *e = enc_fmts; e->ext; ++e) {
        if (g_strcmp0(ext, e->ext) == 0)
            return e;
    }

    return NULL;
}

static int file_write_all(
    FILE *f,
    const unsigned char *buf,
    size_t len)
{
    if (len == 0)
        return 0;

    return fwrite(buf, 1, len, f) == len ? 0 : -1;
}

static void put_u64_be(unsigned char out[8], uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        out[i] = (unsigned char)(value & 0xffU);
        value >>= 8;
    }
}

static uint64_t get_u64_be(const unsigned char in[8])
{
    uint64_t value = 0;

    for (int i = 0; i < 8; ++i)
        value = (value << 8) | in[i];

    return value;
}

static int valid_argon_params(uint64_t ops, uint64_t mem)
{
    if (ops < RINN_ARGON_OPS_MIN ||
        ops > RINN_ARGON_OPS_MAX)
        return 0;

    if (mem < RINN_ARGON_MEM_MIN ||
        mem > RINN_ARGON_MEM_MAX)
        return 0;

    if (mem > (uint64_t)SIZE_MAX)
        return 0;

    return 1;
}

/*
 * Reject unsafe or malformed stored basenames.
 * POSIX filenames cannot contain NUL or '/', but untrusted encrypted
 * metadata can contain arbitrary bytes.
 */
static int valid_original_name(const unsigned char *name, size_t len)
{
    if (!name || len == 0 || len > RINN_MAX_FILENAME_LEN)
        return 0;

    if (memchr(name, '\0', len) != NULL)
        return 0;

    if (memchr(name, '/', len) != NULL)
        return 0;

    if ((len == 1 && name[0] == '.') ||
        (len == 2 && name[0] == '.' && name[1] == '.'))
        return 0;

    return 1;
}

static void free_rinn_header(RinnHeader *h)
{
    if (!h)
        return;

    if (h->bytes) {
        sodium_memzero(h->bytes, h->len + 1);
        free(h->bytes);
    }

    memset(h, 0, sizeof(*h));
}

/* -----------------------------------------------------------
 * RINN header parsing
 * ----------------------------------------------------------- */

static int read_rinn_header(FILE *f, RinnHeader *h)
{
    unsigned char fixed[RINN_FIXED_HEADER_LEN];

    memset(h, 0, sizeof(*h));

    if (fread(fixed, 1, sizeof(fixed), f) != sizeof(fixed))
        return -1;

    if (memcmp(fixed, RINN_MAGIC, RINN_MAGIC_LEN) != 0)
        return -2;

    if (fixed[RINN_OFF_VERSION] != RINN_VERSION)
        return -3;

    if (fixed[RINN_OFF_CIPHER] != RINN_CIPHER_AES_256_GCM)
        return -4;

    if (fixed[RINN_OFF_KDF] != RINN_KDF_ARGON2ID13)
        return -5;

    h->ops = get_u64_be(fixed + RINN_OFF_OPS);
    h->mem = get_u64_be(fixed + RINN_OFF_MEM);

    if (!valid_argon_params(h->ops, h->mem))
        return -6;

    memcpy(h->salt, fixed + RINN_OFF_SALT, SALT_LEN);
    memcpy(h->nonce, fixed + RINN_OFF_NONCE, NONCE_LEN);

    uint32_t name_len_be;
    memcpy(&name_len_be, fixed + RINN_OFF_NAME_LEN,
           sizeof(name_len_be));

    uint32_t name_len = ntohl(name_len_be);

    if (name_len == 0 || name_len > RINN_MAX_FILENAME_LEN)
        return -7;

    h->len = RINN_FIXED_HEADER_LEN + (size_t)name_len;
    h->bytes = malloc(h->len + 1);

    if (!h->bytes) {
        h->len = 0;
        return -8;
    }

    memcpy(h->bytes, fixed, sizeof(fixed));

    if (fread(h->bytes + RINN_FIXED_HEADER_LEN,
              1, name_len, f) != name_len) {
        free_rinn_header(h);
        return -9;
    }

    h->bytes[h->len] = '\0';

    unsigned char *name_bytes =
        h->bytes + RINN_FIXED_HEADER_LEN;

    if (!valid_original_name(name_bytes, name_len)) {
        free_rinn_header(h);
        return -10;
    }

    h->original_name = (char *)name_bytes;

    return 0;
}

static char *read_rinn_original_basename(const char *path)
{
    FILE *f = fopen(path, "rb");

    if (!f)
        return NULL;

    RinnHeader h;
    int rc = read_rinn_header(f, &h);

    if (fclose(f) != 0 && rc == 0)
        rc = -1;

    if (rc != 0)
        return NULL;

    char *result = strdup(h.original_name);
    free_rinn_header(&h);

    return result;
}

/* -----------------------------------------------------------
 * Argon2id key derivation
 * ----------------------------------------------------------- */

static int derive_key(
    const char *password,
    const unsigned char salt[SALT_LEN],
    uint64_t ops,
    uint64_t mem,
    unsigned char key[KEY_LEN])
{
    if (!password || !*password)
        return -1;

    if (!valid_argon_params(ops, mem))
        return -1;

    if (crypto_pwhash(
            key,
            KEY_LEN,
            password,
            (unsigned long long)strlen(password),
            salt,
            (unsigned long long)ops,
            (size_t)mem,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    return 0;
}

/* -----------------------------------------------------------
 * Input/output path safety
 * ----------------------------------------------------------- */

static int validate_input_output(
    const char *inpath,
    const char *outpath,
    struct stat *input_stat)
{
    if (!inpath || !outpath || !*inpath || !*outpath)
        return -1;

    if (stat(inpath, input_stat) != 0)
        return -2;

    if (!S_ISREG(input_stat->st_mode))
        return -3;

    struct stat output_stat;

    if (stat(outpath, &output_stat) == 0) {
        if (input_stat->st_dev == output_stat.st_dev &&
            input_stat->st_ino == output_stat.st_ino)
            return -4;
    } else if (errno != ENOENT) {
        return -5;
    }

    return 0;
}

static int create_temp_output(
    const char *outpath,
    char **tmp_path_out,
    FILE **file_out)
{
    *tmp_path_out = NULL;
    *file_out = NULL;

    gchar *dir = g_path_get_dirname(outpath);

    if (!dir)
        return -1;

    gchar *template = g_build_filename(
        dir, ".kambos-tmp-XXXXXX", NULL);

    g_free(dir);

    if (!template)
        return -2;

    int fd = mkstemp(template);

    if (fd < 0) {
        g_free(template);
        return -3;
    }

    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        unlink(template);
        g_free(template);
        return -4;
    }

    FILE *f = fdopen(fd, "wb");

    if (!f) {
        close(fd);
        unlink(template);
        g_free(template);
        return -5;
    }

    *tmp_path_out = template;
    *file_out = f;

    return 0;
}

static int publish_temp_output(
    FILE *f,
    const char *tmp_path,
    const char *outpath)
{
    int failed = 0;

    if (fflush(f) != 0)
        failed = 1;

    if (!failed && fsync(fileno(f)) != 0)
        failed = 1;

    if (fclose(f) != 0)
        failed = 1;

    if (!failed && rename(tmp_path, outpath) != 0)
        failed = 1;

    if (failed) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

/* -----------------------------------------------------------
 * AES-256-GCM encryption
 * ----------------------------------------------------------- */

static int perform_encrypt(
    const char *inpath,
    const char *outpath,
    const char *password)
{
    int rc = -1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    char *tmp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    unsigned char key[KEY_LEN] = {0};
    unsigned char inbuf[CRYPTO_CHUNK_SIZE];
    unsigned char outbuf[CRYPTO_CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[TAG_LEN];

    unsigned char *header = NULL;
    size_t header_len = 0;

    memset(inbuf, 0, sizeof(inbuf));
    memset(outbuf, 0, sizeof(outbuf));
    memset(tag, 0, sizeof(tag));

    struct stat st;
    int path_rc = validate_input_output(inpath, outpath, &st);

    if (path_rc != 0)
        return -100 + path_rc;

    if (!password || !*password)
        return -110;

    fin = fopen(inpath, "rb");

    if (!fin)
        return -111;

    gchar *basename = g_path_get_basename(inpath);

    if (!basename) {
        rc = -112;
        goto cleanup;
    }

    size_t name_len = strlen(basename);

    if (name_len == 0 || name_len > RINN_MAX_FILENAME_LEN) {
        g_free(basename);
        rc = -113;
        goto cleanup;
    }

    if (!valid_original_name(
            (const unsigned char *)basename, name_len)) {
        g_free(basename);
        rc = -114;
        goto cleanup;
    }

    header_len = RINN_FIXED_HEADER_LEN + name_len;
    header = calloc(1, header_len);

    if (!header) {
        g_free(basename);
        rc = -115;
        goto cleanup;
    }

    uint64_t ops = RINN_ARGON_OPS_DEFAULT;
    uint64_t mem = RINN_ARGON_MEM_DEFAULT;

    if (!valid_argon_params(ops, mem)) {
        g_free(basename);
        rc = -116;
        goto cleanup;
    }

    memcpy(header, RINN_MAGIC, RINN_MAGIC_LEN);
    header[RINN_OFF_VERSION] = RINN_VERSION;
    header[RINN_OFF_CIPHER] = RINN_CIPHER_AES_256_GCM;
    header[RINN_OFF_KDF] = RINN_KDF_ARGON2ID13;

    put_u64_be(header + RINN_OFF_OPS, ops);
    put_u64_be(header + RINN_OFF_MEM, mem);

    randombytes_buf(header + RINN_OFF_SALT, SALT_LEN);
    randombytes_buf(header + RINN_OFF_NONCE, NONCE_LEN);

    uint32_t name_len_be = htonl((uint32_t)name_len);

    memcpy(header + RINN_OFF_NAME_LEN,
           &name_len_be, sizeof(name_len_be));

    memcpy(header + RINN_OFF_NAME, basename, name_len);
    g_free(basename);

    if (derive_key(
            password,
            header + RINN_OFF_SALT,
            ops,
            mem,
            key) != 0) {
        rc = -117;
        goto cleanup;
    }

    int temp_rc = create_temp_output(outpath, &tmp_path, &fout);

    if (temp_rc != 0) {
        rc = -118 + temp_rc;
        goto cleanup;
    }

    if (file_write_all(fout, header, header_len) != 0) {
        rc = -124;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        rc = -125;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(
            ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        rc = -126;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) {
        rc = -127;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(
            ctx, NULL, NULL, key, header + RINN_OFF_NONCE) != 1) {
        rc = -128;
        goto cleanup;
    }

    int outlen = 0;

    /* Authenticate every header byte, including the filename. */
    if (EVP_EncryptUpdate(
            ctx, NULL, &outlen, header, (int)header_len) != 1) {
        rc = -129;
        goto cleanup;
    }

    for (;;) {
        size_t nread = fread(inbuf, 1, sizeof(inbuf), fin);

        if (nread > 0) {
            int produced = 0;

            if (EVP_EncryptUpdate(
                    ctx, outbuf, &produced,
                    inbuf, (int)nread) != 1) {
                rc = -130;
                goto cleanup;
            }

            if (file_write_all(
                    fout, outbuf, (size_t)produced) != 0) {
                rc = -131;
                goto cleanup;
            }

            sodium_memzero(outbuf, sizeof(outbuf));
        }

        if (nread < sizeof(inbuf)) {
            if (ferror(fin)) {
                rc = -132;
                goto cleanup;
            }

            if (feof(fin))
                break;
        }
    }

    int final_len = 0;

    if (EVP_EncryptFinal_ex(ctx, outbuf, &final_len) != 1) {
        rc = -133;
        goto cleanup;
    }

    if (file_write_all(fout, outbuf, (size_t)final_len) != 0) {
        rc = -134;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        rc = -135;
        goto cleanup;
    }

    if (file_write_all(fout, tag, TAG_LEN) != 0) {
        rc = -136;
        goto cleanup;
    }

    if (fclose(fin) != 0) {
        fin = NULL;
        rc = -137;
        goto cleanup;
    }

    fin = NULL;

    FILE *finished_output = fout;
    fout = NULL;

    if (publish_temp_output(
            finished_output, tmp_path, outpath) != 0) {
        rc = -138;
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (fin)
        fclose(fin);

    if (fout) {
        fclose(fout);

        if (tmp_path)
            unlink(tmp_path);
    }

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    if (header) {
        sodium_memzero(header, header_len);
        free(header);
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(inbuf, sizeof(inbuf));
    sodium_memzero(outbuf, sizeof(outbuf));
    sodium_memzero(tag, sizeof(tag));

    g_free(tmp_path);

    return rc;
}

/* -----------------------------------------------------------
 * AES-256-GCM decryption
 * ----------------------------------------------------------- */

static int perform_decrypt(
    const char *inpath,
    const char *outpath,
    const char *password)
{
    int rc = -1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    char *tmp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    unsigned char key[KEY_LEN] = {0};
    unsigned char inbuf[CRYPTO_CHUNK_SIZE];
    unsigned char outbuf[CRYPTO_CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[TAG_LEN];

    memset(inbuf, 0, sizeof(inbuf));
    memset(outbuf, 0, sizeof(outbuf));
    memset(tag, 0, sizeof(tag));

    struct stat input_stat;
    int path_rc = validate_input_output(inpath, outpath, &input_stat);

    if (path_rc != 0)
        return -200 + path_rc;

    if (!password || !*password)
        return -210;

    fin = fopen(inpath, "rb");

    if (!fin)
        return -211;

    struct stat st;

    if (fstat(fileno(fin), &st) != 0 ||
        !S_ISREG(st.st_mode) ||
        st.st_size < 0) {
        rc = -212;
        goto cleanup;
    }

    RinnHeader h;
    int header_rc = read_rinn_header(fin, &h);

    if (header_rc != 0) {
        rc = -220 + header_rc;
        goto cleanup;
    }

    if (st.st_size < (off_t)(h.len + TAG_LEN)) {
        free_rinn_header(&h);
        rc = -230;
        goto cleanup;
    }

    uint64_t file_size = (uint64_t)st.st_size;
    uint64_t payload_len =
        file_size - (uint64_t)h.len - (uint64_t)TAG_LEN;

    if (fseeko(fin, (off_t)h.len, SEEK_SET) != 0) {
        free_rinn_header(&h);
        rc = -231;
        goto cleanup;
    }

    if (derive_key(password, h.salt, h.ops, h.mem, key) != 0) {
        free_rinn_header(&h);
        rc = -232;
        goto cleanup;
    }

    int temp_rc = create_temp_output(outpath, &tmp_path, &fout);

    if (temp_rc != 0) {
        free_rinn_header(&h);
        rc = -233 + temp_rc;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        free_rinn_header(&h);
        rc = -239;
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(
            ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        free_rinn_header(&h);
        rc = -240;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) {
        free_rinn_header(&h);
        rc = -241;
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(
            ctx, NULL, NULL, key, h.nonce) != 1) {
        free_rinn_header(&h);
        rc = -242;
        goto cleanup;
    }

    int outlen = 0;

    /* Authenticate the exact header bytes stored in the encrypted file. */
    if (EVP_DecryptUpdate(
            ctx, NULL, &outlen, h.bytes, (int)h.len) != 1) {
        free_rinn_header(&h);
        rc = -243;
        goto cleanup;
    }

    free_rinn_header(&h);

    uint64_t remaining = payload_len;

    while (remaining > 0) {
        size_t wanted = remaining > sizeof(inbuf)
            ? sizeof(inbuf)
            : (size_t)remaining;

        size_t nread = fread(inbuf, 1, wanted, fin);

        if (nread != wanted) {
            rc = -244;
            goto cleanup;
        }

        int produced = 0;

        if (EVP_DecryptUpdate(
                ctx, outbuf, &produced, inbuf, (int)nread) != 1) {
            rc = -245;
            goto cleanup;
        }

        /*
         * These bytes remain provisional until authentication succeeds.
         * They are written only to a private temporary file.
         */
        if (file_write_all(fout, outbuf, (size_t)produced) != 0) {
            rc = -246;
            goto cleanup;
        }

        sodium_memzero(outbuf, sizeof(outbuf));
        remaining -= (uint64_t)nread;
    }

    if (fread(tag, 1, TAG_LEN, fin) != TAG_LEN) {
        rc = -247;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        rc = -248;
        goto cleanup;
    }

    int final_len = 0;

    /* This is the decisive integrity check. */
    if (EVP_DecryptFinal_ex(ctx, outbuf, &final_len) != 1) {
        rc = -249;
        goto cleanup;
    }

    if (file_write_all(fout, outbuf, (size_t)final_len) != 0) {
        rc = -250;
        goto cleanup;
    }

    if (fclose(fin) != 0) {
        fin = NULL;
        rc = -251;
        goto cleanup;
    }

    fin = NULL;

    FILE *finished_output = fout;
    fout = NULL;

    if (publish_temp_output(
            finished_output, tmp_path, outpath) != 0) {
        rc = -252;
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (fin)
        fclose(fin);

    if (fout) {
        fclose(fout);

        if (tmp_path)
            unlink(tmp_path);
    }

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    sodium_memzero(key, sizeof(key));
    sodium_memzero(inbuf, sizeof(inbuf));
    sodium_memzero(outbuf, sizeof(outbuf));
    sodium_memzero(tag, sizeof(tag));

    g_free(tmp_path);

    return rc;
}

/* -----------------------------------------------------------
 * GTK dialogs
 * ----------------------------------------------------------- */

static gboolean confirm_overwrite(
    GtkWindow *parent,
    const char *path)
{
    GtkWidget *dlg = gtk_message_dialog_new(
        parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_WARNING,
        GTK_BUTTONS_NONE,
        "File %s already exists. Overwrite?",
        path);

    gtk_dialog_add_buttons(
        GTK_DIALOG(dlg),
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Overwrite", GTK_RESPONSE_ACCEPT,
        NULL);

    gboolean ok =
        gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT;

    gtk_widget_destroy(dlg);

    return ok;
}

static char *prompt_password(
    GtkWindow *parent,
    const char *prompt)
{
    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "Password",
        parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_OK", GTK_RESPONSE_OK,
        "_Cancel", GTK_RESPONSE_CANCEL,
        NULL);

    GtkWidget *content =
        gtk_dialog_get_content_area(GTK_DIALOG(dlg));

    GtkWidget *label = gtk_label_new(prompt);

    gtk_box_pack_start(
        GTK_BOX(content), label, FALSE, FALSE, 6);

    GtkWidget *entry = gtk_entry_new();

    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(entry), '*');
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);

    gtk_box_pack_start(
        GTK_BOX(content), entry, FALSE, FALSE, 6);

    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_OK);
    gtk_widget_show_all(dlg);

    char *result = NULL;

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *pw = gtk_entry_get_text(GTK_ENTRY(entry));

        if (pw && *pw)
            result = strdup(pw);
    }

    gtk_entry_set_text(GTK_ENTRY(entry), "");
    gtk_widget_destroy(dlg);

    return result;
}

/* -----------------------------------------------------------
 * File detection
 * ----------------------------------------------------------- */

static DetectKind detect_file(
    const char *path,
    EncFmt **out_fmt,
    int *magic_exists,
    int *magic_matches)
{
    *out_fmt = NULL;
    *magic_exists = 0;
    *magic_matches = 0;

    unsigned char buf[RINN_MAGIC_LEN];
    ssize_t r = read_magic_bytes(path, buf, RINN_MAGIC_LEN);

    if (r >= 1)
        *magic_exists = 1;

    if (r >= (ssize_t)RINN_MAGIC_LEN &&
        memcmp(buf, RINN_MAGIC, RINN_MAGIC_LEN) == 0) {
        *magic_matches = 1;
        *out_fmt = find_format_by_ext(".rinn");
        return DET_RINN_MAGIC;
    }

    char *ext = get_lower_ext(path);

    if (!ext)
        return DET_NONE;

    if (is_ransom_ext(ext)) {
        g_free(ext);
        return DET_RANSOM;
    }

    EncFmt *fmt = find_format_by_ext(ext);

    if (fmt) {
        *out_fmt = fmt;

        if (fmt->magic &&
            r >= (ssize_t)strlen(fmt->magic) &&
            memcmp(buf, fmt->magic, strlen(fmt->magic)) == 0) {
            *magic_matches = 1;
            g_free(ext);
            return DET_RINN_MAGIC;
        }

        gboolean is_rinn = g_strcmp0(fmt->ext, ".rinn") == 0;
        g_free(ext);

        return is_rinn ? DET_RINN_EXT : DET_OTHER_ENC;
    }

    g_free(ext);

    return DET_NONE;
}

/* -----------------------------------------------------------
 * Detection UI
 * ----------------------------------------------------------- */

static void update_detection_ui(AppWidgets *w)
{
    if (!w->current_path) {
        gtk_label_set_text(GTK_LABEL(w->det_title), "");
        gtk_label_set_text(GTK_LABEL(w->det_desc), "");
        gtk_label_set_text(GTK_LABEL(w->det_magic), "");

        gtk_button_set_label(GTK_BUTTON(w->action_button), "Unknown");
        gtk_label_set_text(GTK_LABEL(w->status_label), "Select a file.");

        return;
    }

    EncFmt *fmt = NULL;
    int magic_exists = 0;
    int magic_matches = 0;

    DetectKind kind = detect_file(
        w->current_path, &fmt, &magic_exists, &magic_matches);

    if (kind == DET_RINN_MAGIC || kind == DET_RINN_EXT) {
        gtk_label_set_markup(
            GTK_LABEL(w->det_title),
            "<b>Encrypted file detected. Format: .RINN</b>");

        gtk_label_set_text(
            GTK_LABEL(w->det_desc), "KAMBOS Encrypted File");

        if (magic_matches) {
            gtk_label_set_text(
                GTK_LABEL(w->det_magic), "Magic Header: RINN0711");
        } else if (!magic_exists) {
            gtk_label_set_markup(
                GTK_LABEL(w->det_magic),
                "<span foreground='red'>Magic Header: (none) — Alert!</span>");
        } else {
            gtk_label_set_markup(
                GTK_LABEL(w->det_magic),
                "<span foreground='red'>Magic Header: (unknown) — Alert!</span>");
        }

        gtk_button_set_label(
            GTK_BUTTON(w->action_button), "Decrypt File");

    } else if (kind == DET_OTHER_ENC && fmt) {
        char buf[512];

        g_snprintf(
            buf, sizeof(buf),
            "Encrypted file detected. Format: %s", fmt->ext);

        gtk_label_set_text(GTK_LABEL(w->det_title), buf);
        gtk_label_set_text(
            GTK_LABEL(w->det_desc),
            fmt->desc ? fmt->desc : "(Unknown)");

        gtk_label_set_text(
            GTK_LABEL(w->det_magic),
            magic_exists
                ? "Magic Header: (present)"
                : "Magic Header: (none)");

        gtk_button_set_label(GTK_BUTTON(w->action_button), "Unknown");

    } else if (kind == DET_RANSOM) {
        char *ext = get_lower_ext(w->current_path);

        char *message = g_strdup_printf(
            "Possible ransomware-related extension: %s",
            ext ? ext : "(none)");

        gtk_label_set_text(
            GTK_LABEL(w->det_title),
            "Warning: suspicious file extension");

        gtk_label_set_text(GTK_LABEL(w->det_desc), message);

        gtk_label_set_text(
            GTK_LABEL(w->det_magic),
            "An extension alone cannot confirm ransomware.");

        gtk_button_set_label(GTK_BUTTON(w->action_button), "Unknown");

        g_free(message);
        g_free(ext);

    } else {
        gtk_label_set_text(
            GTK_LABEL(w->det_title),
            "Not recognised as an encrypted file.");

        char *ext = get_lower_ext(w->current_path);

        char *message = g_strdup_printf(
            "File extension: %s", ext ? ext : "(none)");

        gtk_label_set_text(GTK_LABEL(w->det_desc), message);
        gtk_label_set_text(GTK_LABEL(w->det_magic), "");

        gtk_button_set_label(GTK_BUTTON(w->action_button), "Encrypt File");

        g_free(message);
        g_free(ext);
    }

    gtk_widget_set_halign(w->det_title, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(w->det_desc, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(w->det_magic, GTK_ALIGN_CENTER);
}

/* -----------------------------------------------------------
 * File chooser callback
 * ----------------------------------------------------------- */

static void on_file_chooser_changed(
    GtkFileChooserButton *chooser,
    gpointer user_data)
{
    AppWidgets *w = user_data;

    g_free(w->current_path);

    w->current_path = gtk_file_chooser_get_filename(
        GTK_FILE_CHOOSER(chooser));

    update_detection_ui(w);
}

/* -----------------------------------------------------------
 * Main action callback
 * ----------------------------------------------------------- */

static void on_action_button_clicked(
    GtkButton *btn,
    gpointer user_data)
{
    (void)btn;

    AppWidgets *w = user_data;

    if (!w->current_path) {
        gtk_label_set_text(
            GTK_LABEL(w->status_label), "No file selected.");
        return;
    }

    EncFmt *fmt = NULL;
    int magic_exists = 0;
    int magic_matches = 0;

    DetectKind kind = detect_file(
        w->current_path, &fmt, &magic_exists, &magic_matches);

    gchar *input_dir = g_path_get_dirname(w->current_path);

    gboolean decrypting =
        kind == DET_RINN_MAGIC || kind == DET_RINN_EXT;

    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        decrypting ? "Save Decrypted File" : "Save Encrypted File",
        GTK_WINDOW(w->window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT,
        NULL);

    gtk_file_chooser_set_current_folder(
        GTK_FILE_CHOOSER(dlg), input_dir);

    gtk_file_chooser_set_do_overwrite_confirmation(
        GTK_FILE_CHOOSER(dlg), FALSE);

    if (decrypting) {
        char *orig = read_rinn_original_basename(w->current_path);

        if (orig) {
            gtk_file_chooser_set_current_name(
                GTK_FILE_CHOOSER(dlg), orig);
            free(orig);
        } else {
            char *bn = g_path_get_basename(w->current_path);
            size_t len = strlen(bn);

            if (len > 5 && strcmp(bn + len - 5, ".rinn") == 0) {
                char *def = g_strndup(bn, len - 5);
                gtk_file_chooser_set_current_name(
                    GTK_FILE_CHOOSER(dlg), def);
                g_free(def);
            } else {
                gtk_file_chooser_set_current_name(
                    GTK_FILE_CHOOSER(dlg), bn);
            }

            g_free(bn);
        }

    } else {
        char *bn = g_path_get_basename(w->current_path);

        if (!bn) {
            gtk_widget_destroy(dlg);
            g_free(input_dir);
            return;
        }

        /*
         * Remove the final extension, preserving filenames that begin
         * with a dot and have no other extension.
         */
        char *dot = strrchr(bn, '.');

        if (dot && dot != bn)
            *dot = '\0';

        char *suggest = g_strdup_printf("%s.rinn", bn);

        gtk_file_chooser_set_current_name(
            GTK_FILE_CHOOSER(dlg), suggest);

        g_free(suggest);
        g_free(bn);
    }

    if (gtk_dialog_run(GTK_DIALOG(dlg)) != GTK_RESPONSE_ACCEPT) {
        gtk_widget_destroy(dlg);
        g_free(input_dir);
        return;
    }

    char *dest = gtk_file_chooser_get_filename(
        GTK_FILE_CHOOSER(dlg));

    gtk_widget_destroy(dlg);

    if (!dest) {
        g_free(input_dir);
        return;
    }

    if (g_file_test(dest, G_FILE_TEST_EXISTS)) {
        if (!confirm_overwrite(GTK_WINDOW(w->window), dest)) {
            g_free(dest);
            g_free(input_dir);
            return;
        }
    }

    char *pw = prompt_password(
        GTK_WINDOW(w->window),
        decrypting
            ? "Enter password to decrypt:"
            : "Enter password to encrypt:");

    if (!pw) {
        gtk_label_set_text(
            GTK_LABEL(w->status_label),
            decrypting
                ? "Decryption cancelled."
                : "Encryption cancelled.");

        g_free(dest);
        g_free(input_dir);
        return;
    }

    gtk_label_set_text(
        GTK_LABEL(w->status_label),
        decrypting ? "Decrypting..." : "Encrypting...");

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->progress), 0.0);

    /*
     * Processing remains synchronous on the GTK thread. The progress
     * bar reflects completion, not incremental progress.
     */
    int rc = decrypting
        ? perform_decrypt(w->current_path, dest, pw)
        : perform_encrypt(w->current_path, dest, pw);

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->progress), 1.0);

    if (rc == 0) {
        gtk_label_set_text(
            GTK_LABEL(w->status_label),
            decrypting
                ? "Decryption completed and authenticated."
                : "Encryption completed.");
    } else {
        char message[256];

        g_snprintf(
            message, sizeof(message),
            "%s failed (error %d). No output was published on authentication failure.",
            decrypting ? "Decryption" : "Encryption",
            rc);

        gtk_label_set_text(GTK_LABEL(w->status_label), message);
    }

    sodium_memzero(pw, strlen(pw));
    free(pw);

    g_free(dest);
    g_free(input_dir);
}

/* -----------------------------------------------------------
 * Executable directory
 * ----------------------------------------------------------- */

static void determine_exe_dir(char *buf, size_t buflen)
{
    if (!buf || buflen < 2)
        return;

    ssize_t len = readlink("/proc/self/exe", buf, buflen - 1);

    if (len <= 0) {
        buf[0] = '\0';
        return;
    }

    buf[len] = '\0';

    char *d = dirname(buf);

    if (d)
        memmove(buf, d, strlen(d) + 1);
}

/* -----------------------------------------------------------
 * Custom SVG frame
 * ----------------------------------------------------------- */

/*
 * The SVG is a visual frame, not a native window decoration.
 * The drawing area scales it to the window allocation.
 */
static gboolean draw_app_frame(
    GtkWidget *widget,
    cairo_t *cr,
    gpointer user_data)
{
    (void)widget;

    AppWidgets *w = user_data;

    if (!w->frame_pixbuf)
        return FALSE;

    GtkAllocation allocation;
    gtk_widget_get_allocation(widget, &allocation);

    int image_width = gdk_pixbuf_get_width(w->frame_pixbuf);
    int image_height = gdk_pixbuf_get_height(w->frame_pixbuf);

    if (image_width <= 0 || image_height <= 0)
        return FALSE;

    cairo_save(cr);
    cairo_scale(
        cr,
        (double)allocation.width / image_width,
        (double)allocation.height / image_height);

    gdk_cairo_set_source_pixbuf(cr, w->frame_pixbuf, 0, 0);
    cairo_paint(cr);
    cairo_restore(cr);

    return FALSE;
}

static gboolean
on_window_delete(GtkWidget *widget,
                 GdkEvent *event,
                 gpointer user_data)
{
    (void)widget;
    (void)event;
    (void)user_data;

    return FALSE;
}

static void
on_minimise_clicked(GtkButton *button,
                    gpointer user_data)
{
    (void)button;

    AppWidgets *w = user_data;

    gtk_window_iconify(GTK_WINDOW(w->window));
}

static void
on_restore_clicked(GtkButton *button,
                   gpointer user_data)
{
    (void)button;

    AppWidgets *w = user_data;

    if (gtk_window_is_maximized(GTK_WINDOW(w->window))) {
        gtk_window_unmaximize(GTK_WINDOW(w->window));
    } else {
        gtk_window_set_default_size(
            GTK_WINDOW(w->window), 1280, 800);
        gtk_window_unmaximize(GTK_WINDOW(w->window));
    }
}

static void
on_maximise_clicked(GtkButton *button,
                    gpointer user_data)
{
    (void)button;

    AppWidgets *w = user_data;

    if (gtk_window_is_maximized(GTK_WINDOW(w->window)))
        gtk_window_unmaximize(GTK_WINDOW(w->window));
    else
        gtk_window_maximize(GTK_WINDOW(w->window));
}

static gboolean
on_drag_region_button_press(GtkWidget *widget,
                            GdkEventButton *event,
                            gpointer user_data)
{
    (void)widget;

    AppWidgets *w = user_data;

    if (event->type == GDK_BUTTON_PRESS &&
        event->button == GDK_BUTTON_PRIMARY) {
        gtk_window_begin_move_drag(
            GTK_WINDOW(w->window),
            event->button,
            (gint)event->x_root,
            (gint)event->y_root,
            event->time);

        return TRUE;
    }

    return FALSE;
}

static void
on_window_size_allocate(GtkWidget *widget,
                        GtkAllocation *allocation,
                        gpointer user_data)
{
    (void)widget;

    AppWidgets *w = user_data;

    GtkWidget *buttons[] = {
        w->minimise_button,
        w->restore_button,
        w->maximise_button
    };

    /*
     * Scale the controls relative to the original
     * 1280 x 800 SVG frame.
     */
    const double sx =
        (double)allocation->width / 1280.0;

    const double sy =
        (double)allocation->height / 800.0;

    const int button_size =
        MAX(12, (int)(26.0 * MIN(sx, sy)));

    /*
     * Preserve the original button order:
     * Minimise, Restore, Maximise.
     */
    const double centres_from_right[] = {
        110.0, 70.0, 30.0
    };

    const int y =
        MAX(0, (int)(27.0 * sy - button_size / 2.0));

    for (size_t i = 0;
         i < G_N_ELEMENTS(buttons);
         ++i) {
        if (!buttons[i])
            continue;

        const int right_margin = MAX(
            0,
            (int)(centres_from_right[i] * sx
                  - button_size / 2.0));

        gtk_widget_set_size_request(
            buttons[i],
            button_size,
            button_size);

        gtk_widget_set_margin_end(
            buttons[i],
            right_margin);

        gtk_widget_set_margin_top(
            buttons[i],
            y);
    }
}

static GtkWidget *
make_window_control(const char *tooltip,
                    GCallback callback,
                    AppWidgets *w)
{
    GtkWidget *button = gtk_button_new();

    gtk_widget_set_tooltip_text(button, tooltip);
    gtk_widget_set_can_focus(button, FALSE);
    gtk_widget_set_halign(button, GTK_ALIGN_START);
    gtk_widget_set_valign(button, GTK_ALIGN_START);

    g_signal_connect(button, "clicked", callback, w);

    gtk_widget_set_name(button, "kambos-window-control");

    return button;
}

static void
load_frame_image(AppWidgets *w)
{
    /*
     * Development path:
     * images/kambos-app.svg beside the executable.
     */
    gchar *local_path = g_build_filename(
        w->exe_dir,
        "images",
        "kambos-app.svg",
        NULL);

    GError *error = NULL;

    w->frame_pixbuf = gdk_pixbuf_new_from_file(
        local_path,
        &error);

    if (error) {
        g_warning(
            "Could not load frame image '%s': %s",
            local_path,
            error->message);

        g_error_free(error);
        error = NULL;
    }

    g_free(local_path);

    if (w->frame_pixbuf)
        return;

    /*
     * Installed path:
     * /usr/share/kambos/images/kambos-app.svg.
     */
    gchar *installed_path = g_build_filename(
        "/usr/share/kambos",
        "images",
        "kambos-app.svg",
        NULL);

    w->frame_pixbuf = gdk_pixbuf_new_from_file(
        installed_path,
        &error);

    if (error) {
        g_warning(
            "Could not load installed frame image '%s': %s",
            installed_path,
            error->message);

        g_error_free(error);
    }

    g_free(installed_path);
}

static void
set_application_css(const AppWidgets *w)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    GError *error = NULL;

    /*
     * Load the stylesheet from the development directory,
     * relative to the executable.
     */
    gchar *css_path = g_build_filename(
        w->exe_dir,
        "css",
        "style.css",
        NULL);

    gboolean loaded = gtk_css_provider_load_from_path(
        provider,
        css_path,
        &error);

    g_free(css_path);

    /*
     * Fall back to the system installation directory.
     */
    if (!loaded) {
        g_clear_error(&error);

        loaded = gtk_css_provider_load_from_path(
            provider,
            "/usr/share/kambos/css/style.css",
            &error);
    }

    /*
     * Report an error if neither stylesheet could be loaded.
     */
    if (!loaded) {
        g_warning(
            "Could not load application CSS: %s",
            error ? error->message : "Unknown error");

        g_clear_error(&error);
        g_object_unref(provider);
        return;
    }

    /*
     * Apply the stylesheet to the default screen.
     */
    GdkScreen *screen = gdk_screen_get_default();

    if (screen) {
        gtk_style_context_add_provider_for_screen(
            screen,
            GTK_STYLE_PROVIDER(provider),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    }

    g_object_unref(provider);
}

static void
on_information_clicked(GtkButton *button,
                       gpointer user_data)
{
    (void)button;

    AppWidgets *w = user_data;

    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(w->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_INFO,
        GTK_BUTTONS_CLOSE,
        "KAMBOS");

    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(dialog),
        "KAMBOS uses Argon2id for password-based key derivation "
        "and AES-256-GCM for authenticated encryption.\n\n"
        "RINN version 2 authenticates its header, including the "
        "original filename. The filename itself is stored in "
        "plaintext metadata and is therefore visible in the "
        "encrypted file.\n\n"
        "Keep your password safe. KAMBOS cannot recover a "
        "forgotten password.");

    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void
on_window_destroy(GtkWidget *widget,
                  gpointer user_data)
{
    (void)widget;

    AppWidgets *w = user_data;

    g_clear_object(&w->frame_pixbuf);
    g_clear_pointer(&w->current_path, g_free);

    sodium_memzero(w->exe_dir, sizeof(w->exe_dir));

    g_free(w);
}

int
main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: libsodium initialisation failed.\n");
        return EXIT_FAILURE;
    }

    gtk_init(&argc, &argv);

    AppWidgets *w = g_new0(AppWidgets, 1);

    if (!w)
        return EXIT_FAILURE;

    determine_exe_dir(w->exe_dir, sizeof(w->exe_dir));
    load_frame_image(w);
    set_application_css(w);

    if (!w->frame_pixbuf) {
        GtkWidget *dialog = gtk_message_dialog_new(
            NULL,
            GTK_DIALOG_MODAL,
            GTK_MESSAGE_ERROR,
            GTK_BUTTONS_CLOSE,
            "KAMBOS could not load its application frame.");

        gtk_message_dialog_format_secondary_text(
            GTK_MESSAGE_DIALOG(dialog),
            "Place kambos-app.svg beside the executable or install "
            "it at /usr/share/kambos/kambos-app.svg.");

        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);

        g_free(w);
        return EXIT_FAILURE;
    }

    w->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    gtk_window_set_title(GTK_WINDOW(w->window), "KAMBOS");
    gtk_window_set_default_size(GTK_WINDOW(w->window), 1280, 800);
    gtk_window_set_position(GTK_WINDOW(w->window), GTK_WIN_POS_CENTER);
    gtk_window_set_resizable(GTK_WINDOW(w->window), TRUE);
    gtk_window_set_decorated(GTK_WINDOW(w->window), FALSE);
    gtk_widget_set_name(w->window, "kambos-window");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(w->window),
        "kambos-window");

    /*
     * Keep normal window-manager behaviour available, including
     * closing the application with Alt+F4.
     */
    g_signal_connect(
        w->window, "delete-event",
        G_CALLBACK(on_window_delete), w);

    g_signal_connect(
        w->window, "destroy",
        G_CALLBACK(on_window_destroy), w);

    w->overlay = gtk_overlay_new();
    gtk_container_add(GTK_CONTAINER(w->window), w->overlay);

    w->frame_area = gtk_drawing_area_new();
    gtk_widget_set_hexpand(w->frame_area, TRUE);
    gtk_widget_set_vexpand(w->frame_area, TRUE);

    gtk_container_add(
        GTK_CONTAINER(w->overlay), w->frame_area);

    g_signal_connect(
        w->frame_area, "draw",
        G_CALLBACK(draw_app_frame), w);

    gtk_widget_add_events(
        w->frame_area,
        GDK_BUTTON_PRESS_MASK);

    g_signal_connect(
        w->frame_area, "button-press-event",
        G_CALLBACK(on_drag_region_button_press), w);

    g_signal_connect(
        w->window, "size-allocate",
        G_CALLBACK(on_window_size_allocate), w);

    /*
     * The central content sits inside the visual SVG frame.
     * The SVG is not a native window decoration.
     */
    w->content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_name(w->content_box, "kambos-content");
    gtk_widget_set_halign(w->content_box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(w->content_box, GTK_ALIGN_CENTER);
    gtk_widget_set_size_request(w->content_box, 640, 420);

    gtk_overlay_add_overlay(
        GTK_OVERLAY(w->overlay), w->content_box);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(
        GTK_LABEL(title),
        "<span size='xx-large' weight='bold'>Encrypt / Decrypt</span>");
    gtk_box_pack_start(
        GTK_BOX(w->content_box), title, FALSE, FALSE, 6);

    GtkWidget *description = gtk_label_new(
        "Select a file to inspect it or perform a KAMBOS operation.");
    gtk_label_set_line_wrap(GTK_LABEL(description), TRUE);
    gtk_box_pack_start(
        GTK_BOX(w->content_box), description, FALSE, FALSE, 2);

    w->file_button = gtk_file_chooser_button_new(
        "Select a file",
        GTK_FILE_CHOOSER_ACTION_OPEN);

    gtk_box_pack_start(
        GTK_BOX(w->content_box), w->file_button,
        FALSE, FALSE, 4);

    w->det_title = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(w->det_title), TRUE);
    gtk_box_pack_start(
        GTK_BOX(w->content_box), w->det_title,
        FALSE, FALSE, 2);

    w->det_desc = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(w->det_desc), TRUE);
    gtk_box_pack_start(
        GTK_BOX(w->content_box), w->det_desc,
        FALSE, FALSE, 2);

    w->det_magic = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(w->det_magic), TRUE);
    gtk_box_pack_start(
        GTK_BOX(w->content_box), w->det_magic,
        FALSE, FALSE, 2);

    w->action_button = gtk_button_new_with_label("Unknown");
    gtk_widget_set_halign(w->action_button, GTK_ALIGN_CENTER);
    gtk_widget_set_size_request(w->action_button, 180, 42);

    gtk_box_pack_start(
        GTK_BOX(w->content_box), w->action_button,
        FALSE, FALSE, 6);

    w->progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(
        GTK_PROGRESS_BAR(w->progress), FALSE);

    gtk_box_pack_start(
        GTK_BOX(w->content_box), w->progress,
        FALSE, FALSE, 2);

    w->status_label = gtk_label_new("Select a file.");
    gtk_label_set_line_wrap(GTK_LABEL(w->status_label), TRUE);

    gtk_box_pack_start(
        GTK_BOX(w->content_box), w->status_label,
        FALSE, FALSE, 2);

    GtkWidget *information_button =
        gtk_button_new_with_label("Information");

    gtk_widget_set_halign(
        information_button, GTK_ALIGN_CENTER);

    gtk_box_pack_start(
        GTK_BOX(w->content_box), information_button,
        FALSE, FALSE, 2);

    g_signal_connect(
        w->file_button, "file-set",
        G_CALLBACK(on_file_chooser_changed), w);

    g_signal_connect(
        w->action_button, "clicked",
        G_CALLBACK(on_action_button_clicked), w);

    g_signal_connect(
        information_button, "clicked",
        G_CALLBACK(on_information_clicked), w);

    /*
     * Transparent button hit areas sit over the three circles
     * drawn into kambos-app.svg.
     *
     * Window controls are individual overlay widgets.
     * Avoid a full-window GtkFixed overlay, which can
     * intercept clicks intended for the central controls.
     */
     
    w->minimise_button = make_window_control(
        "Minimise",
        G_CALLBACK(on_minimise_clicked), w);

    w->restore_button = make_window_control(
        "Restore window",
        G_CALLBACK(on_restore_clicked), w);

    w->maximise_button = make_window_control(
        "Maximise",
        G_CALLBACK(on_maximise_clicked), w);

    GtkWidget *window_buttons[] = {
        w->minimise_button,
        w->restore_button,
        w->maximise_button
    };

    for (size_t i = 0;
         i < G_N_ELEMENTS(window_buttons);
         ++i) {
        gtk_widget_set_halign(
            window_buttons[i], GTK_ALIGN_END);

        gtk_widget_set_valign(
            window_buttons[i], GTK_ALIGN_START);

        gtk_overlay_add_overlay(
            GTK_OVERLAY(w->overlay),
            window_buttons[i]);
    }

    /*
     * The SVG has no close button. Alt+F4 or the desktop session's
     * window controls can still close the application.
     *
     * Show the splash screen before presenting the main window.
     */

     on_window_size_allocate(
         w->window, &(GtkAllocation){0, 0, 1280, 800}, w);

     update_detection_ui(w);

     kambos_splash_show(
         w->window,
         w->exe_dir);

     gtk_main();

    return EXIT_SUCCESS;
}
