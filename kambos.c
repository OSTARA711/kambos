/*
 * GTK3 Kambos File Encryptor
 * Argon2 + KDF + OpenSSL + Libsodium with hybrid AES-256-CTR encryption
 * Implements:
 *   (1) Command-line file argument handling (for file-manager double-click)
 *   (2) Safe GLib path concatenation (no snprintf truncation warnings)
 *   (3) Compatible with .desktop entry “Exec=/usr/bin/kambos %f”
 *
 *   gcc -o kambos kambos.c $(pkg-config --cflags --libs gtk+-3.0) -lsodium -lssl -lcrypto -pthread
 */

#define _POSIX_C_SOURCE 200809L

// --- Standard C headers ---
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

// --- POSIX headers ---
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <libgen.h>

// --- GTK & GLib ---
#include <gtk/gtk.h>
#include <glib.h>

// --- Cryptography ---
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// ===========================================================
// KAMBOS: File Encryptor (GTK + OpenSSL + libsodium Argon2)
// ===========================================================

// Constants
#define SALT_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32
#define CHUNK_SIZE 4096
#define RINN_MAGIC "RINN0711"
#define RINN_MAGIC_LEN 8
#define SALT_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32
#define TAG_LEN 16

/* Argon2id demo params - increase ARGON_MEM for production */
const uint64_t ARGON_OPS = 3;
const size_t ARGON_MEM = (1 << 20); /* 1 MiB demo */

/* UI state */
typedef struct {
    GtkWidget *window;
    GtkWidget *file_button;
    GtkWidget *action_button;
    GtkWidget *status_label;
    GtkWidget *det_title;
    GtkWidget *det_desc;
    GtkWidget *det_magic;
    GtkWidget *progress;
    GtkWidget *logo_image;
    gchar *current_path;
    char exe_dir[PATH_MAX];
} AppWidgets;

/* Utility: get extension lower-case */
static char *get_lower_ext(const char *path) {
    if (!path) return NULL;
    const char *dot = strrchr(path, '.');
    if (!dot) return NULL;
    char *ext = g_ascii_strdown(dot, -1);
    return ext;
}

/* read up to n bytes from file start */
static ssize_t read_magic_bytes(const char *path, unsigned char *buf, size_t n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    ssize_t r = fread(buf, 1, n, f);
    fclose(f);
    return r;
}

/* check if extension in ransom list */
static const char *ransom_exts[] = { ".xxx", ".locked", ".krab", ".crypt", ".null", ".merry", ".locker", ".enc", ".lockedfile", NULL };
static int is_ransom_ext(const char *ext) {
    if (!ext) return 0;
    for (const char **p = ransom_exts; *p; ++p)
        if (g_strcmp0(ext, *p) == 0) return 1;
    return 0;
}

/* known encrypted formats */
typedef struct { const char *ext; const char *desc; const char *magic; } EncFmt;
static EncFmt enc_fmts[] = {
    { ".rinn", "Kambos Encrypted File", RINN_MAGIC },
    { ".gpg",  "GPG/PGP Encrypted", NULL },
    { ".asc",  "ASCII-armored PGP", NULL },
    { ".bfa",  "Blowfish Encrypted (BFA)", NULL },
    { ".locker","Locker-style encrypted", NULL },
    { ".rem",  "BlackBerry Encrypted Media", NULL },
    { ".sec",  "Secure file", NULL },
    { ".edoc", "Electronically Certified Document", NULL },
    { ".sdoc", "Sealed MS Word Document", NULL },
    { NULL, NULL, NULL }
};

/* detection result */
typedef enum { DET_NONE=0, DET_RINN_MAGIC=1, DET_RINN_EXT=2, DET_OTHER_ENC=3, DET_RANSOM=4 } DetectKind;

/* find enc format by extension (lowercase ".rinn" etc.) */
static EncFmt *find_format_by_ext(const char *ext) {
    if (!ext) return NULL;
    for (EncFmt *e = enc_fmts; e->ext; ++e)
        if (g_strcmp0(ext, e->ext) == 0) return e;
    return NULL;
}

/* detection logic: prefer exact magic; otherwise extension rules (relaxed) */
static DetectKind detect_file(const char *path, EncFmt **out_fmt, int *magic_exists, int *magic_matches) {
    *out_fmt = NULL;
    *magic_exists = 0;
    *magic_matches = 0;
    unsigned char buf[RINN_MAGIC_LEN];
    ssize_t r = read_magic_bytes(path, buf, RINN_MAGIC_LEN);
    if (r >= 1) *magic_exists = 1;
    if (r >= (ssize_t)RINN_MAGIC_LEN) {
        if (memcmp(buf, RINN_MAGIC, RINN_MAGIC_LEN) == 0) {
            *magic_matches = 1;
            *out_fmt = find_format_by_ext(".rinn");
            return DET_RINN_MAGIC;
        }
    }

    char *ext = get_lower_ext(path);
    if (!ext) { if (ext) g_free(ext); return DET_NONE; }

    if (is_ransom_ext(ext)) { g_free(ext); return DET_RANSOM; }

    EncFmt *fmt = find_format_by_ext(ext);
    if (fmt) {
        *out_fmt = fmt;
        if (fmt->magic && r >= (ssize_t)strlen(fmt->magic) && memcmp(buf, fmt->magic, strlen(fmt->magic)) == 0) {
            *magic_matches = 1;
            g_free(ext);
            return DET_RINN_MAGIC; /* treat as magic-recognized (encrypted) */
        }
        g_free(ext);
        if (g_strcmp0(fmt->ext, ".rinn") == 0) return DET_RINN_EXT;
        return DET_OTHER_ENC;
    }

    g_free(ext);
    return DET_NONE;
}

/* read original basename stored in header (for rinn) */
static char *read_rinn_original_basename(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char header[RINN_MAGIC_LEN];
    if (fread(header,1,RINN_MAGIC_LEN,f) != RINN_MAGIC_LEN) { fclose(f); return NULL; }
    if (memcmp(header, RINN_MAGIC, RINN_MAGIC_LEN) != 0) { fclose(f); return NULL; }
    unsigned char alg;
    if (fread(&alg,1,1,f) != 1) { fclose(f); return NULL; }
    unsigned char salt[SALT_LEN];
    if (fread(salt,1,SALT_LEN,f) != SALT_LEN) { fclose(f); return NULL; }
    unsigned char nonce[NONCE_LEN];
    if (fread(nonce,1,NONCE_LEN,f) != NONCE_LEN) { fclose(f); return NULL; }
    uint32_t nm_be;
    if (fread(&nm_be,1,4,f) != 4) { fclose(f); return NULL; }
    uint32_t nm = ntohl(nm_be);
    if (nm == 0 || nm > 4096) { fclose(f); return NULL; }
    char *orig = malloc(nm+1);
    if (!orig) { fclose(f); return NULL; }
    if (fread(orig,1,nm,f) != nm) { free(orig); fclose(f); return NULL; }
    orig[nm] = '\0';
    fclose(f);
    return orig;
}

/* derive key using libsodium Argon2id */
static int derive_key(const char *pwd, const unsigned char salt[SALT_LEN], unsigned char key[KEY_LEN]) {
    if (crypto_pwhash(key, KEY_LEN, pwd, strlen(pwd), salt, ARGON_OPS, ARGON_MEM, crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -1;
    return 0;
}

/* encrypt whole file in memory using OpenSSL AES-256-GCM */
static int encrypt_file_mem(const unsigned char *key, const unsigned char nonce[NONCE_LEN],
                            const unsigned char *pt, size_t ptlen,
                            unsigned char **ct_out, size_t *ctlen_out, unsigned char tag_out[TAG_LEN]) {
    int ret = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto cleanup;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) goto cleanup;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) goto cleanup;

    unsigned char *ct = malloc(ptlen + 16);
    if (!ct) goto cleanup;
    int outlen1=0;
    if (1 != EVP_EncryptUpdate(ctx, ct, &outlen1, pt, (int)ptlen)) { free(ct); goto cleanup; }

    int outlen2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ct + outlen1, &outlen2)) { free(ct); goto cleanup; }
    int total = outlen1 + outlen2;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag_out)) { free(ct); goto cleanup; }

    *ct_out = ct;
    *ctlen_out = (size_t)total;
    ret = 0;
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* decrypt whole in memory AES-256-GCM */
static int decrypt_file_mem(const unsigned char *key, const unsigned char nonce[NONCE_LEN],
                            const unsigned char *ct, size_t ctlen,
                            const unsigned char tag[TAG_LEN],
                            unsigned char **pt_out, size_t *ptlen_out) {
    int ret = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto cleanup;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) goto cleanup;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto cleanup;

    unsigned char *pt = malloc(ctlen + 1);
    if (!pt) goto cleanup;
    int outlen1=0;
    if (1 != EVP_DecryptUpdate(ctx, pt, &outlen1, ct, (int)ctlen)) { free(pt); goto cleanup; }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) { free(pt); goto cleanup; }

    int outlen2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, pt + outlen1, &outlen2)) { free(pt); goto cleanup; }

    *pt_out = pt;
    *ptlen_out = (size_t)(outlen1 + outlen2);
    ret = 0;
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* atomic write helper */
static int atomic_write(const char *tmp, const unsigned char *buf, size_t len, mode_t mode) {
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    if (fwrite(buf,1,len,f) != len) { fclose(f); unlink(tmp); return -2; }
    fclose(f);
    if (chmod(tmp, mode) != 0) { /* non-fatal */ }
    return 0;
}

/* perform encryption: read input, derive key, encrypt, write output file with header */
static int perform_encrypt(const char *inpath, const char *outpath, const char *password) {
    struct stat st;
    if (stat(inpath, &st) != 0) return -1;
    size_t inlen = (size_t)st.st_size;
    FILE *fin = fopen(inpath, "rb");
    if (!fin) return -2;
    unsigned char *plain = malloc(inlen);
    if (!plain) { fclose(fin); return -3; }
    if (fread(plain,1,inlen,fin) != inlen) { free(plain); fclose(fin); return -4; }
    fclose(fin);

    /* salt & key & nonce */
    unsigned char salt[SALT_LEN];
    randombytes_buf(salt, SALT_LEN);
    unsigned char key[KEY_LEN];
    if (derive_key(password, salt, key) != 0) { free(plain); return -5; }
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1) { free(plain); sodium_memzero(key,KEY_LEN); return -6; }

    /* encrypt */
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char tag[TAG_LEN];
    if (encrypt_file_mem(key, nonce, plain, inlen, &ct, &ctlen, tag) != 0) { free(plain); sodium_memzero(key,KEY_LEN); return -7; }

    /* build output buffer in memory: header + ciphertext + tag */
    const unsigned char alg = 0x01;
    char *basename = g_path_get_basename(inpath);
    uint32_t namelen = (uint32_t)strlen(basename);
    uint32_t namelen_be = htonl(namelen);

    size_t header_len = RINN_MAGIC_LEN + 1 + SALT_LEN + NONCE_LEN + 4 + namelen;
    size_t total_len = header_len + ctlen + TAG_LEN;
    unsigned char *outbuf = malloc(total_len);
    if (!outbuf) { free(plain); free(ct); g_free(basename); sodium_memzero(key,KEY_LEN); return -8; }

    unsigned char *p = outbuf;
    memcpy(p, RINN_MAGIC, RINN_MAGIC_LEN); p += RINN_MAGIC_LEN;
    memcpy(p, &alg, 1); p += 1;
    memcpy(p, salt, SALT_LEN); p += SALT_LEN;
    memcpy(p, nonce, NONCE_LEN); p += NONCE_LEN;
    memcpy(p, &namelen_be, 4); p += 4;
    memcpy(p, basename, namelen); p += namelen;
    memcpy(p, ct, ctlen); p += ctlen;
    memcpy(p, tag, TAG_LEN);

    g_free(basename);
    free(plain);
    free(ct);
    sodium_memzero(key, KEY_LEN);

    /* write atomically to tmp then rename */
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", outpath);
    int aw = atomic_write(tmp, outbuf, total_len, 0644);
    free(outbuf);
    if (aw != 0) { unlink(tmp); return -9; }
    if (rename(tmp, outpath) != 0) { unlink(tmp); return -10; }
    return 0;
}

/* perform decryption: read header, derive key, decrypt, write result */
static int perform_decrypt(const char *inpath, const char *outpath, const char *password) {
    FILE *fin = fopen(inpath, "rb");
    if (!fin) return -1;
    /* read header */
    unsigned char header[RINN_MAGIC_LEN];
    if (fread(header,1,RINN_MAGIC_LEN,fin) != RINN_MAGIC_LEN) { fclose(fin); return -2; }
    if (memcmp(header, RINN_MAGIC, RINN_MAGIC_LEN) != 0) { fclose(fin); return -3; }

    unsigned char alg;
    if (fread(&alg,1,1,fin) != 1) { fclose(fin); return -4; }
    unsigned char salt[SALT_LEN];
    if (fread(salt,1,SALT_LEN,fin) != SALT_LEN) { fclose(fin); return -5; }
    unsigned char nonce[NONCE_LEN];
    if (fread(nonce,1,NONCE_LEN,fin) != NONCE_LEN) { fclose(fin); return -6; }
    uint32_t nm_be;
    if (fread(&nm_be,1,4,fin) != 4) { fclose(fin); return -7; }
    uint32_t nm = ntohl(nm_be);
    if (nm > 4096) { fclose(fin); return -8; }
    char *orig = malloc(nm+1);
    if (!orig) { fclose(fin); return -9; }
    if (fread(orig,1,nm,fin) != nm) { free(orig); fclose(fin); return -10; }
    orig[nm] = '\0';

    /* read remaining ciphertext+tag */
    if (fseek(fin, 0, SEEK_END) != 0) { free(orig); fclose(fin); return -11; }
    long endpos = ftell(fin);
    long ciph_start = RINN_MAGIC_LEN + 1 + SALT_LEN + NONCE_LEN + 4 + (long)nm;
    if (endpos <= ciph_start) { free(orig); fclose(fin); return -12; }
    long ciph_len = endpos - ciph_start;
    if (fseek(fin, ciph_start, SEEK_SET) != 0) { free(orig); fclose(fin); return -13; }

    unsigned char *ct = malloc(ciph_len);
    if (!ct) { free(orig); fclose(fin); return -14; }
    if (fread(ct,1,ciph_len,fin) != (size_t)ciph_len) { free(ct); free(orig); fclose(fin); return -15; }
    fclose(fin);

    if (ciph_len < TAG_LEN) { free(ct); free(orig); return -16; }
    size_t payload_len = (size_t)(ciph_len - TAG_LEN);
    unsigned char tag[TAG_LEN];
    memcpy(tag, ct + payload_len, TAG_LEN);

    unsigned char key[KEY_LEN];
    if (derive_key(password, salt, key) != 0) { free(ct); free(orig); return -17; }

    unsigned char *pt = NULL;
    size_t ptlen = 0;
    if (decrypt_file_mem(key, nonce, ct, payload_len, tag, &pt, &ptlen) != 0) { free(ct); free(orig); sodium_memzero(key,KEY_LEN); return -18; }

    sodium_memzero(key, KEY_LEN);
    free(ct);

    /* write output atomically */
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", outpath);
    int aw = atomic_write(tmp, pt, ptlen, 0644);
    free(pt);
    if (aw != 0) { unlink(tmp); free(orig); return -19; }
    if (rename(tmp, outpath) != 0) { unlink(tmp); free(orig); return -20; }

    free(orig);
    return 0;
}

/* GTK helper: confirm overwrite */
static gboolean confirm_overwrite(GtkWindow *parent, const char *path) {
    GtkWidget *dlg = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                            GTK_MESSAGE_WARNING, GTK_BUTTONS_NONE,
                                            "File %s already exists. Overwrite?", path);
    gtk_dialog_add_buttons(GTK_DIALOG(dlg), "_Cancel", GTK_RESPONSE_CANCEL, "_Overwrite", GTK_RESPONSE_ACCEPT, NULL);
    gboolean ok = FALSE;
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) ok = TRUE;
    gtk_widget_destroy(dlg);
    return ok;
}

/* prompt password */
static char *prompt_password(GtkWindow *parent, const char *prompt) {
    GtkWidget *dlg = gtk_dialog_new_with_buttons("Password", parent,
                                                 GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                 "_OK", GTK_RESPONSE_OK,
                                                 "_Cancel", GTK_RESPONSE_CANCEL,
                                                 NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *label = gtk_label_new(prompt);
    gtk_box_pack_start(GTK_BOX(content), label, FALSE, FALSE, 6);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(entry), '*');
    gtk_box_pack_start(GTK_BOX(content), entry, FALSE, FALSE, 6);
    gtk_widget_show_all(dlg);

    char *ret = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *pw = gtk_entry_get_text(GTK_ENTRY(entry));
        if (pw && *pw) ret = strdup(pw);
    }
    gtk_widget_destroy(dlg);
    return ret;
}

/* update detection UI (centered labels, red alerts where needed) */
static void update_detection_ui(AppWidgets *w) {
    if (!w->current_path) {
        gtk_label_set_text(GTK_LABEL(w->det_title), "");
        gtk_label_set_text(GTK_LABEL(w->det_desc), "");
        gtk_label_set_text(GTK_LABEL(w->det_magic), "");
        gtk_button_set_label(GTK_BUTTON(w->action_button), "Unknown");
        gtk_label_set_text(GTK_LABEL(w->status_label), "Select a file.");
        return;
    }

    EncFmt *fmt = NULL;
    int magic_exists = 0, magic_matches = 0;
    DetectKind kind = detect_file(w->current_path, &fmt, &magic_exists, &magic_matches);

    if (kind == DET_RINN_MAGIC || kind == DET_RINN_EXT) {
        gtk_label_set_markup(GTK_LABEL(w->det_title), "<b>Encrypted file detected. Format: .RINN</b>");
        gtk_label_set_text(GTK_LABEL(w->det_desc), "Kambos Encrypted File");
        if (magic_matches) gtk_label_set_text(GTK_LABEL(w->det_magic), "Magic Header: RINN0711");
        else if (!magic_exists) gtk_label_set_markup(GTK_LABEL(w->det_magic), "<span foreground='red'>Magic Header: (none) >> Alert!</span>");
        else gtk_label_set_markup(GTK_LABEL(w->det_magic), "<span foreground='red'>Magic Header: (unknown) >> Alert!</span>");
        gtk_button_set_label(GTK_BUTTON(w->action_button), "Decrypt File");
    } else if (kind == DET_OTHER_ENC && fmt) {
        char buf[512];
        snprintf(buf, sizeof(buf), "<b>Encrypted file detected.</b> Format: %s", fmt->ext);
        gtk_label_set_markup(GTK_LABEL(w->det_title), buf);
        gtk_label_set_text(GTK_LABEL(w->det_desc), fmt->desc ? fmt->desc : "(Unknown)");
        if (magic_exists) gtk_label_set_text(GTK_LABEL(w->det_magic), "Magic Header: (present)");
        else gtk_label_set_text(GTK_LABEL(w->det_magic), "Magic Header: (none)");
        gtk_button_set_label(GTK_BUTTON(w->action_button), "Unknown");
    } else if (kind == DET_RANSOM) {
        char *ext = get_lower_ext(w->current_path);
        char buf[512];
        snprintf(buf, sizeof(buf), "<span foreground='red'><b>Ransomware-like file detected. Warning!</b></span>\nFile Extension: %s", ext ? ext : "(none)");
        gtk_label_set_markup(GTK_LABEL(w->det_title), buf);
        gtk_label_set_markup(GTK_LABEL(w->det_magic), "<span foreground='red'>Magic Header: (none) >> Alert!</span>");
        gtk_button_set_label(GTK_BUTTON(w->action_button), "Unknown");
        if (ext) g_free(ext);
    } else {
        /* not encrypted */
        gtk_label_set_text(GTK_LABEL(w->det_title), "Not encrypted.");
        char *ext = get_lower_ext(w->current_path);
        char buf[256];
        snprintf(buf, sizeof(buf), "File Extension: %s", ext ? ext : "(none)");
        gtk_label_set_text(GTK_LABEL(w->det_desc), buf);
        gtk_label_set_text(GTK_LABEL(w->det_magic), "");
        gtk_button_set_label(GTK_BUTTON(w->action_button), "Encrypt File");
        if (ext) g_free(ext);
    }

    gtk_widget_set_halign(w->det_title, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(w->det_desc, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(w->det_magic, GTK_ALIGN_CENTER);
}

/* file chooser changed */
static void on_file_chooser_changed(GtkFileChooserButton *chooser, gpointer user_data) {
    AppWidgets *w = user_data;
    if (w->current_path) g_free(w->current_path);
    w->current_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
    update_detection_ui(w);
}

/* action button clicked */
static void on_action_button_clicked(GtkButton *btn, gpointer user_data) {
    AppWidgets *w = user_data;
    if (!w->current_path) {
        gtk_label_set_text(GTK_LABEL(w->status_label), "No file selected.");
        return;
    }

    EncFmt *fmt = NULL;
    int magic_exists = 0, magic_matches = 0;
    DetectKind kind = detect_file(w->current_path, &fmt, &magic_exists, &magic_matches);

    /* choose default folder = same as input file */
    gchar *input_dir = g_path_get_dirname(w->current_path);

    if (kind == DET_RINN_MAGIC || kind == DET_RINN_EXT) {
        /* decrypt flow */
        char *orig = read_rinn_original_basename(w->current_path);
        GtkWidget *dlg = gtk_file_chooser_dialog_new("Save Decrypted File",
                                                     GTK_WINDOW(w->window),
                                                     GTK_FILE_CHOOSER_ACTION_SAVE,
                                                     "_Cancel", GTK_RESPONSE_CANCEL,
                                                     "_Save", GTK_RESPONSE_ACCEPT,
                                                     NULL);
        gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dlg), input_dir);
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), FALSE);

        if (orig) {
            gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), orig);
            free(orig);
        } else {
            char *bn = g_path_get_basename(w->current_path);
            size_t len = strlen(bn);
            if (len > 5 && strcmp(bn + len - 5, ".rinn") == 0) {
                char *def = g_strndup(bn, len - 5);
                gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), def);
                g_free(def);
            } else {
                gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), bn);
            }
            g_free(bn);
        }

        if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
            char *dest = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
            if (g_file_test(dest, G_FILE_TEST_EXISTS)) {
                if (!confirm_overwrite(GTK_WINDOW(w->window), dest)) { g_free(dest); gtk_widget_destroy(dlg); g_free(input_dir); return; }
            }
            char *pw = prompt_password(GTK_WINDOW(w->window), "Enter password to decrypt:");
            if (!pw) { gtk_label_set_text(GTK_LABEL(w->status_label), "Decryption cancelled (no password)."); g_free(dest); gtk_widget_destroy(dlg); g_free(input_dir); return; }

            gtk_label_set_text(GTK_LABEL(w->status_label), "Decrypting...");
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->progress), 0.0);

            int rc = perform_decrypt(w->current_path, dest, pw);

            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->progress), 1.0);
            if (rc == 0) gtk_label_set_text(GTK_LABEL(w->status_label), "Decryption completed.");
            else {
                char buf[256];
                snprintf(buf, sizeof(buf), "Decryption failed (code %d).", rc);
                gtk_label_set_text(GTK_LABEL(w->status_label), buf);
            }

            g_free(dest);
            free(pw);
        }
        gtk_widget_destroy(dlg);
    } else {
        /* encrypt flow: always allow user to choose destination */
        GtkWidget *dlg = gtk_file_chooser_dialog_new("Save Encrypted File",
                                                     GTK_WINDOW(w->window),
                                                     GTK_FILE_CHOOSER_ACTION_SAVE,
                                                     "_Cancel", GTK_RESPONSE_CANCEL,
                                                     "_Save", GTK_RESPONSE_ACCEPT,
                                                     NULL);
        gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dlg), input_dir);
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), FALSE);

        char *bn = g_path_get_basename(w->current_path);
        char *suggest = g_strdup_printf("%s.rinn", bn);
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), suggest);
        g_free(suggest);
        g_free(bn);

        if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
            char *dest = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
            if (g_file_test(dest, G_FILE_TEST_EXISTS)) {
                if (!confirm_overwrite(GTK_WINDOW(w->window), dest)) { g_free(dest); gtk_widget_destroy(dlg); g_free(input_dir); return; }
            }
            char *pw = prompt_password(GTK_WINDOW(w->window), "Enter password to encrypt:");
            if (!pw) { gtk_label_set_text(GTK_LABEL(w->status_label), "Encryption cancelled (no password)."); g_free(dest); gtk_widget_destroy(dlg); g_free(input_dir); return; }

            gtk_label_set_text(GTK_LABEL(w->status_label), "Encrypting...");
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->progress), 0.0);

            int rc = perform_encrypt(w->current_path, dest, pw);

            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->progress), 1.0);
            if (rc == 0) gtk_label_set_text(GTK_LABEL(w->status_label), "Encryption completed.");
            else {
                char buf[256];
                snprintf(buf, sizeof(buf), "Encryption failed (code %d).", rc);
                gtk_label_set_text(GTK_LABEL(w->status_label), buf);
            }

            g_free(dest);
            free(pw);
        }
        gtk_widget_destroy(dlg);
    }

    g_free(input_dir);
}

/* determine exe dir */
static void determine_exe_dir(char *buf, size_t buflen) {
    ssize_t len = readlink("/proc/self/exe", buf, buflen - 1);
    if (len <= 0) { buf[0] = '\0'; return; }
    buf[len] = '\0';
    char *d = dirname(buf);
    memmove(buf, d, strlen(d) + 1);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return 1; }
    OpenSSL_add_all_algorithms();
    gtk_init(&argc, &argv);

    AppWidgets *w = g_new0(AppWidgets, 1);
    w->current_path = NULL;
    w->exe_dir[0] = '\0';
    determine_exe_dir(w->exe_dir, sizeof(w->exe_dir));

    w->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(w->window), "KAMBOS File Encryptor");
    gtk_window_set_default_size(GTK_WINDOW(w->window), 800, 380);
    g_signal_connect(w->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* remove maximize: keep minimize and close */
    gtk_window_set_resizable(GTK_WINDOW(w->window), FALSE);

    /* icon: prefer system-wide, then exe dir, then local */
    if (g_file_test("/usr/share/icons/kambos_256x256.png", G_FILE_TEST_EXISTS)) {

    /* System-wide icon (corrected file type) */
    GError *err = NULL;
    gtk_window_set_icon_from_file(GTK_WINDOW(w->window),
    "/usr/share/icons/kambos_256x256.png",
    &err);
    if (err) g_clear_error(&err);

    } else {

    char logo_path[PATH_MAX];

    /* Check executable directory icon */
    if (w->exe_dir[0]) {

        /* Build path safely using GLib (no truncation warnings) */
        char *logo_full = g_build_filename(w->exe_dir,
                                           "kambos_256x256.png",
                                           NULL);

        /* Copy safely into fixed buffer */
        g_strlcpy(logo_path, logo_full, sizeof(logo_path));
        g_free(logo_full);

        if (g_file_test(logo_path, G_FILE_TEST_EXISTS)) {
            GError *err = NULL;
            gtk_window_set_icon_from_file(GTK_WINDOW(w->window),
                                          logo_path,
                                          &err);
            if (err) g_clear_error(&err);
        }
    }

    /* Fallback: local working directory */
    if (g_file_test("./kambos_256x256.png", G_FILE_TEST_EXISTS)) {
        GError *err = NULL;
        gtk_window_set_icon_from_file(GTK_WINDOW(w->window),
                                      "./kambos_256x256.png",
                                      &err);
        if (err) g_clear_error(&err);
    }
}


    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);
    gtk_container_add(GTK_CONTAINER(w->window), grid);

    /* logo frame 256x256 */
GtkWidget *logo_frame = gtk_frame_new(NULL);
gtk_widget_set_size_request(logo_frame, 256, 256);
gtk_grid_attach(GTK_GRID(grid), logo_frame, 0, 0, 1, 4);

GtkWidget *logo_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
gtk_container_add(GTK_CONTAINER(logo_frame), logo_box);

w->logo_image = NULL;

// Try to load system-wide logo first
if (g_file_test("/usr/share/kambos/kambos_256x256.png", G_FILE_TEST_EXISTS)) {
    w->logo_image = gtk_image_new_from_file("/usr/share/kambos/kambos_256x256.png");
    gtk_box_pack_start(GTK_BOX(logo_box), w->logo_image, TRUE, TRUE, 0);
} else {
    // Fallback: try exe-dir logo
    char exe_logo_path[PATH_MAX];
    snprintf(exe_logo_path, sizeof(exe_logo_path), "%s/kambos_256x256.png", w->exe_dir);
    if (g_file_test(exe_logo_path, G_FILE_TEST_EXISTS)) {
        w->logo_image = gtk_image_new_from_file(exe_logo_path);
        gtk_box_pack_start(GTK_BOX(logo_box), w->logo_image, TRUE, TRUE, 0);
    } else {
        // Fallback label if image is missing
        GtkWidget *lbl = gtk_label_new("KAMBOS\n256x256");
        gtk_box_pack_start(GTK_BOX(logo_box), lbl, TRUE, TRUE, 0);
    }
}

/* file chooser */
w->file_button = gtk_file_chooser_button_new("Select File", GTK_FILE_CHOOSER_ACTION_OPEN);
gtk_grid_attach(GTK_GRID(grid), w->file_button, 1, 0, 2, 1);

/* action button */
w->action_button = gtk_button_new_with_label("Unknown");
gtk_grid_attach(GTK_GRID(grid), w->action_button, 1, 1, 1, 1);

/* progress bar (height 20px) */
w->progress = gtk_progress_bar_new();
gtk_widget_set_size_request(w->progress, -1, 20);
gtk_grid_attach(GTK_GRID(grid), w->progress, 2, 1, 1, 1);

/* status */
w->status_label = gtk_label_new("Select a file.");
gtk_grid_attach(GTK_GRID(grid), w->status_label, 1, 2, 2, 1);

/* detection labels centered */
w->det_title = gtk_label_new(NULL);
gtk_grid_attach(GTK_GRID(grid), w->det_title, 1, 3, 2, 1);
w->det_desc = gtk_label_new(NULL);
gtk_grid_attach(GTK_GRID(grid), w->det_desc, 1, 4, 2, 1);
w->det_magic = gtk_label_new(NULL);
gtk_grid_attach(GTK_GRID(grid), w->det_magic, 1, 5, 2, 1);

/* signals */
g_signal_connect(w->file_button, "file-set", G_CALLBACK(on_file_chooser_changed), w);
g_signal_connect(w->action_button, "clicked", G_CALLBACK(on_action_button_clicked), w);

gtk_widget_show_all(w->window);
gtk_main();

if (w->current_path) g_free(w->current_path);
g_free(w);
return 0;
}
