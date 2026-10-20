/*
 * File: dashboard/kryptos/kryptos.h
 * Project: KAMBOS File Encryptor
 *
 * Kryptos module interface.
 *
 * Responsibilities:
 *   - RINN v2 file encryption and decryption.
 *   - File format detection.
 *   - Kryptos dashboard user interface.
 *
 * Cryptographic implementation details remain private to kryptos.c.
 */

#ifndef KAMBOS_KRYPTOS_H
#define KAMBOS_KRYPTOS_H

#include <gtk/gtk.h>

/*
 * Create the Kryptos dashboard interface.
 *
 * exe_dir:
 *   Directory containing the running executable.
 *   Used to locate development assets when required.
 *
 * Returns a newly created GTK widget owned by the caller's container.
 *
 * The returned widget owns its internal Kryptos state and callbacks.
 *
 */
GtkWidget *kambos_kryptos_new(const char *exe_dir);

#endif /* KAMBOS_KRYPTOS_H */
