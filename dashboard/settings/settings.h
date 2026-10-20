/*
 * File: dashboard/settings.h
 * Project: KAMBOS Workstation Vault
 *
 * Settings section interface.
 */

#ifndef KAMBOS_SETTINGS_H
#define KAMBOS_SETTINGS_H

#include <gtk/gtk.h>

/*
 * Create the Settings section.
 *
 * exe_dir is the directory containing the running KAMBOS executable.
 * SVG assets are loaded from exe_dir/images, with an installed fallback.
 */
GtkWidget *kambos_settings_new(const char *exe_dir);

/*
 * Return the current Incognito Mode switch state.
 *
 * This reports local UI state only. It does not suppress API requests.
 */
gboolean kambos_settings_get_incognito(GtkWidget *settings);

#endif /* KAMBOS_SETTINGS_H */
