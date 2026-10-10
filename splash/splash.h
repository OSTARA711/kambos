#ifndef KAMBOS_SPLASH_H
#define KAMBOS_SPLASH_H

#include <gtk/gtk.h>

/*
 * Display the KAMBOS splash screen.
 *
 * main_window: the already-created, initially hidden main window.
 * exe_dir:     directory containing the executable.
 *
 * The main window is shown when the splash screen is dismissed.
 */
void kambos_splash_show(
    GtkWidget *main_window,
    const char *exe_dir);

#endif /* KAMBOS_SPLASH_H */
