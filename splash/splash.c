/*
 * File: splash/splash.c
 * Project: KAMBOS File Encryptor
 *
 * GTK3 launch splash screen.
 *
 * Features:
 *   - Dark, undecorated splash window.
 *   - Centred KAMBOS SVG logotype.
 *   - Dismissal by mouse click, Enter, or Space.
 *   - Main window appears when the splash is dismissed.
 *   - Supports development and installed asset paths.
 */

#include "splash.h"

#include <gdk-pixbuf/gdk-pixbuf.h>
#include <glib.h>

/* -----------------------------------------------------------
 * Load splash logotype
 * ----------------------------------------------------------- */

static GdkPixbuf *
load_splash_logo(const char *exe_dir)
{
    GError *error = NULL;
    gchar *path = NULL;
    GdkPixbuf *pixbuf = NULL;

    /*
     * Development path:
     * images/kambos.svg relative to the executable.
     */
    path = g_build_filename(
        exe_dir,
        "images",
        "kambos.svg",
        NULL);

    pixbuf = gdk_pixbuf_new_from_file_at_scale(
        path,
        500,
        500,
        TRUE,
        &error);

    if (pixbuf) {
        g_free(path);
        return pixbuf;
    }

    g_clear_error(&error);
    g_free(path);

    /*
     * Installed path:
     * /usr/share/kambos/images/kambos.svg.
     */
    path = g_build_filename(
        "/usr/share/kambos",
        "images",
        "kambos.svg",
        NULL);

    pixbuf = gdk_pixbuf_new_from_file_at_scale(
        path,
        500,
        500,
        TRUE,
        &error);

    if (!pixbuf) {
        g_warning(
            "Could not load KAMBOS splash logo '%s': %s",
            path,
            error ? error->message : "Unknown error");

        g_clear_error(&error);
    }

    g_free(path);

    return pixbuf;
}

/* -----------------------------------------------------------
 * Dismiss splash screen
 * ----------------------------------------------------------- */

static void
dismiss_splash(GtkWidget *splash,
               GtkWidget *main_window)
{
    /*
     * Destroy the splash before presenting the main window.
     */
    gtk_widget_destroy(splash);

    gtk_widget_show_all(main_window);

    gtk_window_present(GTK_WINDOW(main_window));
}

static void
on_splash_clicked(GtkButton *button,
                  gpointer user_data)
{
    GtkWidget *main_window = GTK_WIDGET(user_data);
    GtkWidget *splash = gtk_widget_get_toplevel(
        GTK_WIDGET(button));

    dismiss_splash(splash, main_window);
}

static gboolean
on_splash_delete(GtkWidget *splash,
                 GdkEvent *event,
                 gpointer user_data)
{
    (void)event;

    GtkWidget *main_window = GTK_WIDGET(user_data);

    dismiss_splash(splash, main_window);

    /*
     * The splash was explicitly destroyed above.
     * Prevent GTK from processing the delete a second time.
     */
    return TRUE;
}

/* -----------------------------------------------------------
 * Public splash-screen entry point
 * ----------------------------------------------------------- */

void
kambos_splash_show(GtkWidget *main_window,
                   const char *exe_dir)
{
    if (!GTK_IS_WIDGET(main_window) || !exe_dir)
        return;

    GtkWidget *splash = gtk_window_new(
        GTK_WINDOW_TOPLEVEL);

    gtk_window_set_title(
        GTK_WINDOW(splash),
        "KAMBOS");

    gtk_window_set_decorated(
        GTK_WINDOW(splash),
        FALSE);

    gtk_window_set_resizable(
        GTK_WINDOW(splash),
        FALSE);

    gtk_window_set_position(
        GTK_WINDOW(splash),
        GTK_WIN_POS_CENTER);

    gtk_window_set_default_size(
        GTK_WINDOW(splash),
        1280,
        800);

    gtk_window_set_type_hint(
        GTK_WINDOW(splash),
        GDK_WINDOW_TYPE_HINT_SPLASHSCREEN);

    gtk_window_set_accept_focus(
        GTK_WINDOW(splash),
        TRUE);

    gtk_style_context_add_class(
        gtk_widget_get_style_context(splash),
        "kambos-splash");

    /*
     * A full-window button provides one click target and
     * native keyboard activation using Enter or Space.
     */
    GtkWidget *button = gtk_button_new();

    gtk_button_set_relief(
        GTK_BUTTON(button),
        GTK_RELIEF_NONE);

    gtk_widget_set_hexpand(button, TRUE);
    gtk_widget_set_vexpand(button, TRUE);
    gtk_widget_set_can_focus(button, TRUE);
    gtk_widget_set_can_default(button, TRUE);

    GdkPixbuf *logo = load_splash_logo(exe_dir);
    GtkWidget *image;

    if (logo) {
        image = gtk_image_new_from_pixbuf(logo);
        g_object_unref(logo);
    } else {
        /*
         * Keep the splash usable if the SVG is missing.
         */
        image = gtk_label_new("KAMBOS");
    }

    gtk_widget_set_halign(image, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(image, GTK_ALIGN_CENTER);

    gtk_container_add(
        GTK_CONTAINER(button),
        image);

    gtk_container_add(
        GTK_CONTAINER(splash),
        button);

    /*
     * Enter activates the default button.
     * Space activates the focused button.
     */
    gtk_window_set_default(
        GTK_WINDOW(splash),
        button);

    g_signal_connect(
        button,
        "clicked",
        G_CALLBACK(on_splash_clicked),
        main_window);

    g_signal_connect(
        splash,
        "delete-event",
        G_CALLBACK(on_splash_delete),
        main_window);

    gtk_widget_show_all(splash);

    gtk_widget_grab_focus(button);
}
