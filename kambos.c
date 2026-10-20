/*
 * File: ~/kambos/kambos.c
 * Project: KAMBOS File Encryptor
 *
 * Main GTK3 application window.
 *
 * Responsibilities:
 *   - Main window and custom SVG frame.
 *   - Window controls and dragging.
 *   - Dashboard sidebar and section navigation.
 *   - Kryptos module integration.
 *   - Application CSS and splash screen.
 *
 * Cryptographic operations, file detection, password dialogs,
 * and the Kryptos interface are implemented in: dashboard/kryptos/kryptos.c
 *
 * Build:
 *   make clean && make
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>

#include <gtk/gtk.h>
#include <glib.h>
#include <sodium.h>

#include "splash/splash.h"
#include "dashboard/sidebar.h"
#include "dashboard/kryptos/kryptos.h"

/* -----------------------------------------------------------
 * GTK application state
 * ----------------------------------------------------------- */

typedef struct {
    GtkWidget *window;
    GtkWidget *overlay;
    GtkWidget *frame_area;
    GtkWidget *dashboard_box;
    GtkWidget *sidebar;
    GtkWidget *section_area;
    GtkWidget *section_placeholder;
    GtkWidget *section_placeholder_title;
    GtkWidget *section_placeholder_desc;
    GtkWidget *kryptos_box;

    GtkWidget *minimise_button;
    GtkWidget *restore_button;
    GtkWidget *maximise_button;

    GdkPixbuf *frame_pixbuf;

    char exe_dir[PATH_MAX];
} AppWidgets;

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
    (void)user_data;

    AppWidgets *w = g_object_get_data(
        G_OBJECT(widget), "kambos-app-widgets");

    if (!w || !w->frame_pixbuf)
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

/* -----------------------------------------------------------
 * Window controls
 * ----------------------------------------------------------- */

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

/* -----------------------------------------------------------
 * Frame image loading
 * ----------------------------------------------------------- */

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

/* -----------------------------------------------------------
 * Application CSS
 * ----------------------------------------------------------- */

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

/* -----------------------------------------------------------
 * Window destruction
 * ----------------------------------------------------------- */

static void
on_window_destroy(GtkWidget *widget,
                  gpointer user_data)
{
    (void)widget;

    AppWidgets *w = user_data;

    g_clear_object(&w->frame_pixbuf);

    sodium_memzero(w->exe_dir, sizeof(w->exe_dir));

    g_free(w);
}

/* -----------------------------------------------------------
 * Dashboard section navigation
 * ----------------------------------------------------------- */

static void
on_dashboard_section_changed(KambosSidebarSection section,
                             gpointer user_data)
{
    AppWidgets *w = user_data;

    if (!w ||
        !w->kryptos_box ||
        !w->section_placeholder)
        return;

    const char *title = "KAMBOS";
    const char *description =
        "This dashboard section is being prepared.";

    /*
     * Kryptos owns its interface and state.
     * The main application only controls its visibility.
     */
    if (section == KAMBOS_SIDEBAR_KRYPTOS) {
        gtk_widget_hide(w->section_placeholder);
        gtk_widget_show_all(w->kryptos_box);
        return;
    }

    switch (section) {
    case KAMBOS_SIDEBAR_KALLAS:
        title = "Kallas";
        description =
            "Messaging and communication tools.";
        break;

    case KAMBOS_SIDEBAR_VAULT:
        title = "Vault";
        description =
            "Stored and encrypted files.";
        break;

    case KAMBOS_SIDEBAR_QUARANTINE:
        title = "Quarantine";
        description =
            "Files isolated for inspection & deletion.";
        break;

    case KAMBOS_SIDEBAR_HISTORY:
        title = "History";
        description =
            "Communication and files history.";
        break;

    case KAMBOS_SIDEBAR_STATS:
        title = "Stats";
        description =
            "Communication and file statistics.";
        break;

    case KAMBOS_SIDEBAR_USERS:
        title = "Users";
        description =
            "User and access management.";
        break;

    case KAMBOS_SIDEBAR_SETTINGS:
        title = "Settings";
        description =
            "Application preferences and security settings.";
        break;

    case KAMBOS_SIDEBAR_BUGS:
        title = "Bugs";
        description =
            "Report design & security incidents.";
        break;

    case KAMBOS_SIDEBAR_NEWS:
        title = "News";
        description =
            "Updates and all kind of news.";
        break;

    default:
        title = "KAMBOS";
        description =
            "This dashboard section is not available.";
        break;
    }

    gchar *markup = g_markup_printf_escaped(
        "<span size='xx-large' weight='bold'>%s</span>",
        title);

    gtk_label_set_markup(
        GTK_LABEL(w->section_placeholder_title),
        markup);

    g_free(markup);

    gtk_label_set_text(
        GTK_LABEL(w->section_placeholder_desc),
        description);

    gtk_widget_hide(w->kryptos_box);
    gtk_widget_show_all(w->section_placeholder);
}

/* -----------------------------------------------------------
 * Main application
 * ----------------------------------------------------------- */

int
main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(
            stderr,
            "Error: libsodium initialisation failed.\n");

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
            "it at /usr/share/kambos/images/kambos-app.svg.");

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
        w->window,
        "delete-event",
        G_CALLBACK(on_window_delete),
        w);

    g_signal_connect(
        w->window,
        "destroy",
        G_CALLBACK(on_window_destroy),
        w);

    /* -------------------------------------------------------
     * Window overlay and SVG frame
     * ------------------------------------------------------- */

    w->overlay = gtk_overlay_new();

    gtk_container_add(
        GTK_CONTAINER(w->window),
        w->overlay);

    w->frame_area = gtk_drawing_area_new();

    gtk_widget_set_hexpand(w->frame_area, TRUE);
    gtk_widget_set_vexpand(w->frame_area, TRUE);

    g_object_set_data(
        G_OBJECT(w->frame_area),
        "kambos-app-widgets",
        w);

    gtk_container_add(
        GTK_CONTAINER(w->overlay),
        w->frame_area);

    g_signal_connect(
        w->frame_area,
        "draw",
        G_CALLBACK(draw_app_frame),
        w);

    gtk_widget_add_events(
        w->frame_area,
        GDK_BUTTON_PRESS_MASK);

    g_signal_connect(
        w->frame_area,
        "button-press-event",
        G_CALLBACK(on_drag_region_button_press),
        w);

    g_signal_connect(
        w->window,
        "size-allocate",
        G_CALLBACK(on_window_size_allocate),
        w);

    /* -------------------------------------------------------
     * Dashboard container
     * ------------------------------------------------------- */

    w->dashboard_box = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL,
        0);

    gtk_widget_set_name(
        w->dashboard_box,
        "kambos-dashboard");

    gtk_widget_set_hexpand(w->dashboard_box, TRUE);
    gtk_widget_set_vexpand(w->dashboard_box, TRUE);

    gtk_widget_set_halign(
        w->dashboard_box,
        GTK_ALIGN_FILL);

    gtk_widget_set_valign(
        w->dashboard_box,
        GTK_ALIGN_FILL);

    /*
     * Keep the dashboard positioned consistently inside the SVG
     * frame. The sidebar stays fixed at the start; only the
     * section area expands.
     */
    gtk_widget_set_margin_start(w->dashboard_box, 8);
    gtk_widget_set_margin_end(w->dashboard_box, 28);
    gtk_widget_set_margin_top(w->dashboard_box, 58);
    gtk_widget_set_margin_bottom(w->dashboard_box, 24);

    gtk_overlay_add_overlay(
        GTK_OVERLAY(w->overlay),
        w->dashboard_box);

    /* -------------------------------------------------------
     * Fixed dashboard sidebar
     * ------------------------------------------------------- */

    w->sidebar = kambos_sidebar_new(
        on_dashboard_section_changed,
        w);

    gtk_widget_set_halign(
        w->sidebar,
        GTK_ALIGN_START);

    gtk_widget_set_valign(
        w->sidebar,
        GTK_ALIGN_FILL);

    gtk_widget_set_hexpand(w->sidebar, FALSE);
    gtk_widget_set_vexpand(w->sidebar, TRUE);

    gtk_box_pack_start(
        GTK_BOX(w->dashboard_box),
        w->sidebar,
        FALSE,
        FALSE,
        0);

    /* -------------------------------------------------------
     * Dashboard section area
     * ------------------------------------------------------- */

    w->section_area = gtk_box_new(
        GTK_ORIENTATION_VERTICAL,
        0);

    gtk_widget_set_hexpand(w->section_area, TRUE);
    gtk_widget_set_vexpand(w->section_area, TRUE);

    gtk_widget_set_halign(
        w->section_area,
        GTK_ALIGN_FILL);

    gtk_widget_set_valign(
        w->section_area,
        GTK_ALIGN_FILL);

    gtk_widget_set_margin_start(w->section_area, 18);
    gtk_widget_set_margin_end(w->section_area, 18);
    gtk_widget_set_margin_top(w->section_area, 14);
    gtk_widget_set_margin_bottom(w->section_area, 14);

    gtk_box_pack_start(
        GTK_BOX(w->dashboard_box),
        w->section_area,
        TRUE,
        TRUE,
        0);

    /* -------------------------------------------------------
     * Kryptos module
     * ------------------------------------------------------- */

    /*
     * The Kryptos module owns its encryption/decryption UI and
     * file-operation state. No cryptographic implementation or
     * Kryptos-specific callbacks belong in this file.
     */
    w->kryptos_box = kambos_kryptos_new(w->exe_dir);

    if (!w->kryptos_box) {
        g_warning("Could not initialise the Kryptos module.");

        gtk_widget_destroy(w->window);

        return EXIT_FAILURE;
    }

    gtk_widget_set_hexpand(w->kryptos_box, TRUE);
    gtk_widget_set_vexpand(w->kryptos_box, TRUE);

    gtk_widget_set_halign(
        w->kryptos_box,
        GTK_ALIGN_FILL);

    gtk_widget_set_valign(
        w->kryptos_box,
        GTK_ALIGN_FILL);

    gtk_box_pack_start(
        GTK_BOX(w->section_area),
        w->kryptos_box,
        TRUE,
        TRUE,
        0);

    /* -------------------------------------------------------
     * Placeholder for unfinished dashboard sections
     * ------------------------------------------------------- */

    w->section_placeholder = gtk_box_new(
        GTK_ORIENTATION_VERTICAL,
        12);

    gtk_widget_set_hexpand(
        w->section_placeholder,
        TRUE);

    gtk_widget_set_vexpand(
        w->section_placeholder,
        TRUE);

    gtk_widget_set_halign(
        w->section_placeholder,
        GTK_ALIGN_CENTER);

    gtk_widget_set_valign(
        w->section_placeholder,
        GTK_ALIGN_CENTER);

    gtk_widget_set_margin_start(
        w->section_placeholder,
        24);

    gtk_widget_set_margin_end(
        w->section_placeholder,
        24);

    w->section_placeholder_title = gtk_label_new("History");

    gtk_label_set_markup(
        GTK_LABEL(w->section_placeholder_title),
        "<span size='xx-large' weight='bold'>History</span>");

    gtk_widget_set_halign(
        w->section_placeholder_title,
        GTK_ALIGN_CENTER);

    w->section_placeholder_desc = gtk_label_new(
        "Communication and files history.");

    gtk_label_set_line_wrap(
        GTK_LABEL(w->section_placeholder_desc),
        TRUE);

    gtk_widget_set_halign(
        w->section_placeholder_desc,
        GTK_ALIGN_CENTER);

    gtk_label_set_justify(
        GTK_LABEL(w->section_placeholder_desc),
        GTK_JUSTIFY_CENTER);

    gtk_box_pack_start(
        GTK_BOX(w->section_placeholder),
        w->section_placeholder_title,
        FALSE,
        FALSE,
        4);

    gtk_box_pack_start(
        GTK_BOX(w->section_placeholder),
        w->section_placeholder_desc,
        FALSE,
        FALSE,
        4);

    gtk_box_pack_start(
        GTK_BOX(w->section_area),
        w->section_placeholder,
        TRUE,
        TRUE,
        0);

    /*
     * Start on Kryptos, as the original application did.
     */
    gtk_widget_hide(w->section_placeholder);

    /* -------------------------------------------------------
     * SVG window-control hit areas
     * ------------------------------------------------------- */

    /*
     * Transparent button hit areas sit over the three circles
     * drawn into kambos-app.svg.
     *
     * These are individual overlay widgets. Avoid a full-window
     * GtkFixed overlay that can intercept unrelated clicks.
     */

    w->minimise_button = make_window_control(
        "Minimise",
        G_CALLBACK(on_minimise_clicked),
        w);

    w->restore_button = make_window_control(
        "Restore window",
        G_CALLBACK(on_restore_clicked),
        w);

    w->maximise_button = make_window_control(
        "Maximise",
        G_CALLBACK(on_maximise_clicked),
        w);

    GtkWidget *window_buttons[] = {
        w->minimise_button,
        w->restore_button,
        w->maximise_button
    };

    for (size_t i = 0;
         i < G_N_ELEMENTS(window_buttons);
         ++i) {
        gtk_widget_set_halign(
            window_buttons[i],
            GTK_ALIGN_END);

        gtk_widget_set_valign(
            window_buttons[i],
            GTK_ALIGN_START);

        gtk_overlay_add_overlay(
            GTK_OVERLAY(w->overlay),
            window_buttons[i]);
    }

    /* -------------------------------------------------------
     * Initial layout and application startup
     * ------------------------------------------------------- */

    /*
     * The SVG has no close button. Alt+F4 or the desktop
     * session's window controls can still close the application.
     *
     * Initialise the control positions for the default window
     * dimensions before displaying the splash screen.
     */

    on_window_size_allocate(
        w->window,
        &(GtkAllocation){0, 0, 1280, 800},
        w);

    kambos_splash_show(
        w->window,
        w->exe_dir);

    gtk_main();

    return EXIT_SUCCESS;
}
