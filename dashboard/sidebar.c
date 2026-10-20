/*
 * File: dashboard/sidebar.c
 * Project: KAMBOS Workstation Vault
 *
 * GTK3 dashboard navigation sidebar.
 *
 * Features:
 *   - Eleven navigation sections.
 *   - External SVG icons loaded from the images directory.
 *   - Active-section highlighting.
 *   - Green labels on hover, keyboard focus, and active selection.
 *   - Upright labels without unwanted text effects.
 *   - Thin grey vertical divider.
 *   - Callback for application-level navigation.
 */

#include "sidebar.h"

#include <gdk-pixbuf/gdk-pixbuf.h>

#define SIDEBAR_WIDTH 180
#define ICON_SIZE      48
#define BUTTON_HEIGHT  56

typedef struct {
    GtkWidget *root;
    GtkWidget *buttons[KAMBOS_SIDEBAR_SECTION_COUNT];
    KambosSidebarSection active;
    KambosSidebarSectionChanged callback;
    gpointer user_data;
} SidebarState;

typedef struct {
    KambosSidebarSection section;
    const char *label;
    const char *icon_file;
} SidebarItem;

static const SidebarItem sidebar_items[] = {
    { KAMBOS_SIDEBAR_KRYPTOS,    "Kryptos",    "kryptos.svg" },
    { KAMBOS_SIDEBAR_KALLAS,     "Kallas",     "kallas.svg" },
    { KAMBOS_SIDEBAR_VAULT,      "Vault",      "vault.svg" },
    { KAMBOS_SIDEBAR_QUARANTINE, "Quarantine", "quarantine.svg" },
    { KAMBOS_SIDEBAR_HISTORY,    "History",    "history.svg" },
    { KAMBOS_SIDEBAR_STATS,      "Stats",      "stats.svg" },
    { KAMBOS_SIDEBAR_USERS,      "Users",      "users.svg" },
    { KAMBOS_SIDEBAR_SETTINGS,   "Settings",   "settings.svg" },
    { KAMBOS_SIDEBAR_BUGS,       "Bugs",       "bugs.svg" },
    { KAMBOS_SIDEBAR_NEWS,       "News",       "news.svg" },
    { KAMBOS_SIDEBAR_EXIT,       "Exit",       "exit.svg" }
};

/*
 * Load an SVG image from the development images directory,
 * falling back to the installed images directory.
 */
static GtkWidget *
create_file_icon(const char *filename, gint size)
{
    char *path = g_build_filename("images", filename, NULL);

    if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
        g_free(path);
        path = g_build_filename(
            "/usr/share/kambos/images", filename, NULL);
    }

    if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
        g_warning("KAMBOS icon not found: %s", filename);
        g_free(path);

        return gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_LARGE_TOOLBAR);
    }

    GError *error = NULL;
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file_at_scale(
        path, size, size, TRUE, &error);

    if (!pixbuf) {
        g_warning("Unable to load %s: %s",
                  path,
                  error ? error->message : "unknown error");

        g_clear_error(&error);
        g_free(path);

        return gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_LARGE_TOOLBAR);
    }

    GtkWidget *image = gtk_image_new_from_pixbuf(pixbuf);

    g_object_unref(pixbuf);
    g_free(path);

    return image;
}

static void
install_sidebar_css(void)
{
    static gboolean installed = FALSE;

    if (installed)
        return;

    GdkScreen *screen = gdk_screen_get_default();

    if (!screen)
        return;

    static const gchar css[] =
        ".kambos-sidebar {"
        "  padding: 12px 8px;"
        "}"

        ".kambos-sidebar-button {"
        "  min-height: 42px;"
        "  padding: 5px 8px;"
        "  border: 1px solid transparent;"
        "  border-radius: 5px;"
        "  background: transparent;"
        "  background-image: none;"
        "  color: #d2d6dc;"
        "  box-shadow: none;"
        "  text-shadow: none;"
        "}"

        ".kambos-sidebar-button,"
        ".kambos-sidebar-button .kambos-sidebar-label {"
        "  font-style: normal;"
        "  text-shadow: none;"
        "}"

        ".kambos-sidebar-button:hover {"
        "  background: rgba(190, 200, 210, 0.10);"
        "  border-color: rgba(190, 200, 210, 0.14);"
        "}"

        ".kambos-sidebar-button:hover .kambos-sidebar-label,"
        ".kambos-sidebar-button:focus .kambos-sidebar-label {"
        "  color: #00ff66;"
        "}"

        ".kambos-sidebar-button.kambos-sidebar-active,"
        ".kambos-sidebar-button:checked {"
        "  background: rgba(110, 160, 170, 0.20);"
        "  border-color: rgba(125, 180, 190, 0.40);"
        "}"

        ".kambos-sidebar-button.kambos-sidebar-active "
        ".kambos-sidebar-label,"
        ".kambos-sidebar-button:checked "
        ".kambos-sidebar-label {"
        "  color: #00ff66;"
        "}"

        ".kambos-sidebar-button.kambos-sidebar-active:hover "
        ".kambos-sidebar-label,"
        ".kambos-sidebar-button.kambos-sidebar-active:focus "
        ".kambos-sidebar-label,"
        ".kambos-sidebar-button:checked:hover "
        ".kambos-sidebar-label,"
        ".kambos-sidebar-button:checked:focus "
        ".kambos-sidebar-label {"
        "  color: #00ff66;"
        "}"

        ".kambos-sidebar-button label {"
        "  text-shadow: none;"
        "}"

        ".kambos-sidebar-divider {"
        "  background-color: #555a61;"
        "  min-width: 1px;"
        "  margin: 8px 0;"
        "}";

    GtkCssProvider *provider = gtk_css_provider_new();
    GError *error = NULL;

    if (gtk_css_provider_load_from_data(
            provider, css, -1, &error)) {
        gtk_style_context_add_provider_for_screen(
            screen,
            GTK_STYLE_PROVIDER(provider),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

        installed = TRUE;
    } else {
        g_warning("Unable to load sidebar CSS: %s",
                  error ? error->message : "unknown error");
        g_clear_error(&error);
    }

    g_object_unref(provider);
}

static void
set_active_internal(SidebarState *state,
                    KambosSidebarSection section)
{
    if (!state ||
        section < 0 ||
        section >= KAMBOS_SIDEBAR_SECTION_COUNT)
        return;

    state->active = section;

    for (gint i = 0; i < KAMBOS_SIDEBAR_SECTION_COUNT; ++i) {
        GtkWidget *button = state->buttons[i];

        if (!button)
            continue;

        GtkStyleContext *context =
            gtk_widget_get_style_context(button);

        if (i == (gint)section) {
            gtk_style_context_add_class(
                context, "kambos-sidebar-active");
        } else {
            gtk_style_context_remove_class(
                context, "kambos-sidebar-active");
        }

        gtk_widget_set_state_flags(
            button,
            i == (gint)section
                ? GTK_STATE_FLAG_CHECKED
                : GTK_STATE_FLAG_NORMAL,
            TRUE);
    }
}

static void
on_sidebar_button_clicked(GtkButton *button,
                          gpointer user_data)
{
    SidebarState *state = user_data;

    if (!state || !GTK_IS_BUTTON(button))
        return;

    KambosSidebarSection section =
        (KambosSidebarSection)GPOINTER_TO_INT(
            g_object_get_data(
                G_OBJECT(button),
                "kambos-sidebar-section"));

    set_active_internal(state, section);

    if (state->callback)
        state->callback(section, state->user_data);
}

static void
free_sidebar_state(gpointer data)
{
    g_free(data);
}

GtkWidget *
kambos_sidebar_new(KambosSidebarSectionChanged callback,
                   gpointer user_data)
{
    install_sidebar_css();

    SidebarState *state = g_new0(SidebarState, 1);

    state->active = KAMBOS_SIDEBAR_KRYPTOS;
    state->callback = callback;
    state->user_data = user_data;

    /*
     * The root includes the navigation column and its divider.
     * Pack this widget on the left side of the dashboard layout.
     */
    GtkWidget *root = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 0);

    state->root = root;

    gtk_widget_set_name(root, "kambos-dashboard-sidebar");
    gtk_widget_set_size_request(root, SIDEBAR_WIDTH + 1, -1);

    gtk_style_context_add_class(
        gtk_widget_get_style_context(root),
        "kambos-sidebar");

    g_object_set_data_full(
        G_OBJECT(root),
        "kambos-sidebar-state",
        state,
        free_sidebar_state);

    GtkWidget *navigation = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 5);

    gtk_widget_set_size_request(
        navigation, SIDEBAR_WIDTH, -1);
    gtk_widget_set_halign(navigation, GTK_ALIGN_FILL);
    gtk_widget_set_valign(navigation, GTK_ALIGN_FILL);

    gtk_box_pack_start(
        GTK_BOX(root), navigation, FALSE, TRUE, 0);

    for (gint i = 0; i < KAMBOS_SIDEBAR_SECTION_COUNT; ++i) {
        const SidebarItem *item = &sidebar_items[i];

        GtkWidget *button = gtk_button_new();

        gtk_button_set_relief(
            GTK_BUTTON(button), GTK_RELIEF_NONE);
        gtk_widget_set_hexpand(button, TRUE);
        gtk_widget_set_halign(button, GTK_ALIGN_FILL);

        gtk_widget_set_size_request(
            button, SIDEBAR_WIDTH - 16, BUTTON_HEIGHT);

        gtk_style_context_add_class(
            gtk_widget_get_style_context(button),
            "kambos-sidebar-button");

        GtkWidget *row = gtk_box_new(
            GTK_ORIENTATION_HORIZONTAL, 10);

        gtk_widget_set_halign(row, GTK_ALIGN_FILL);

        /*
         * All sidebar icons are external SVG files.
         * No embedded SVG definitions or conversion function
         * are needed.
         */
        GtkWidget *icon = create_file_icon(
            item->icon_file, ICON_SIZE);

        gtk_widget_set_size_request(
            icon, ICON_SIZE, ICON_SIZE);
        gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);

        GtkWidget *label = gtk_label_new(item->label);

        gtk_widget_set_halign(label, GTK_ALIGN_START);
        gtk_widget_set_valign(label, GTK_ALIGN_CENTER);
        gtk_widget_set_hexpand(label, TRUE);

        gtk_style_context_add_class(
            gtk_widget_get_style_context(label),
            "kambos-sidebar-label");

        gtk_box_pack_start(
            GTK_BOX(row), icon, FALSE, FALSE, 2);
        gtk_box_pack_start(
            GTK_BOX(row), label, TRUE, TRUE, 0);

        gtk_container_add(GTK_CONTAINER(button), row);

        g_object_set_data(
            G_OBJECT(button),
            "kambos-sidebar-section",
            GINT_TO_POINTER(item->section));

        g_signal_connect(
            button,
            "clicked",
            G_CALLBACK(on_sidebar_button_clicked),
            state);

        state->buttons[item->section] = button;

        gtk_box_pack_start(
            GTK_BOX(navigation), button, FALSE, FALSE, 0);
    }

    /*
     * A narrow drawing area provides a consistent one-pixel
     * divider regardless of the current GTK theme.
     */
    GtkWidget *divider = gtk_drawing_area_new();

    gtk_widget_set_name(divider, "kambos-sidebar-divider");
    gtk_widget_set_size_request(divider, 1, -1);
    gtk_widget_set_hexpand(divider, FALSE);
    gtk_widget_set_vexpand(divider, TRUE);

    gtk_style_context_add_class(
        gtk_widget_get_style_context(divider),
        "kambos-sidebar-divider");

    gtk_box_pack_start(
        GTK_BOX(root), divider, FALSE, TRUE, 0);

    set_active_internal(state, KAMBOS_SIDEBAR_KRYPTOS);

    return root;
}

void
kambos_sidebar_set_active(GtkWidget *sidebar,
                          KambosSidebarSection section)
{
    if (!GTK_IS_WIDGET(sidebar))
        return;

    SidebarState *state = g_object_get_data(
        G_OBJECT(sidebar), "kambos-sidebar-state");

    if (state)
        set_active_internal(state, section);
}

KambosSidebarSection
kambos_sidebar_get_active(GtkWidget *sidebar)
{
    if (!GTK_IS_WIDGET(sidebar))
        return KAMBOS_SIDEBAR_KRYPTOS;

    SidebarState *state = g_object_get_data(
        G_OBJECT(sidebar), "kambos-sidebar-state");

    return state
        ? state->active
        : KAMBOS_SIDEBAR_KRYPTOS;
}
