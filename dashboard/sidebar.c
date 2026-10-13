/*
 * File: dashboard/sidebar.c
 * Project: KAMBOS Workstation Vault
 *
 * GTK3 dashboard navigation sidebar.
 *
 * Features:
 *   - Eight navigation sections.
 *   - Square SVG icons embedded in this source file.
 *   - Active-section highlighting.
 *   - Thin grey vertical divider.
 *   - Callback for application-level navigation.
 */

#include "sidebar.h"

#include <gdk-pixbuf/gdk-pixbuf.h>
#include <string.h>

#define SIDEBAR_WIDTH 180
#define ICON_SIZE      24

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
    const char *svg;
} SidebarItem;

// SVGs use a shared 32x32 viewBox so every icon has the same square dimensions and visual alignment.
static const char *icon_cryptos =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<circle cx='16' cy='16' r='12'/>"
    "<path d='M20 10h-6a3 3 0 0 0 0 6h4a3 3 0 0 1 0 6h-6'/>"
    "<path d='M16 7v3m0 12v3'/>"
    "</g></svg>";

static const char *icon_history =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<path d='M5 10V4M5 10h6'/>"
    "<path d='M6 9a12 12 0 1 1-1 10'/>"
    "<path d='M16 9v7l5 3'/>"
    "</g></svg>";

static const char *icon_kallas =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<path d='M4 7h24v16H17l-7 5v-5H4z'/>"
    "<path d='M9 12h14M9 17h9'/>"
    "</g></svg>";

static const char *icon_quarantine =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<path d='M16 3 27 7v8c0 7-4 11-11 14C9 26 5 22 5 15V7z'/>"
    "<path d='M16 10v8M16 22h.01'/>"
    "</g></svg>";

static const char *icon_settings =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<circle cx='16' cy='16' r='4'/>"
    "<path d='m13 3 6 0 1 4 3 2 4-1 3 5-3 3v3l3 3-3 5-4-1-3 2-1 4h-6l-1-4-3-2-4 1-3-5 3-3v-3l-3-3 3-5 4 1 3-2z'/>"
    "</g></svg>";

static const char *icon_stats =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<path d='M5 27V5M5 27h23'/>"
    "<rect x='9' y='17' width='4' height='7'/>"
    "<rect x='16' y='11' width='4' height='13'/>"
    "<rect x='23' y='6' width='4' height='18'/>"
    "</g></svg>";

static const char *icon_users =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<circle cx='12' cy='10' r='5'/>"
    "<path d='M3 27v-3a9 9 0 0 1 18 0v3z'/>"
    "<path d='M21 6a5 5 0 0 1 0 9M24 19a7 7 0 0 1 5 7v1'/>"
    "</g></svg>";

static const char *icon_vault =
    "<svg xmlns='http://www.w3.org/2000/svg' "
    "width='32' height='32' viewBox='0 0 32 32'>"
    "<g fill='none' stroke='#b9c2cc' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round'>"
    "<rect x='4' y='4' width='24' height='24' rx='3'/>"
    "<circle cx='16' cy='16' r='7'/>"
    "<circle cx='16' cy='16' r='2'/>"
    "<path d='M16 9v5m7 2h-5M16 23v-5M9 16h5'/>"
    "</g></svg>";

static const SidebarItem sidebar_items[] = {
    { KAMBOS_SIDEBAR_CRYPTOS,   "Cryptos",    NULL },
    { KAMBOS_SIDEBAR_HISTORY,   "History",    NULL },
    { KAMBOS_SIDEBAR_KALLAS,    "Kallas",     NULL },
    { KAMBOS_SIDEBAR_QUARANTINE,"Quarantine", NULL },
    { KAMBOS_SIDEBAR_SETTINGS,  "Settings",   NULL },
    { KAMBOS_SIDEBAR_STATS,     "Stats",      NULL },
    { KAMBOS_SIDEBAR_USERS,     "Users",      NULL },
    { KAMBOS_SIDEBAR_VAULT,     "Vault",      NULL }
};

static const char *
icon_for_section(KambosSidebarSection section)
{
    switch (section) {
    case KAMBOS_SIDEBAR_CRYPTOS:
        return icon_cryptos;
    case KAMBOS_SIDEBAR_HISTORY:
        return icon_history;
    case KAMBOS_SIDEBAR_KALLAS:
        return icon_kallas;
    case KAMBOS_SIDEBAR_QUARANTINE:
        return icon_quarantine;
    case KAMBOS_SIDEBAR_SETTINGS:
        return icon_settings;
    case KAMBOS_SIDEBAR_STATS:
        return icon_stats;
    case KAMBOS_SIDEBAR_USERS:
        return icon_users;
    case KAMBOS_SIDEBAR_VAULT:
        return icon_vault;
    default:
        return icon_vault;
    }
}

// Convert an SVG string into a GTK image.
static GtkWidget *
create_svg_icon(const char *svg)
{
    GError *error = NULL;
    GdkPixbufLoader *loader = gdk_pixbuf_loader_new_with_type(
        "svg", &error);

    if (!loader) {
        g_clear_error(&error);
        return gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_LARGE_TOOLBAR);
    }

    gsize length = strlen(svg);
    gboolean written = gdk_pixbuf_loader_write(
        loader, (const guchar *)svg, length, &error);

    if (!written) {
        g_clear_error(&error);
        g_object_unref(loader);
        return gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_LARGE_TOOLBAR);
    }

    if (!gdk_pixbuf_loader_close(loader, &error)) {
        g_clear_error(&error);
        g_object_unref(loader);
        return gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_LARGE_TOOLBAR);
    }

    GdkPixbuf *pixbuf = gdk_pixbuf_loader_get_pixbuf(loader);
    GtkWidget *image;

    if (pixbuf) {
        g_object_ref(pixbuf);
        image = gtk_image_new_from_pixbuf(pixbuf);
        g_object_unref(pixbuf);
        gtk_image_set_pixel_size(GTK_IMAGE(image), ICON_SIZE);
    } else {
        image = gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_LARGE_TOOLBAR);
    }

    g_object_unref(loader);
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
        "  color: #d2d6dc;"
        "  box-shadow: none;"
        "}"
        ".kambos-sidebar-button:hover {"
        "  background: rgba(190, 200, 210, 0.10);"
        "  border-color: rgba(190, 200, 210, 0.14);"
        "}"
        ".kambos-sidebar-button:checked,"
        ".kambos-sidebar-button.kambos-sidebar-active {"
        "  background: rgba(110, 160, 170, 0.20);"
        "  border-color: rgba(125, 180, 190, 0.40);"
        "  color: #ffffff;"
        "}"
        ".kambos-sidebar-label {"
        "  color: inherit;"
        "}"
        ".kambos-sidebar-divider {"
        "  background-color: #555a61;"
        "  min-width: 1px;"
        "  margin: 8px 0;"
        "}";

    GtkCssProvider *provider = gtk_css_provider_new();

    if (gtk_css_provider_load_from_data(
            provider, css, -1, NULL)) {
        gtk_style_context_add_provider_for_screen(
            screen,
            GTK_STYLE_PROVIDER(provider),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        installed = TRUE;
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

        if (i == section) {
            gtk_style_context_add_class(
                context, "kambos-sidebar-active");
        } else {
            gtk_style_context_remove_class(
                context, "kambos-sidebar-active");
        }

        gtk_widget_set_state_flags(
            button,
            i == section ? GTK_STATE_FLAG_CHECKED
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
            g_object_get_data(G_OBJECT(button),
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

    state->active = KAMBOS_SIDEBAR_CRYPTOS;
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
        gtk_widget_set_size_request(button, SIDEBAR_WIDTH - 16, 42);

        gtk_style_context_add_class(
            gtk_widget_get_style_context(button),
            "kambos-sidebar-button");

        GtkWidget *row = gtk_box_new(
            GTK_ORIENTATION_HORIZONTAL, 10);

        gtk_widget_set_halign(row, GTK_ALIGN_FILL);

        GtkWidget *icon = create_svg_icon(
            icon_for_section(item->section));

        gtk_widget_set_size_request(icon, ICON_SIZE, ICON_SIZE);
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

    set_active_internal(state, KAMBOS_SIDEBAR_CRYPTOS);

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
        return KAMBOS_SIDEBAR_CRYPTOS;

    SidebarState *state = g_object_get_data(
        G_OBJECT(sidebar), "kambos-sidebar-state");

    return state ? state->active : KAMBOS_SIDEBAR_CRYPTOS;
}
