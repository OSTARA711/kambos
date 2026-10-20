/*
 * File: dashboard/settings.c
 * Project: KAMBOS Workstation Vault
 *
 * GTK3 Settings section.
 *
 * Features:
 *   - Three horizontally arranged settings cards.
 *   - Incognito Mode switch (local UI state only).
 *   - English/French language selector.
 *   - Keyboard shortcuts information dialog.
 *   - External SVG icons with development/installed path fallback.
 */

#include "settings.h"

#include <string.h>

#define SETTINGS_ICON_SIZE 48
#define SETTINGS_CARD_WIDTH 260

typedef struct {
    GtkWidget *incognito_switch;
    GtkWidget *incognito_status;
    GtkWidget *language_combo;
    gchar *exe_dir;
} SettingsState;

static GtkWidget *
create_settings_icon(const char *exe_dir, const char *filename)
{
    char *path = NULL;

    if (exe_dir && *exe_dir) {
        path = g_build_filename(
            exe_dir, "images", filename, NULL);
    }

    if (!path || !g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
        g_free(path);
        path = g_build_filename(
            "/usr/share/kambos/images", filename, NULL);
    }

    if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
        g_warning("Settings icon not found: %s", filename);
        g_free(path);

        return gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_DIALOG);
    }

    GError *error = NULL;
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file_at_scale(
        path,
        SETTINGS_ICON_SIZE,
        SETTINGS_ICON_SIZE,
        TRUE,
        &error);

    if (!pixbuf) {
        g_warning(
            "Unable to load Settings icon %s: %s",
            path,
            error ? error->message : "unknown error");

        g_clear_error(&error);
        g_free(path);

        return gtk_image_new_from_icon_name(
            "image-missing", GTK_ICON_SIZE_DIALOG);
    }

    GtkWidget *image = gtk_image_new_from_pixbuf(pixbuf);

    g_object_unref(pixbuf);
    g_free(path);

    gtk_widget_set_size_request(
        image, SETTINGS_ICON_SIZE, SETTINGS_ICON_SIZE);

    return image;
}

static GtkWidget *
create_card(const char *title,
            const char *description,
            const char *icon_file,
            const char *exe_dir,
            GtkWidget **body_out)
{
    GtkWidget *card = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 12);

    gtk_widget_set_name(card, "kambos-settings-card");
    gtk_widget_set_size_request(
        card, SETTINGS_CARD_WIDTH, 210);
    gtk_widget_set_halign(card, GTK_ALIGN_FILL);
    gtk_widget_set_valign(card, GTK_ALIGN_START);
    gtk_widget_set_margin_start(card, 4);
    gtk_widget_set_margin_end(card, 4);
    gtk_widget_set_margin_top(card, 4);
    gtk_widget_set_margin_bottom(card, 4);

    gtk_style_context_add_class(
        gtk_widget_get_style_context(card),
        "kambos-settings-card");

    GtkWidget *header = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 12);

    gtk_widget_set_halign(header, GTK_ALIGN_FILL);
    gtk_widget_set_valign(header, GTK_ALIGN_START);

    GtkWidget *icon = create_settings_icon(exe_dir, icon_file);
    gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);

    GtkWidget *heading_box = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 4);

    gtk_widget_set_hexpand(heading_box, TRUE);
    gtk_widget_set_valign(heading_box, GTK_ALIGN_CENTER);

    GtkWidget *heading = gtk_label_new(NULL);
    gchar *markup = g_markup_printf_escaped(
        "<span size='large' weight='bold'>%s</span>", title);

    gtk_label_set_markup(GTK_LABEL(heading), markup);
    g_free(markup);

    gtk_widget_set_halign(heading, GTK_ALIGN_START);
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);

    GtkWidget *description_label = gtk_label_new(description);

    gtk_label_set_line_wrap(
        GTK_LABEL(description_label), TRUE);
    gtk_label_set_xalign(
        GTK_LABEL(description_label), 0.0f);
    gtk_widget_set_halign(
        description_label, GTK_ALIGN_START);
    gtk_widget_set_valign(
        description_label, GTK_ALIGN_START);

    gtk_style_context_add_class(
        gtk_widget_get_style_context(description_label),
        "kambos-settings-description");

    gtk_box_pack_start(
        GTK_BOX(heading_box), heading, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(heading_box),
        description_label, FALSE, FALSE, 0);

    gtk_box_pack_start(
        GTK_BOX(header), icon, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(header), heading_box, TRUE, TRUE, 0);

    gtk_box_pack_start(
        GTK_BOX(card), header, FALSE, FALSE, 0);

    GtkWidget *separator = gtk_separator_new(
        GTK_ORIENTATION_HORIZONTAL);

    gtk_box_pack_start(
        GTK_BOX(card), separator, FALSE, FALSE, 0);

    GtkWidget *body = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 8);

    gtk_widget_set_hexpand(body, TRUE);
    gtk_widget_set_valign(body, GTK_ALIGN_START);

    gtk_box_pack_start(
        GTK_BOX(card), body, FALSE, FALSE, 0);

    if (body_out)
        *body_out = body;

    return card;
}

static void
on_incognito_state_changed(GObject *object,
                           GParamSpec *pspec,
                           gpointer user_data)
{
    (void)pspec;

    SettingsState *state = user_data;

    if (!state || !state->incognito_status ||
        !GTK_IS_SWITCH(object))
        return;

    gboolean enabled = gtk_switch_get_active(
        GTK_SWITCH(object));

    gtk_label_set_text(
        GTK_LABEL(state->incognito_status),
        enabled ? "On" : "Off");
}

static void
on_language_changed(GtkComboBox *combo, gpointer user_data)
{
    (void)user_data;

    /*
     * The selector stores the selected language for the UI.
     * Full application translation will be connected separately.
     */
    const gchar *language =
        gtk_combo_box_get_active_id(combo);

    if (language && g_str_equal(language, "fr")) {
        gtk_widget_set_tooltip_text(
            GTK_WIDGET(combo),
            "Français selected. Full translation is not yet enabled.");
    } else {
        gtk_widget_set_tooltip_text(
            GTK_WIDGET(combo),
            "English selected. Full translation is not yet enabled.");
    }
}

static void
on_shortcuts_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;

    GtkWidget *parent = GTK_WIDGET(user_data);
    GtkWidget *toplevel = gtk_widget_get_toplevel(parent);

    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_IS_WINDOW(toplevel) ? GTK_WINDOW(toplevel) : NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_INFO,
        GTK_BUTTONS_CLOSE,
        "%s",
        "Keyboard shortcuts");

    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(dialog),
        "%s",
        "Application-specific keyboard shortcuts have not yet "
        "been registered.");

    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void
free_settings_state(gpointer data)
{
    SettingsState *state = data;

    if (!state)
        return;

    g_free(state->exe_dir);
    g_free(state);
}

GtkWidget *
kambos_settings_new(const char *exe_dir)
{
    static gboolean css_installed = FALSE;

    if (!css_installed) {
        GdkScreen *screen = gdk_screen_get_default();

        if (screen) {
            static const gchar css[] =
                "#kambos-settings-card {"
                "  background-color: rgba(35, 39, 45, 0.94);"
                "  border: 1px solid #505760;"
                "  border-radius: 9px;"
                "  padding: 16px;"
                "}"
                ".kambos-settings-description {"
                "  color: #c4cbd3;"
                "}"
                "#kambos-settings-card button {"
                "  min-height: 34px;"
                "}"
                "#kambos-settings-card switch {"
                "  min-width: 48px;"
                "}";

            GtkCssProvider *provider = gtk_css_provider_new();

            if (gtk_css_provider_load_from_data(
                    provider, css, -1, NULL)) {
                gtk_style_context_add_provider_for_screen(
                    screen,
                    GTK_STYLE_PROVIDER(provider),
                    GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
                css_installed = TRUE;
            }

            g_object_unref(provider);
        }
    }

    SettingsState *state = g_new0(SettingsState, 1);

    state->exe_dir = g_strdup(exe_dir);

    GtkWidget *root = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 18);

    gtk_widget_set_name(root, "kambos-settings");
    gtk_widget_set_hexpand(root, TRUE);
    gtk_widget_set_vexpand(root, TRUE);
    gtk_widget_set_halign(root, GTK_ALIGN_FILL);
    gtk_widget_set_valign(root, GTK_ALIGN_START);
    gtk_widget_set_margin_start(root, 8);
    gtk_widget_set_margin_end(root, 8);
    gtk_widget_set_margin_top(root, 8);

    g_object_set_data_full(
        G_OBJECT(root),
        "kambos-settings-state",
        state,
        free_settings_state);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(
        GTK_LABEL(title),
        "<span size='xx-large' weight='bold'>Settings</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);

    GtkWidget *description = gtk_label_new(
        "Application preferences and security settings.");
    gtk_label_set_xalign(GTK_LABEL(description), 0.0f);
    gtk_widget_set_halign(description, GTK_ALIGN_START);

    gtk_style_context_add_class(
        gtk_widget_get_style_context(description),
        "kambos-settings-description");

    gtk_box_pack_start(
        GTK_BOX(root), title, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(root), description, FALSE, FALSE, 0);

    GtkWidget *cards = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 16);

    gtk_widget_set_hexpand(cards, TRUE);
    gtk_widget_set_halign(cards, GTK_ALIGN_START);
    gtk_widget_set_valign(cards, GTK_ALIGN_START);

    /* Incognito Mode card. */
    GtkWidget *incognito_body = NULL;
    GtkWidget *incognito_card = create_card(
        "Incognito Mode",
        "Limit network activity.",
        "incognito.svg",
        state->exe_dir,
        &incognito_body);

    GtkWidget *incognito_row = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 10);

    gtk_widget_set_hexpand(incognito_row, TRUE);
    gtk_widget_set_valign(incognito_row, GTK_ALIGN_CENTER);

    GtkWidget *incognito_label = gtk_label_new("Status");
    gtk_widget_set_halign(
        incognito_label, GTK_ALIGN_START);
    gtk_widget_set_hexpand(incognito_label, TRUE);

    state->incognito_status = gtk_label_new("Off");
    gtk_widget_set_halign(
        state->incognito_status, GTK_ALIGN_END);

    state->incognito_switch = gtk_switch_new();
    gtk_switch_set_active(
        GTK_SWITCH(state->incognito_switch), FALSE);
    gtk_widget_set_valign(
        state->incognito_switch, GTK_ALIGN_CENTER);

    g_signal_connect(
        state->incognito_switch,
        "notify::active",
        G_CALLBACK(on_incognito_state_changed),
        state);

    gtk_box_pack_start(
        GTK_BOX(incognito_row),
        incognito_label, TRUE, TRUE, 0);
    gtk_box_pack_start(
        GTK_BOX(incognito_row),
        state->incognito_status, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(incognito_row),
        state->incognito_switch, FALSE, FALSE, 0);

    gtk_box_pack_start(
        GTK_BOX(incognito_body),
        incognito_row, FALSE, FALSE, 0);

    /* App language card. */
    GtkWidget *language_body = NULL;
    GtkWidget *language_card = create_card(
        "App language",
        "Choose the preferred interface language.",
        "translator.svg",
        state->exe_dir,
        &language_body);

    state->language_combo = gtk_combo_box_text_new();

    gtk_combo_box_text_append(
        GTK_COMBO_BOX_TEXT(state->language_combo),
        "en", "English");
    gtk_combo_box_text_append(
        GTK_COMBO_BOX_TEXT(state->language_combo),
        "fr", "Français");

    gtk_combo_box_set_active_id(
        GTK_COMBO_BOX(state->language_combo), "en");

    gtk_widget_set_hexpand(
        state->language_combo, TRUE);

    g_signal_connect(
        state->language_combo,
        "changed",
        G_CALLBACK(on_language_changed),
        state);

    gtk_box_pack_start(
        GTK_BOX(language_body),
        state->language_combo, FALSE, FALSE, 0);

    /* Keyboard shortcuts card. */
    GtkWidget *shortcuts_body = NULL;
    GtkWidget *shortcuts_card = create_card(
        "Keyboard shortcuts",
        "View the available keyboard shortcuts.",
        "hotkeys.svg",
        state->exe_dir,
        &shortcuts_body);

    GtkWidget *shortcuts_button =
        gtk_button_new_with_label("View shortcuts");

    gtk_widget_set_halign(
        shortcuts_button, GTK_ALIGN_START);

    g_signal_connect(
        shortcuts_button,
        "clicked",
        G_CALLBACK(on_shortcuts_clicked),
        root);

    gtk_box_pack_start(
        GTK_BOX(shortcuts_body),
        shortcuts_button, FALSE, FALSE, 0);

    gtk_box_pack_start(
        GTK_BOX(cards), incognito_card, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(cards), language_card, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(cards), shortcuts_card, FALSE, FALSE, 0);

    gtk_box_pack_start(
        GTK_BOX(root), cards, FALSE, FALSE, 0);

    return root;
}

gboolean
kambos_settings_get_incognito(GtkWidget *settings)
{
    if (!GTK_IS_WIDGET(settings))
        return FALSE;

    SettingsState *state = g_object_get_data(
        G_OBJECT(settings), "kambos-settings-state");

    if (!state || !GTK_IS_SWITCH(state->incognito_switch))
        return FALSE;

    return gtk_switch_get_active(
        GTK_SWITCH(state->incognito_switch));
}
