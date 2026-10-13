/*
 * File: dashboard/sidebar.h
 * Project: KAMBOS Workstation Vault
 *
 * GTK3 dashboard sidebar interface.
 */

#ifndef KAMBOS_DASHBOARD_SIDEBAR_H
#define KAMBOS_DASHBOARD_SIDEBAR_H

#include <gtk/gtk.h>

typedef enum {
    KAMBOS_SIDEBAR_CRYPTOS = 0,
    KAMBOS_SIDEBAR_HISTORY,
    KAMBOS_SIDEBAR_KALLAS,
    KAMBOS_SIDEBAR_QUARANTINE,
    KAMBOS_SIDEBAR_SETTINGS,
    KAMBOS_SIDEBAR_STATS,
    KAMBOS_SIDEBAR_USERS,
    KAMBOS_SIDEBAR_VAULT,
    KAMBOS_SIDEBAR_SECTION_COUNT
} KambosSidebarSection;

// Called whenever the user selects a sidebar section.
typedef void (*KambosSidebarSectionChanged)(
    KambosSidebarSection section,
    gpointer user_data);

/*
 * Create the sidebar and its right-hand vertical divider.
 *
 * The returned widget is intended to be packed into the left side
 * of a horizontal container alongside the dashboard content.
 *
 * The first section, Cryptos, is selected initially.
 */
GtkWidget *kambos_sidebar_new(
    KambosSidebarSectionChanged callback,
    gpointer user_data);

// Change the highlighted section programmatically.
void kambos_sidebar_set_active(
    GtkWidget *sidebar,
    KambosSidebarSection section);

/*
 * Return the currently highlighted section.
 * Returns KAMBOS_SIDEBAR_CRYPTOS if sidebar is invalid.
 */
KambosSidebarSection kambos_sidebar_get_active(
    GtkWidget *sidebar);

#endif /* KAMBOS_DASHBOARD_SIDEBAR_H */
