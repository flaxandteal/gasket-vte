
#ifndef VTE_GASKET_H
#define VTE_GASKET_H

#include <glib-object.h>
#include <cairo.h>

G_BEGIN_DECLS

/**
 * VteGasketError:
 * @VTE_GASKET_ERROR_ENVIRONMENT_SETUP_FAILED: could not set environment variables
 */
typedef enum {
  VTE_GASKET_ERROR_ENVIRONMENT_SETUP_FAILED = 0
} VteGasketError;

GQuark vte_gasket_error_quark (void);

#define VTE_GASKET_ERROR ( vte_gasket_error_quark() )

#define VTE_TYPE_GASKET           (vte_gasket_get_type())
#define VTE_GASKET(obj)           (G_TYPE_CHECK_INSTANCE_CAST ((obj), VTE_TYPE_GASKET, VteGasket))
#define VTE_GASKET_CLASS(klass)   (G_TYPE_CHECK_CLASS_CAST ((klass),  VTE_TYPE_GASKET, VteGasketClass))
#define VTE_IS_GASKET(obj)        (G_TYPE_CHECK_INSTANCE_TYPE ((obj), VTE_TYPE_GASKET))
#define VTE_IS_GASKET_CLASS(obj)  (G_TYPE_CHECK_CLASS_TYPE ((klass),  VTE_TYPE_GASKET))
#define VTE_GASKET_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj),  VTE_TYPE_GASKET, VteGasketClass))

typedef struct _VteGasket      VteGasket;
typedef struct _VteGasketClass VteGasketClass;

GType vte_gasket_get_type(void);

VteGasket *vte_gasket_new (GError **error);
VteGasket *vte_gasket_new_with_uuid(const gchar* uuid, GError **error);

gboolean vte_gasket_set_uuid (VteGasket *gasket, const gchar* uuid_str);
gboolean vte_gasket_make_socket (VteGasket *gasket);
void vte_gasket_child_setup (VteGasket *gasket);
void vte_gasket_update_table (VteGasket *gasket, GHashTable* table);
void vte_gasket_launch_listen (VteGasket *gasket);
void vte_gasket_paint_overlay (VteGasket *gasket, cairo_t *cr);
void vte_gasket_set_invalidation_function (VteGasket *gasket, GSourceFunc function, gpointer user_data);
void vte_gasket_set_target_extents(VteGasket *gasket, int row, int col, int row_count, int column_count, long width, long height);
void vte_gasket_close(VteGasket *gasket);
gpointer vte_gasket_listen (VteGasket *gasket);

G_END_DECLS

#endif
