/*
 * libvte <-> Gasket interoperability routines
 *
 * Copyright © 2012- Phil Weir
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <glib-object.h>
#include <uuid/uuid.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <cairo.h>
#include <librsvg/rsvg.h>

#include "vte/vtegasket.h"
#include "vtegasket-private.h"
#include "debug.h"

#define GASKET_MAXFILEPATH 1024
#define GASKET_CABOOSE ("__GASKET_CABOOSE__\n")
#define GASKET_STATION_RESET ("__GASKET_STATION_RESET__")
#define GASKET_ENVIRONMENT_GASKET_ID ("GASKET_ID")
#define GASKET_ENVIRONMENT_GASKET_SOCKET ("GASKET_SOCKET")
#define GASKET_TMPDIR_PRINTF ("/tmp/gasket-%d")
#define GASKET_SOCKET_PRINTF ("/tmp/gasket-%d/gasket_track_%s.sock")

typedef struct _VteGasketPrivate VteGasketPrivate;

struct _VteGasketPrivate {
        int vte;
};

struct _VteGasket {
        GasketServer parent_instance;

        /* <private> */
        VteGasketPrivate *priv;
};

struct _VteGasketClass {
        GasketServerClass parent_class;
};

static gboolean
vte_gasket_initable_init (GInitable *initable,
                          GCancellable *cancellable,
                          GError **error)
{
    gboolean ret = TRUE;

    if (cancellable != NULL) {
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                             "Cancellable initialization not supported");
        return FALSE;
    }

    _vte_debug_print(VTE_DEBUG_GASKET,
        "vte_gasket_initable_init returning %s\n",
        ret ? "TRUE" : "FALSE");

    return ret;
}

static gboolean
vte_gasket_initable_iface_init (GInitableIface *iface)
{
    iface->init = vte_gasket_initable_init;

    return TRUE;
}

G_DEFINE_TYPE_WITH_CODE (VteGasket, vte_gasket, GASKET_TYPE_SERVER,
    G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, vte_gasket_initable_iface_init))

static void
vte_gasket_init(VteGasket* gasket)
{
    VteGasketPrivate *priv;

    priv = gasket->priv = G_TYPE_INSTANCE_GET_PRIVATE (gasket, VTE_TYPE_GASKET, VteGasketPrivate);
}

static void
vte_gasket_finalize(GObject *object)
{
    VteGasket *gasket = VTE_GASKET (object);
}

static void
vte_gasket_get_property (GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
    VteGasket *gasket = VTE_GASKET (object);
    VteGasketPrivate *priv = gasket->priv;

    switch (property_id)
    {
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
    }
}

static void
vte_gasket_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
    VteGasket *gasket = VTE_GASKET (object);

    switch (property_id)
    {
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
    }
}

static void
vte_gasket_class_init (VteGasketClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    GasketServerClass *gasket_server_class = GASKET_SERVER_CLASS (klass);

    g_type_class_add_private(object_class, sizeof(VteGasketPrivate));

    object_class->set_property = vte_gasket_set_property;
    object_class->get_property = vte_gasket_get_property;
    object_class->finalize     = vte_gasket_finalize;
}

/* Public API */

/**
 * vte_gasket_error_quark:
 *
 * Error domain for VTE Gasket errors. These errors will be from the #VteGasketError
 * enum. See #GError for further details.
 *
 * Returns: the error domain for VTE Gasket errors
 */
GQuark
vte_gasket_error_quark(void)
{
    static GQuark error_quark = 0;

    if (G_UNLIKELY (error_quark == 0))
        error_quark = g_quark_from_static_string("vte-gasket-error");

    return error_quark;
}

/**
 * vte_gasket_new:
 * @error: (allow-none): return location for a #GError, or %NULL
 * 
 * Creates a new gasket and generates a UUID for it.
 *
 * Returns: (transfer full): a new #VteGasket, or %NULL on error with @error filled in
 */
VteGasket*
vte_gasket_new(GError **error)
{
    VteGasket *ret = NULL;

    ret = VTE_GASKET( g_initable_new (VTE_TYPE_GASKET,
                          NULL /* (i.e. not cancellable) */,
                          error,
                          NULL) );

    return ret;
}
