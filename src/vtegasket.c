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

#include "vtegasket.h"
#include "vtegasket-private.h"
#include "debug.h"

#define GASKET_CABOOSE ("__GASKET_CABOOSE__\n")
#define GASKET_ENVIRONMENT_GASKET_ID ("GASKET_ID")
#define GASKET_ENVIRONMENT_GASKET_SOCKET ("GASKET_SOCKET")
#define GASKET_TMPDIR_PRINTF ("/tmp/gasket-%d")
#define GASKET_SOCKET_PRINTF ("/tmp/gasket-%d/gasket_track_%s.sock")

typedef struct _VteGasketPrivate VteGasketPrivate;

struct _VteGasketTargetExtents {
    int row;
    int col;

    int row_count;
    int col_count;

    long width;
    long height;
};

struct _VteGasketPrivate {
    uuid_t* uuid;

    struct _VteGasketTargetExtents extents;
 	void* svg_handle;
 	gboolean svg_invalid;
 	GString* svg;

    GSourceFunc invalidation_function;
    gpointer invalidation_data;

    unsigned int socket;
    gboolean socket_made;
    int parent_pid;
};

struct _VteGasket {
        GObject parent_instance;

        /* <private> */
        VteGasketPrivate *priv;
};

struct _VteGasketClass {
        GObjectClass parent_class;
};

struct _VteGasketUpdateSVGData {
    GString* svg;
    VteGasket* gasket;
};

gboolean
_vte_gasket_close_socket(VteGasket *gasket)
{  
    char uuid_str[300];
    char socket_str[330];
    char tmpdir[300];
        
    //TODO: Implement close socket
	if (gasket->priv->socket_made)
    {
        close(gasket->priv->socket);

        uuid_unparse(*gasket->priv->uuid, uuid_str);
	    sprintf(socket_str, GASKET_SOCKET_PRINTF, gasket->priv->parent_pid, uuid_str);
        sprintf(tmpdir, GASKET_TMPDIR_PRINTF, gasket->priv->parent_pid);

        if (unlink(socket_str) == -1)
        {
            _vte_debug_print (VTE_DEBUG_GASKET,
                "Could not unlink closed socket %s\n",
                socket_str);

            return FALSE;
        }
        if (rmdir(tmpdir) == -1 && errno != ENOTEMPTY)
        {
            _vte_debug_print (VTE_DEBUG_GASKET,
                "Could not remove directory %s\n",
                tmpdir);

            return FALSE;
        }

        gasket->priv->socket_made = FALSE;
    }
    return TRUE;
}

gboolean
_vte_gasket_setenv(int parent_pid, uuid_t *uuid_ptr)
{
	char uuid_str[300], socket_str[330];
	uuid_unparse(*uuid_ptr, uuid_str);

    _vte_debug_print (VTE_DEBUG_GASKET,
        "Setting up Gasket for child pty: UUID = %s\n",
        uuid_str);

    /* Set the Gasket socket path from the UUID */
	sprintf(socket_str, GASKET_SOCKET_PRINTF, parent_pid, uuid_str);

    /* Set the environment variables within the PTY that called us */
    if (!g_setenv(GASKET_ENVIRONMENT_GASKET_ID, uuid_str, TRUE) ||
        !g_setenv(GASKET_ENVIRONMENT_GASKET_SOCKET, socket_str, TRUE)) {
        _vte_debug_print (VTE_DEBUG_GASKET,
            "Could not set Gasket environment variables\n");
        return FALSE;
	}
    return TRUE;
}


enum {
    PROP_0,
    PROP_UUID,
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

G_DEFINE_TYPE_WITH_CODE (VteGasket, vte_gasket, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, vte_gasket_initable_iface_init))

static void
vte_gasket_init(VteGasket* gasket)
{
    VteGasketPrivate *priv;

    priv = gasket->priv = G_TYPE_INSTANCE_GET_PRIVATE (gasket, VTE_TYPE_GASKET, VteGasketPrivate);

    priv->uuid = NULL;
	priv->svg = g_string_new("");
	priv->svg_invalid = FALSE;
	priv->svg_handle = NULL;
    priv->socket = 0;
    priv->socket_made = FALSE;
    priv->parent_pid = getpid();
}

static void
vte_gasket_finalize(GObject *object)
{
    VteGasket *gasket = VTE_GASKET (object);

    vte_gasket_close(gasket);
}

static void
vte_gasket_get_property (GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
    VteGasket *gasket = VTE_GASKET (object);
    VteGasketPrivate *priv = gasket->priv;
    char uuid_str[300];

    switch (property_id)
    {
        case PROP_UUID:
            uuid_unparse(*priv->uuid, uuid_str);
            g_value_set_string(value, uuid_str);
            break;

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
        case PROP_UUID:
            vte_gasket_set_uuid(gasket, g_value_get_string(value));
            break;

        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
    }
}

static void
vte_gasket_class_init (VteGasketClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private(object_class, sizeof(VteGasketPrivate));

    object_class->set_property = vte_gasket_set_property;
    object_class->get_property = vte_gasket_get_property;
    object_class->finalize     = vte_gasket_finalize;

    /**
     * VteGasket:uuid:
     *
     * The UUID reference for the current Gasket instance - this is the
     * basis of finding resources, such as a Unix socket, related to a
     * specific Gasket train.
     */
    g_object_class_install_property(object_class, PROP_UUID,
        g_param_spec_string("uuid", NULL, NULL, "", G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
    );
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
 * vte_gasket_new_with_uuid:
 * uuid: string representation of UUID
 * @error: (allow-none): return location for a #GError, or %NULL
 * 
 * Creates a new gasket given a UUID string (normally avoided).
 *
 * Returns: (transfer full): a new #VteGasket, or %NULL on error with @error filled in
 */
VteGasket*
vte_gasket_new_with_uuid(const gchar* uuid, GError **error)
{
    VteGasket *ret = NULL;

    ret = g_initable_new (VTE_TYPE_GASKET,
                          NULL /* (i.e. not cancellable) */,
                          error,
                          "uuid", uuid,
                          NULL);

    return ret;
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
    uuid_t uuid;
	char uuid_str[300];

	uuid_generate(uuid);
    uuid_unparse(uuid, uuid_str);

    return vte_gasket_new_with_uuid(uuid_str, error);
}

/**
 * vte_gasket_set_uuid:
 * @gasket: a #VteGasket
 * @uuid: a UUID as a string. Unsets if empty.
 *
 * Set the UUID for the gasket, as used in sockets, etc..
 *
 * Returns: (transfer none): a boolean indicating success
 */
gboolean
vte_gasket_set_uuid(VteGasket *gasket, const gchar* uuid_str)
{  
    int uuid_ret = 0;

    VteGasketPrivate *priv = gasket->priv;

    if (strlen(uuid_str) > 0)
    {
        if (priv->uuid == NULL)
            priv->uuid = (uuid_t*)malloc(sizeof(uuid_t));

        uuid_ret = uuid_parse(uuid_str, *priv->uuid);

        if (uuid_ret != 0)
        {
            _vte_debug_print (VTE_DEBUG_GASKET,
                "Could not set Gasket UUID : %s\n",
                uuid_str);

            g_object_notify(G_OBJECT(gasket), "uuid");
            priv->uuid = NULL;

            return FALSE;
        }
    }
    else
    {
        //FIXME: deallocate old uuid
        if (priv->uuid != NULL)
            free(priv->uuid);

        priv->uuid = NULL;
    }

    //FIXME: I think this needs to be changed to update the _child_ process env.
    //_vte_gasket_setenv(priv->uuid);

    g_object_notify(G_OBJECT(gasket), "uuid");
    return TRUE;
}

gboolean
_vte_gasket_make_tmpdir(VteGasket* gasket)
{
    char tmpdir[300];
    
    sprintf(tmpdir, GASKET_TMPDIR_PRINTF, gasket->priv->parent_pid);

    if (mkdir(tmpdir, S_IRWXU) == -1 && errno != EEXIST)
    {
		g_warning("Error (%s) creating temporary directory.",
			  g_strerror(errno));
        _vte_debug_print (VTE_DEBUG_GASKET,
          "Cannot create a temporary directory\n");
        return FALSE;
    }
    return TRUE;
}

/**
 * vte_gasket_make_socket:
 * @gasket: a #VteGasket
 *
 * Sets up a new socket for the current UUID.
 *
 * Returns: (transfer none): a boolean indicating success
 */
gboolean
vte_gasket_make_socket(VteGasket* gasket)
{
    VteGasketPrivate *priv = gasket->priv;

	gchar uuid_str[300];
    int socket_ret;
	unsigned int gasket_socket;
	struct sockaddr_un local;
	gchar socket_str[330];

    if (priv->uuid == NULL)
    {
        _vte_debug_print (VTE_DEBUG_GASKET,
          "Cannot make socket without UUID set\n");
        return FALSE;
    }

    /* Create a temporary directory for this (parent) process */
    _vte_gasket_make_tmpdir(gasket);

    /* Get a string representation of the UUID */
	uuid_unparse(*priv->uuid, uuid_str);

    _vte_debug_print (VTE_DEBUG_GASKET,
      "Making socket for Gasket with UUID: %s\n",
      uuid_str);

    /* Set up the socket itself
     *
     * With thanks for sockets tips to...
     * http://beej.us/guide/bgipc/output/html/multipage/unixsock.html */

    /* Name socket after UUID */
	sprintf(socket_str, GASKET_SOCKET_PRINTF, priv->parent_pid, uuid_str);
	socket_ret = socket(AF_UNIX, SOCK_STREAM, 0);
	if ((socket_ret = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		g_warning("Error (%s) creating new Unix socket.",
			  g_strerror(errno));
        _vte_debug_print (VTE_DEBUG_GASKET,
          "Cannot create a new Unix socket\n");
        return FALSE;
	}
    gasket_socket = (unsigned int)socket_ret;

    /* Working with Unix sockets here */
	local.sun_family = AF_UNIX;

    /* Ensure we start afresh */
	strcpy(local.sun_path, socket_str);
	unlink(local.sun_path);

    /* Attempt to bind the socket to a local address */
	if (bind(gasket_socket, (struct sockaddr*)&local, sizeof(struct sockaddr_un)) == -1) {
		g_warning("Error (%s) binding unix socket.",
			  g_strerror(errno));
        _vte_debug_print (VTE_DEBUG_GASKET,
          "Cannot bind new Unix socket\n");
        return FALSE;
	}

    priv->socket = gasket_socket;
    priv->socket_made = TRUE;

    /* Mark this socket as for listening on */
	listen(gasket_socket, 5);

    return TRUE;
}

/**
 * vte_gasket_launch_listen:
 * @gasket: a #VteGasket
 *
 * Start the listener on the socket.
 */
void
vte_gasket_launch_listen(VteGasket *gasket)
{
    _vte_debug_print (VTE_DEBUG_GASKET,
      "Launching a listener thread for Gasket\n");

    /* Start the listener */
	g_thread_new("gasket_platform", (GThreadFunc)vte_gasket_listen, gasket);
}

gboolean
_vte_gasket_update_svg(gpointer user_data)
{
    struct _VteGasketUpdateSVGData *update_data =
        (struct _VteGasketUpdateSVGData*)user_data;

    VteGasketPrivate *priv = update_data->gasket->priv;

    /* Inject the SVG string (done here as thread-safe) */
	g_string_assign(priv->svg, update_data->svg->str);

    /* Flag the SVG as being new */
    priv->svg_invalid = TRUE;

    /* Tidy up carrier */
    g_string_free(update_data->svg, TRUE);
    free(update_data);

    /* Invalidate the terminal */
    priv->invalidation_function(priv->invalidation_data);
}

/**
 * vte_gasket_listen:
 * @gasket: a #VteGasket
 *
 * Listen on the socket.
 */
gpointer
vte_gasket_listen(VteGasket *gasket)
{
	GError* err = NULL;

	GString* svg = g_string_new("");
	GString buffer[1024];
	gsize eol;
    int socket_ret;
	unsigned int local_len, gasket_socket_conn;
	struct sockaddr_un remote;

	GIOChannel* gasket_channel;
    struct _VteGasketUpdateSVGData* update_data;

    /* Enter acceptance loop */
	for (;;) {
        /* Accept data via socket */
		local_len = sizeof(struct sockaddr_un);
		socket_ret = accept(gasket->priv->socket, (struct sockaddr*)&remote, &local_len);

        if (socket_ret == -1)
        {
            g_warning("Could not accept requests from socket - %s\n",
			  g_strerror(errno));
            return NULL;
        }
        gasket_socket_conn = (unsigned int)socket_ret;

        /* Start reading in SVG */
		gasket_channel = g_io_channel_unix_new(gasket_socket_conn);

        /* Read this chunk into buffer */
		while (g_io_channel_read_line_string(gasket_channel, buffer, &eol, &err) != G_IO_STATUS_EOF) {
            /* If we find a caboose, process and continue */
			if (g_strcmp0(buffer->str, GASKET_CABOOSE) == 0) {
                /* Clean whitespace */
				g_strstrip(svg->str);

                /* Prepare a temporary variable to handle update info */
                update_data =
                    (struct _VteGasketUpdateSVGData*)malloc(sizeof(struct _VteGasketUpdateSVGData));

                /* Inject the SVG string (hold here for the moment) */
                update_data->svg = g_string_new(svg->str);
                update_data->gasket = gasket;

                /* Break into main thread and force redraw */
                g_main_context_invoke(NULL, _vte_gasket_update_svg, update_data);

                /* Wipe the SVG string to start the next chunk */
				g_string_truncate(svg, 0);
			} else {
                /* Add on the new content to the SVG string */
				g_string_append_printf(svg, "%s", buffer->str);
			}
		}

		if (err != NULL) {
			fprintf(stderr, "Looping: %s\n", err->message);
			g_error_free(err);
		}

		close(gasket_socket_conn);
	}
	g_string_free(svg, TRUE);

    return NULL;
}

/**
 * vte_gasket_paint_overlay:
 * @gasket: a #VteGasket
 *
 * Paint an overlay during the cairo write.
 */
void
vte_gasket_paint_overlay(VteGasket *gasket, cairo_t* cr)
{
    VteGasketPrivate *priv = gasket->priv;

    struct _VteGasketTargetExtents *extents = &priv->extents;

    RsvgHandle *handle, *new_handle;
    GString *svg;
	RsvgDimensionData dims;

    GError *err;
    FILE* err_back; 

    /* Only bother if we are initialized */
    if (priv->uuid == NULL || priv->svg == NULL)
        return;

    //TODO: double-check explanation
    /* Ensure we are not located on the boundaries of the window */
	if ((CLAMP(extents->col, 0, extents->col_count - 1) != extents->col) ||
	    (CLAMP(extents->row, 0, extents->row_count - 1) != extents->row))
		return;

    /* Pick out SVG content and handle from Gasket object */
	handle = (RsvgHandle*)priv->svg_handle;
	new_handle = NULL;
	svg = priv->svg;

	err = NULL;
    /* Only regenerate the RSVG if marked as invalid */
	if (svg != NULL && priv->svg_invalid) {
		if (svg->len > 0) {
            new_handle = rsvg_handle_new_from_data(svg->str, strlen(svg->str), &err);
			if (err == NULL) {
				if (handle != NULL) {
					g_object_unref(handle);
				}
				handle = new_handle;
			} else {
				fprintf(stderr, "Creating handle problem: %s\n", err->message);
				g_error_free(err);
				err = NULL;
				err_back = fopen("/tmp/gasket/gasket_errbak.svg", "w");
				if (err_back == NULL) {
					perror("Couldn't save problematic SVG backup");
				} else {
					fprintf(err_back, "%s", svg->str);
					fclose(err_back);
				}
			}
		} else {
			if (handle != NULL) {
				g_object_unref(handle);
			}
			handle = NULL;
		}
	}

    /* Get dimension data to rescale appropriately */
	if (handle != NULL) {
		err = NULL;
		rsvg_handle_get_dimensions(handle, &dims);

		cairo_save(cr);
		cairo_scale(cr, extents->width, extents->height);
		rsvg_handle_render_cairo(handle, cr);
		cairo_restore(cr);
	}
	priv->svg_handle = handle;
}

void
vte_gasket_child_setup(VteGasket *gasket)
{
    //FIXME: error tests before dereference
    _vte_gasket_setenv(gasket->priv->parent_pid, gasket->priv->uuid);
}

void
vte_gasket_update_table(VteGasket *gasket, GHashTable* table)
{
	char uuid_str[300], socket_str[330];
    //FIXME: error tests before dereference
    uuid_t *uuid = gasket->priv->uuid;

    /* Set the environment variables within the PTY that called us */
    if (!_vte_gasket_setenv(gasket->priv->parent_pid, uuid)) {
        _vte_debug_print (VTE_DEBUG_GASKET,
            "Could not set environment variables when updating\n");
        return;
	}

	uuid_unparse(*uuid, uuid_str);

    /* Set the Gasket socket path from the UUID */
	sprintf(socket_str, GASKET_SOCKET_PRINTF, gasket->priv->parent_pid, uuid_str);

    /* Update the hash table with the relevant environment variables */
    g_hash_table_replace (table, g_strdup (GASKET_ENVIRONMENT_GASKET_ID), g_strdup (uuid_str));
    g_hash_table_replace (table, g_strdup (GASKET_ENVIRONMENT_GASKET_SOCKET), g_strdup (socket_str));
}

void
vte_gasket_set_invalidation_function (VteGasket *gasket, GSourceFunc function, gpointer user_data)
{
    g_return_if_fail( VTE_IS_GASKET(gasket) );

    gasket->priv->invalidation_function = function;
    gasket->priv->invalidation_data = user_data;
}

void
vte_gasket_set_target_extents(VteGasket *gasket, int row, int col, int row_count, int col_count, long width, long height)
{
    VteGasketPrivate *priv = gasket->priv;
    struct _VteGasketTargetExtents *extents = &priv->extents;

    extents->row = row;
    extents->col = col;
    extents->row_count = row_count;
    extents->col_count = col_count;
    extents->width = width;
    extents->height = height;
}

void
vte_gasket_close(VteGasket *gasket)
{
    _vte_gasket_close_socket(gasket);
}
