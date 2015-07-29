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

G_BEGIN_DECLS

struct _VteGasketConnectionData;
gboolean _vte_gasket_close_socket(VteGasket *gasket);
gboolean _vte_gasket_setenv(int parent_pid, uuid_t *uuid_ptr);
gboolean _vte_gasket_make_tmpdir(VteGasket* gasket);
gboolean _vte_gasket_update_svg(gpointer user_data);
gpointer _vte_gasket_handle_new_connection(struct _VteGasketConnectionData *data);
gboolean _vte_gasket_close_connection(gpointer data);

G_END_DECLS
