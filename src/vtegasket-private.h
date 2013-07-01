G_BEGIN_DECLS

struct _VteGasketConnectionData;
gboolean _vte_gasket_close_socket(VteGasket *gasket);
gboolean _vte_gasket_setenv(int parent_pid, uuid_t *uuid_ptr);
gboolean _vte_gasket_make_tmpdir(VteGasket* gasket);
gboolean _vte_gasket_update_svg(gpointer user_data);
gpointer _vte_gasket_handle_new_connection(struct _VteGasketConnectionData *data);
gboolean _vte_gasket_close_connection(gpointer data);

G_END_DECLS
