G_BEGIN_DECLS

gboolean _vte_gasket_close_socket(VteGasket *gasket);
gboolean _vte_gasket_setenv(int parent_pid, uuid_t *uuid_ptr);
gboolean _vte_gasket_make_tmpdir(VteGasket* gasket);
gboolean _vte_gasket_update_svg(gpointer user_data);

G_END_DECLS
