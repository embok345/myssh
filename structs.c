#include "structs.h"

void free_enc(enc_struct *to_free) {
  free_byteArray(to_free->key);
  free_byteArray(to_free->iv);
  free(to_free);
}
void free_mac(mac_struct *to_free) {
  free_byteArray(to_free->key);
  free(to_free);
}

void free_connection(connection con) {
  free_byteArray(con.session_id);
  free(con.session_id);
  free_enc(con.enc_c2s);
  free_enc(con.enc_s2c);
  free_mac(con.mac_c2s);
  free_mac(con.mac_s2c);
}

connection create_connection_struct(int sock) {
  connection con;
  con.socket = sock;
  con.session_id = NULL;
  con.enc_c2s = NULL;
  con.enc_s2c = NULL;
  con.mac_c2s = NULL;
  con.mac_s2c = NULL;
  con.sequence_number = 0;
  con.pak.p = NULL;
  pthread_cond_t packet_handled = PTHREAD_COND_INITIALIZER;
  pthread_cond_t packet_present = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  con.pak.packet_handled = packet_handled;
  con.pak.packet_present = packet_present;
  con.pak.mutex = mutex;
  return con;
}

