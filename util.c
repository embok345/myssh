#include "myssh.h"


void free_enc(enc_struct *to_free) {
  free(to_free->key.arr);
  free(to_free->iv.arr);
  free(to_free);
}
void free_mac(mac_struct *to_free) {
  free(to_free->key.arr);
  free(to_free);
}

void copy_bytes(const uint8_t *in, uint32_t length, byte_array_t *out) {
  out->len = length;
  out->arr = malloc(length);
  memcpy(out->arr, in, length);
}

uint8_t byteArray_contains(const byte_array_t arr, uint8_t to_find) {
  for(int i=0; i<arr.len; i++) {
    if(arr.arr[i] == to_find)
      return 1;
  }
  return 0;
}

char getch() {
  char buf = 0;
  struct termios old = {0};
  if(tcgetattr(0, &old) < 0)
    perror("tcsetattr()");
  old.c_lflag &= ~ICANON;
  old.c_lflag &= ~ECHO;
  old.c_cc[VMIN] = 1;
  old.c_cc[VTIME] = 0;

  if(tcsetattr(0, TCSANOW, &old) < 0)
    perror("tcsetattr ICANON");
  if(read(0, &buf, 1) < 0)
    perror("read()");

  old.c_lflag |= ICANON;
  old.c_lflag |= ECHO;

  if(tcsetattr(0, TCSADRAIN, &old) < 0)
    perror("tcsetattr ~ICANON");

  return buf;
}

uint8_t isdigit_s(const char *in) {
  uint32_t in_len = strlen(in);
  for(int i=0; i<in_len; i++) {
    if(!isdigit(in[i])) return 0;
  }
  return 1;
}

void free_connection(connection con) {
  free(con.session_id->arr);
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
  packet_lock pak_lock;
  con.pak.p = NULL;
  pthread_cond_t packet_handled = PTHREAD_COND_INITIALIZER;
  pthread_cond_t packet_present = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  con.pak.packet_handled = packet_handled;
  con.pak.packet_present = packet_present;
  con.pak.mutex = mutex;
  return con;
}
