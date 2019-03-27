#include "myssh.h"

int open_session(connection *c) {
  /*uint8_t *session = "session";
  byte_array_t open_session_bytes;
  open_session_bytes.len = 17 + strlen(session);
  open_session_bytes.arr = malloc(open_session_bytes.len);
  open_session_bytes.arr[0] = SSH_MSG_CHANNEL_OPEN;
  int_to_bytes(strlen(session), open_session_bytes.arr + 1);
  memcpy(open_session_bytes.arr + 5, session, strlen(session));
  int_to_bytes(1, open_session_bytes.arr + strlen(session) + 5);
  //I don't really know what the numbers should be below
  int_to_bytes(1000, open_session_bytes.arr + strlen(session) + 9);
  int_to_bytes(10000, open_session_bytes.arr + strlen(session) + 13);
  packet open_session_pak = build_packet(open_session_bytes, c);
  send_packet(open_session_pak, c);*/
  return 0;

}
