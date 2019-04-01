#include "myssh.h"

int64_t open_channel(connection *c, uint32_t local_channel) {
  uint8_t *session = "session";
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
  send_packet(open_session_pak, c);

  packet channel_open_response = wait_for_packet(c, 2,
      SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE);
  if(channel_open_response.payload.arr[0] == SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
    printf("Channel opened\n");
  } else if(channel_open_response.payload.arr[0] == SSH_MSG_CHANNEL_OPEN_FAILURE) {
    printf("Channel not opened\n");
    return -1; //TODO error code
  } else {
    //never reached
    printf("Channel not opened really badly\n");
    return -1;
  }

  return 0;

}
