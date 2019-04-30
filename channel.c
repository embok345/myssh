#include "myssh.h"

void send_channel_message(const char *message, uint32_t channel, connection *c) {
  byte_array_t message_bytes = create_byteArray(0);
  byteArray_append_byte(message_bytes, SSH_MSG_CHANNEL_DATA);
  byteArray_append_int(message_bytes, channel);
  byteArray_append_len_str(message_bytes, message);
  packet pak = build_packet(message_bytes, c);
  send_packet(pak, c);
  free_pak(pak);
  free_byteArray(message_bytes);
}

void send_channel_char(char c, uint32_t channel, connection *con) {
  byte_array_t message_bytes = create_byteArray(0);
  byteArray_append_byte(message_bytes, SSH_MSG_CHANNEL_DATA);
  byteArray_append_int(message_bytes, channel);
  byteArray_append_int(message_bytes, 1);
  byteArray_append_byte(message_bytes, c);
  packet pak = build_packet(message_bytes, con);
  send_packet(pak, con);
  free_pak(pak);
  free_byteArray(message_bytes);
}

uint8_t open_channel(connection *c,
                     uint32_t local_channel,
                     uint32_t *remote_channel) {

  char *session = "session";
  byte_array_t open_session_bytes = create_byteArray(0);
  byteArray_append_byte(open_session_bytes, SSH_MSG_CHANNEL_OPEN);
  byteArray_append_len_str(open_session_bytes, session);
  byteArray_append_int(open_session_bytes, local_channel);
  byteArray_append_int(open_session_bytes, 1<<21);
  byteArray_append_int(open_session_bytes, 1<<15);
  packet open_session_pak = build_packet(open_session_bytes, c);
  send_packet(open_session_pak, c);
  free_pak(open_session_pak);
  free_byteArray(open_session_bytes);

  packet channel_open_response = wait_for_packet(c, 2,
      SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE);
  if(get_byteArray_element(channel_open_response.payload, 0) ==
      SSH_MSG_CHANNEL_OPEN_FAILURE) {
    printf("Channel not opened\n");
    free_pak(channel_open_response);
    return 1; //TODO error code
  }

  if( get_byteArray_len(channel_open_response.payload) < 17 ||
      byteArray_to_int(channel_open_response.payload, 1) != local_channel) {
    printf("Channel open confirmation malformed\n");
    free_pak(channel_open_response);
    return 1;
  }

  *remote_channel = byteArray_to_int(channel_open_response.payload, 5);
  uint32_t window_size = byteArray_to_int(channel_open_response.payload, 9);
  uint32_t packet_size = byteArray_to_int(channel_open_response.payload, 13);

  free_pak(channel_open_response);

  pthread_t listener;
  struct stuff {connection *c; uint32_t channel;} arg = {c, local_channel};
  pthread_create(&listener, NULL, channel_listener, (void *)&arg);

  char *type = "pty-req";
  char *term = "xterm-256color";
  byte_array_t pty_req = create_byteArray(0);
  byteArray_append_byte(pty_req, SSH_MSG_CHANNEL_REQUEST);
  byteArray_append_int(pty_req, *remote_channel);
  byteArray_append_len_str(pty_req, type);
  byteArray_append_byte(pty_req, 1);
  byteArray_append_len_str(pty_req, term);
  byteArray_append_int(pty_req, 80);
  byteArray_append_int(pty_req, 24);
  byteArray_append_int(pty_req, 640);
  byteArray_append_int(pty_req, 480);
  byteArray_append_int(pty_req, 0);
  packet pty_req_pak = build_packet(pty_req, c);
  send_packet(pty_req_pak, c);

  free_pak(pty_req_pak);
  free_byteArray(pty_req);

  type = "shell";
  byte_array_t shell_req_bytes = create_byteArray(0);
  byteArray_append_byte(shell_req_bytes, SSH_MSG_CHANNEL_REQUEST);
  byteArray_append_int(shell_req_bytes, *remote_channel);
  byteArray_append_len_str(shell_req_bytes, type);
  byteArray_append_byte(shell_req_bytes, 1);
  packet shell_req = build_packet(shell_req_bytes, c);
  send_packet(shell_req, c);

  free_pak(shell_req);
  free_byteArray(shell_req_bytes);

  return 0;
}
