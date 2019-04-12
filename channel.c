#include "myssh.h"

void send_channel_message(const char *message, uint32_t channel, connection *c) {
  byte_array_t message_bytes;
  message_bytes.len = 9 + strlen(message);
  message_bytes.arr = malloc(message_bytes.len);
  message_bytes.arr[0] = SSH_MSG_CHANNEL_DATA;
  int_to_bytes(channel, message_bytes.arr + 1);
  int_to_bytes(strlen(message), message_bytes.arr + 5);
  memcpy(message_bytes.arr + 9, message, strlen(message));
  packet pak = build_packet(message_bytes, c);
  send_packet(pak, c);
  free_pak(pak);
  free(message_bytes.arr);
}

void send_channel_char(char c, uint32_t channel, connection *con) {
  byte_array_t message_bytes;
  message_bytes.len = 10;
  message_bytes.arr = malloc(message_bytes.len);
  message_bytes.arr[0] = SSH_MSG_CHANNEL_DATA;
  int_to_bytes(channel, message_bytes.arr + 1);
  int_to_bytes(1, message_bytes.arr + 5);
  message_bytes.arr[9] = c;
  packet pak = build_packet(message_bytes, con);
  send_packet(pak, con);
  free_pak(pak);
  free(message_bytes.arr);
}

uint8_t open_channel(connection *c,
                     uint32_t local_channel,
                     uint32_t *remote_channel) {

  uint8_t *session = "session";
  byte_array_t open_session_bytes;
  open_session_bytes.len = 17 + strlen(session);
  open_session_bytes.arr = malloc(open_session_bytes.len);
  open_session_bytes.arr[0] = SSH_MSG_CHANNEL_OPEN;
  int_to_bytes(strlen(session), open_session_bytes.arr + 1);
  memcpy(open_session_bytes.arr + 5, session, strlen(session));
  int_to_bytes(local_channel, open_session_bytes.arr + strlen(session) + 5);
  //I don't really know what the numbers should be below
  //These are what they apear to be for openssh
  int_to_bytes(1<<21, open_session_bytes.arr + strlen(session) + 9);
  int_to_bytes(1<<15, open_session_bytes.arr + strlen(session) + 13);
  packet open_session_pak = build_packet(open_session_bytes, c);
  send_packet(open_session_pak, c);
  free_pak(open_session_pak);
  free(open_session_bytes.arr);

  packet channel_open_response = wait_for_packet(c, 2,
      SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE);
  if(channel_open_response.payload.arr[0] == SSH_MSG_CHANNEL_OPEN_FAILURE) {
    printf("Channel not opened\n");
    free_pak(channel_open_response);
    return 1; //TODO error code
  }

  if(channel_open_response.payload.len < 17 ||
      bytes_to_int(channel_open_response.payload.arr + 1) != local_channel) {
    printf("Channel open confirmation malformed\n");
    free_pak(channel_open_response);
    return 1;
  }

  *remote_channel = bytes_to_int(channel_open_response.payload.arr + 5);
  uint32_t window_size = bytes_to_int(channel_open_response.payload.arr + 9);
  uint32_t packet_size = bytes_to_int(channel_open_response.payload.arr + 13);

  free_pak(channel_open_response);

  pthread_t listener;
  struct stuff {connection *c; uint32_t channel;} arg = {c, local_channel};
  pthread_create(&listener, NULL, channel_listener, (void *)&arg);

  char *type = "pty-req";
  char *term = "xterm-256color";
  byte_array_t pty_req;
  pty_req.len = 34+strlen(type) + strlen(term);
  pty_req.arr = malloc(pty_req.len);
  pty_req.arr[0] = SSH_MSG_CHANNEL_REQUEST;
  int_to_bytes(*remote_channel, pty_req.arr + 1);
  int_to_bytes(strlen(type), pty_req.arr + 5);
  memcpy(pty_req.arr + 9, type, strlen(type));
  pty_req.arr[9 + strlen(type)] = 1;
  int_to_bytes(strlen(term), pty_req.arr + 10 + strlen(type));
  memcpy(pty_req.arr + 14 + strlen(type), term, strlen(term));
  int_to_bytes(80, pty_req.arr + 14 + strlen(type) + strlen(term));
  int_to_bytes(24, pty_req.arr + 18 + strlen(type) + strlen(term));
  int_to_bytes(640, pty_req.arr + 22 + strlen(type) + strlen(term));
  int_to_bytes(480, pty_req.arr + 26 + strlen(type) + strlen(term));
  int_to_bytes(0, pty_req.arr + 30 + strlen(type) + strlen(term));
  packet pty_req_pak = build_packet(pty_req, c);
  send_packet(pty_req_pak, c);

  free_pak(pty_req_pak);
  free(pty_req.arr);

  type = "shell";
  byte_array_t shell_req_bytes;
  shell_req_bytes.len = 10 + strlen(type);
  shell_req_bytes.arr = malloc(shell_req_bytes.len);
  shell_req_bytes.arr[0] = SSH_MSG_CHANNEL_REQUEST;
  int_to_bytes(*remote_channel, shell_req_bytes.arr + 1);
  int_to_bytes(strlen(type), shell_req_bytes.arr + 5);
  memcpy(shell_req_bytes.arr + 9, type, strlen(type));
  shell_req_bytes.arr[9 + strlen(type)] = 1;
  packet shell_req = build_packet(shell_req_bytes, c);
  send_packet(shell_req, c);

  free_pak(shell_req);
  free(shell_req_bytes.arr);

  return 0;
}
