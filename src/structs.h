#ifndef STRUCTS_H
#define STRUCTS_H

#include "byte_array.h"
#include <pthread.h>

typedef struct mac_struct {
  void (*hash)(const byte_array_t, byte_array_t *);
  void (*mac)(const byte_array_t, const byte_array_t,
      void (*)(const byte_array_t, byte_array_t *),
      uint8_t, byte_array_t *);
  byte_array_t key;
  uint8_t hash_block_size;
  uint8_t mac_output_size;
} mac_struct;

typedef struct enc_struct {
  int (*enc)(const byte_array_t, const byte_array_t,
      byte_array_t, byte_array_t *);
  int (*dec)(const byte_array_t, const byte_array_t,
      byte_array_t, byte_array_t *);
  byte_array_t key;
  byte_array_t iv;
  uint8_t block_size;
  uint8_t key_size;
} enc_struct;

typedef struct packet {
  uint32_t packet_length;
  uint8_t padding_length;
  byte_array_t payload;
  uint8_t *padding;
  byte_array_t mac;
} packet;

typedef struct packet_lock {
  packet *p;
  pthread_cond_t packet_handled;
  pthread_cond_t packet_present;
  pthread_mutex_t mutex;
} packet_lock;

typedef struct connection {
  int socket;
  uint32_t sequence_number;
  byte_array_t session_id;
  mac_struct *mac_c2s;
  mac_struct *mac_s2c;
  enc_struct *enc_c2s;
  enc_struct *enc_s2c;
  packet_lock pak;
} connection;

typedef struct channel {
  uint32_t local_channel;
  uint32_t remote_channel;
  uint32_t maximum_packet_size;
  uint32_t window_size;
  connection *c;
} channel;


void free_enc(enc_struct *);
void free_mac(mac_struct *);
connection create_connection_struct(int);
void free_connection(connection);

#endif
