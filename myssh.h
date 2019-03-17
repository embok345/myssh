#ifndef MYSSH_H
#define MYSSH_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <ctype.h>
#include <bignum.h>

#include "names.h"
#include "numbers.h"

typedef struct byte_array_t {
  uint32_t len;
  uint8_t *arr;
} byte_array_t;

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
      byte_array_t *, byte_array_t *);
  int (*dec)(const byte_array_t, const byte_array_t,
      byte_array_t *, byte_array_t *);
  byte_array_t key;
  byte_array_t iv;
  uint8_t block_size;
  uint8_t key_size;
} enc_struct;

typedef struct connection {
  int socket;
  uint32_t sequence_number;
  byte_array_t session_id;
  mac_struct *mac_c2s;
  mac_struct *mac_s2c;
  enc_struct *enc_c2s;
  enc_struct *enc_s2c;
} connection;

typedef struct packet {
  uint32_t packet_length;
  uint8_t padding_length;
  uint8_t *payload;
  uint8_t *padding;
  byte_array_t mac;
} packet;


/*main*/
int start_connection(connection *);
int kex_init(connection *, bignum **, byte_array_t *);
void *listener_thread(void *);

/*kex*/

/*conversion*/
void packet_to_bytes(packet, connection *, byte_array_t *);
packet bytes_to_packet(const uint8_t *, int);

void int_to_bytes(uint32_t, uint8_t *);
uint32_t bytes_to_int(const uint8_t *);

void mpint_to_bignum(const uint8_t *, uint32_t, bignum *);
uint32_t bignum_to_mpint(const bignum *, uint8_t *);

/*packets*/
packet build_kex_init(connection *);
packet build_packet(const byte_array_t, connection *);
uint32_t build_name_list(uint32_t, const char **, uint8_t *);
void free_pak(packet *);
int send_packet(packet, connection *);


/*sha*/
void sha_256(byte_array_t, byte_array_t *);
void hmac(const byte_array_t, const byte_array_t,
    void (*)(const byte_array_t, byte_array_t *),
    uint8_t, byte_array_t *);

/*aes*/
int aes_ctr(const byte_array_t, const byte_array_t, byte_array_t *, byte_array_t *);

#endif
