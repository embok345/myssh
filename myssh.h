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
  byte_array_t *session_id;
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

typedef struct der_val_t {
  uint8_t type;
  void *value;
} der_val_t;

typedef der_val_t der_int_t;
typedef bignum* bn_t;

typedef struct der_seq_t {
  uint32_t no_elements;
  der_val_t *elements;
} der_seq_t;

/*main*/
uint8_t start_connection(connection *);
uint8_t kex_init(connection *);
packet wait_for_packet(connection *, int, ...);

/*listeners*/
void *reader_listener(void *);
void *global_request_listener(void *);

/*kex*/
void compute_exchange_hash(void (*)(const byte_array_t, byte_array_t *),
    byte_array_t *, int, ...);
uint8_t kex_dh_14_rsa(connection *, byte_array_t *, bn_t*, bn_t*,
    bn_t*, byte_array_t *);
char *get_chosen_algo(uint8_t*, uint32_t, const char **, uint32_t);
char **get_chosen_algos(uint8_t*, uint32_t *);

/*conversion*/
void packet_to_bytes(packet, connection *, byte_array_t *);
packet bytes_to_packet(const uint8_t *, int);

void int_to_bytes(uint32_t, uint8_t *);
uint32_t bytes_to_int(const uint8_t *);

void byteArray_into_byteArray(const byte_array_t, byte_array_t *);
void string_into_byteArray(const char *, byte_array_t *);

void mpint_to_bignum(const uint8_t *, uint32_t, bn_t);
void bignum_into_mpint(const bn_t, byte_array_t *);
void bignum_to_byteArray(const bn_t, byte_array_t *);
void bignum_to_byteArray_u(const bn_t, byte_array_t *);

/*packets*/
packet clone_pak(packet);
void copy_pak(const packet *, packet *);
packet build_kex_init(connection *);
packet build_packet(const byte_array_t, connection *);
void build_name_list(uint32_t, const char **, byte_array_t *);
void free_pak(packet *);
int send_packet(packet, connection *);


/*sha*/
void sha_256(byte_array_t, byte_array_t *);
void hmac(const byte_array_t, const byte_array_t,
    void (*)(const byte_array_t, byte_array_t *),
    uint8_t, byte_array_t *);

/*aes*/
int aes_ctr(const byte_array_t, const byte_array_t,
    byte_array_t *, byte_array_t *);

/*der*/
void free_der(der_val_t *);
int base64_to_byteArray(const char *, byte_array_t *);
int32_t decode_der_string(const byte_array_t, der_val_t **);
void print_der_val(const der_val_t);

/*user_auth*/
int user_auth_publickey(connection *, const char*, const char*,
    const char*, const char*);
//int sign_message(const byte_array_t, const char *, const bn_t, const bn_t,
//    byte_array_t *);
int sign_message(const byte_array_t, const char *, byte_array_t *, int, ...);
//int get_private_key(const char *, bn_t, uint32_t*, bn_t);
int get_private_key(const char *, int, ...);
int get_public_key(const char *, byte_array_t *);

/*channel*/
int open_channel(connection *);

#endif
