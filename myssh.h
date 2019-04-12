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
#include <termio.h>
#include <netdb.h>

#include "names.h"
#include "numbers.h"

extern const char *LOG_NAME;

typedef struct byte_array_t {
  uint32_t len;
  uint8_t *arr;
} byte_array_t;
typedef struct byte_array* _byte_array_t;

_byte_array_t create_byteArray(uint32_t);
_byte_array_t set_byteArray(uint32_t, const uint8_t *);
void free_byteArray(_byte_array_t);
void print_byteArray(const _byte_array_t);
uint32_t get_byteArray_len(const _byte_array_t);
uint8_t get_byteArray_element(const _byte_array_t, uint32_t);
void set_byteArray_element(_byte_array_t, uint32_t, uint8_t);
void increment_byteArray(_byte_array_t);

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

typedef bignum* bn_t;

/*main*/
uint8_t version_exchange(connection *, char **, char **);

/*util*/
void free_enc(enc_struct *);
void free_mac(mac_struct *);
void copy_bytes(const uint8_t *, uint32_t, byte_array_t *);
uint8_t byteArray_contains(const byte_array_t, uint8_t);
char getch();
connection create_connection_struct(int);
void free_connection(connection);
uint8_t isdigit_s(const char *);

/*listeners*/
void start_reader(connection *);
void *channel_listener(void *);
packet wait_for_packet(connection *, int, ...);
packet wait_for_channel_packet(connection *, uint32_t);

/*kex*/
uint8_t kex(connection *, const char *, const char *);
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
packet clone_pak(const packet);
void copy_pak(const packet, packet *);
void free_pak(packet);
packet build_kex_init(connection *);
packet build_packet(const byte_array_t, connection *);
void build_name_list(uint32_t, const char **, byte_array_t *);
int send_packet(const packet, connection *);


/*sha*/
void sha_256(byte_array_t, byte_array_t *);
void hmac(const byte_array_t, const byte_array_t,
    void (*)(const byte_array_t, byte_array_t *),
    uint8_t, byte_array_t *);

/*aes*/
int aes_ctr(const byte_array_t, const byte_array_t,
    byte_array_t *, byte_array_t *);

/*der*/
uint8_t decode_private_key(const byte_array_t, int, va_list);
int base64_to_byteArray(const char *, byte_array_t *);

/*user_auth*/
int user_auth_publickey(connection *, const char*, const char*,
    const char*, const char*);
int sign_message(const byte_array_t, const char *, byte_array_t *, int, ...);
int get_private_key(const char *, int, ...);
int get_public_key(const char *, byte_array_t *);

/*channel*/
uint8_t open_channel(connection *, uint32_t, uint32_t *);
void send_channel_message(const char *, uint32_t, connection *);
void send_channel_char(char, uint32_t, connection *);

#endif
