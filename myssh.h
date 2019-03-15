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

typedef struct connection {
  //struct sockaddr_in socket;
  int socket;
  uint8_t encryption_block_size; //0 if no encryption
  uint8_t mac_block_size; //0 if no mac
  uint8_t mac_output_size;
  uint32_t sequence_number;
  byte_array_t session_id;
  byte_array_t iv_c2s;
  byte_array_t iv_s2c;
  byte_array_t key_c2s;
  byte_array_t key_s2c;
  byte_array_t mac_c2s;
  byte_array_t mac_s2c;
} connection;

typedef struct packet {
  uint32_t packet_length;
  uint8_t padding_length;
  uint8_t *payload;
  uint8_t *padding;
  byte_array_t mac;
} packet;


/*main*/
void start_connection(int);
void kex_init(connection *, bignum **, byte_array_t *);
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

/*aes*/
int aes_ctr(const byte_array_t, const byte_array_t, byte_array_t *, byte_array_t *);

#endif
