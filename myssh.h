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
#include "byte_array.h"
#include "structs.h"
#include "util.h"

extern const char *LOG_NAME;

typedef bignum* bn_t;

/*main*/
uint8_t version_exchange(connection *, char **, char **);

/*listeners*/
void start_reader(connection *);
void *channel_listener(void *);
packet wait_for_packet(connection *, int, ...);
packet wait_for_channel_packet(connection *, uint32_t);

/*kex*/
uint8_t kex(connection *, const char *, const char *);
void compute_exchange_hash(void (*)(const _byte_array_t, _byte_array_t *),
    _byte_array_t *, int, ...);
uint8_t kex_dh_14_rsa(connection *, _byte_array_t *, bn_t*, bn_t*,
    bn_t*, _byte_array_t *);
//char *get_chosen_algo(uint8_t*, uint32_t, const char **, uint32_t);
char *get_chosen_algo(_byte_array_t, const char **, uint32_t);
//char **get_chosen_algos(uint8_t*, uint32_t *);
char **get_chosen_algos(_byte_array_t, uint32_t);

/*conversion*/
void packet_to_bytes(packet, connection *, _byte_array_t *);
packet bytes_to_packet(const uint8_t *, int);
//void int_to_bytes(uint32_t, uint8_t *);
//uint32_t bytes_to_int(const uint8_t *);
//void byteArray_into_byteArray(const byte_array_t, byte_array_t *);
//void string_into_byteArray(const char *, byte_array_t *);
//void mpint_to_bignum(const uint8_t *, uint32_t, bn_t);
//void bignum_into_mpint(const bn_t, byte_array_t *);
//void bignum_to_byteArray(const bn_t, byte_array_t *);
//void bignum_to_byteArray_u(const bn_t, byte_array_t *);

/*packets*/
packet clone_pak(const packet);
void copy_pak(const packet, packet *);
void free_pak(packet);
packet build_kex_init(connection *);
packet build_packet(const _byte_array_t, connection *);
void build_name_list(uint32_t, const char **, _byte_array_t);
int send_packet(const packet, connection *);


/*sha*/
void sha_256(const _byte_array_t, _byte_array_t *);
//void sha_256(byte_array_t, byte_array_t *);
void hmac(const _byte_array_t, const _byte_array_t,
    void (*)(const _byte_array_t, _byte_array_t *),
    uint8_t, _byte_array_t *);

/*aes*/
//int aes_ctr(const byte_array_t, const byte_array_t,
//    byte_array_t *, byte_array_t *);
int aes_ctr(const _byte_array_t, const _byte_array_t,
    _byte_array_t, _byte_array_t *);

/*der*/
uint8_t decode_private_key(const _byte_array_t, int, va_list);
int base64_to_byteArray(const char *, _byte_array_t);

/*user_auth*/
int user_auth_publickey(connection *, const char*, const char*,
    const char*, const char*);
int sign_message(const _byte_array_t, const char *, _byte_array_t, int, ...);
int get_private_key(const char *, int, ...);
int get_public_key(const char *, _byte_array_t);

/*channel*/
uint8_t open_channel(connection *, uint32_t, uint32_t *);
void send_channel_message(const char *, uint32_t, connection *);
void send_channel_char(char, uint32_t, connection *);

#endif
