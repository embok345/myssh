#ifndef MYSSH_H
#define MYSSH_H

#include "myssh_common.h"
#include "names.h"
#include "numbers.h"
#include "byte_array.h"
#include "structs.h"
#include "util.h"
#include "hash.h"

extern const char *LOG_NAME;

/*main*/
uint8_t version_exchange(connection *, char **, char **);

/*listeners*/
pthread_t start_reader(connection *);
void *channel_listener(void *);
packet wait_for_packet(connection *, int, ...);
packet wait_for_channel_packet(connection *, uint32_t);

/*kex*/
uint8_t kex(connection *, const char *, const char *);
void compute_exchange_hash(void (*)(const byte_array_t, byte_array_t *),
    byte_array_t *, int, ...);
uint8_t kex_dh_14_rsa(connection *, byte_array_t *, bn_t*, bn_t*,
    bn_t*, byte_array_t *);
char *get_chosen_algo(byte_array_t, const char **, uint32_t);
char **get_chosen_algos(byte_array_t, uint32_t);

/*packets*/
packet clone_pak(const packet);
void copy_pak(const packet, packet *);
void free_pak(packet);
packet build_kex_init(connection *);
packet build_packet(const byte_array_t, connection *);
void build_name_list(uint32_t, const char **, byte_array_t);
int send_packet(const packet, connection *);
void packet_to_bytes(packet, connection *, byte_array_t *);
packet bytes_to_packet(const uint8_t *, int);

/*sha*/
//void sha_256(const byte_array_t, byte_array_t *);
//void hmac(const byte_array_t, const byte_array_t,
//    void (*)(const byte_array_t, byte_array_t *),
//    uint8_t, byte_array_t *);

/*aes*/
int aes_ctr(const byte_array_t, const byte_array_t,
    byte_array_t, byte_array_t *);
int inv_aes_cbc(const byte_array_t, const byte_array_t,
    byte_array_t, byte_array_t *);

/*der*/
uint8_t decode_private_key(const byte_array_t, int, ...);
int base64_to_byteArray(const char *, byte_array_t);

/*user_auth*/
int user_auth_publickey(connection *, const char*, const char*,
    const char*, const char*);
int sign_message(const byte_array_t, const char *, byte_array_t, int, ...);
int get_private_key(const char *, int, ...);
int get_public_key(const char *, byte_array_t);

/*channel*/
uint8_t open_channel(connection *, uint32_t, uint32_t *);
void send_channel_message(const char *, uint32_t, connection *);
void send_channel_char(char, uint32_t, connection *);

#endif
