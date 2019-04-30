#ifndef MYSSH_BYTEARRAY_H
#define MYSSH_BYTEARRAY_H

#include "myssh_common.h"

#include <sys/socket.h>

#ifdef USE_BIGNUM
#include <bignum.h>
typedef bignum* bn_t;
#endif

typedef struct byte_array* byte_array_t;

byte_array_t create_byteArray(uint32_t);
byte_array_t set_byteArray(uint32_t, const uint8_t *);
byte_array_t copy_byteArray(const byte_array_t);
void clone_byteArray(const byte_array_t, byte_array_t);
byte_array_t tail_byteArray(const byte_array_t, uint32_t);
byte_array_t head_byteArray(const byte_array_t, uint32_t);
byte_array_t sub_byteArray(const byte_array_t, uint32_t, uint32_t);
byte_array_t str_to_byteArray(const char *);
void resize_byteArray(byte_array_t, uint32_t);
void add_len_byteArray(byte_array_t, uint32_t);
void remove_len_byteArray(byte_array_t, uint32_t);
void free_byteArray(byte_array_t);
void print_byteArray(const byte_array_t);
void print_byteArray_hex(const byte_array_t);
uint32_t get_byteArray_len(const byte_array_t);
uint8_t get_byteArray_element(const byte_array_t, uint32_t);
void set_byteArray_element(byte_array_t, uint32_t, uint8_t);
void increment_byteArray(byte_array_t);
void byteArray_append_str(byte_array_t, const char *);
void byteArray_append_len_str(byte_array_t, const char *);
void byteArray_append_byte(byte_array_t, uint8_t);
void byteArray_append_bytes(byte_array_t, const uint8_t*, uint32_t);
void byteArray_append_byteArray(byte_array_t, const byte_array_t);
void byteArray_append_len_byteArray(byte_array_t, const byte_array_t);
void byteArray_append_int(byte_array_t, uint32_t);
void byteArray_append_int_le(byte_array_t, uint32_t);
void byteArray_append_long(byte_array_t, uint64_t);
void byteArray_append_long_le(byte_array_t, uint64_t);
uint32_t byteArray_to_int(const byte_array_t, uint32_t);
uint32_t byteArray_to_int_le(const byte_array_t, uint32_t);
int base64_to_byteArray(const char *, byte_array_t);

void byteArray_strncpy(char *, byte_array_t, uint32_t, uint32_t);

int8_t byteArray_strncmp(const byte_array_t, const char *,
    uint32_t, uint32_t);
int8_t byteArray_ncmp(const byte_array_t, uint32_t,
    const byte_array_t, uint32_t, uint32_t);
uint8_t byteArray_equals(const byte_array_t, const byte_array_t);
uint8_t byteArray_contains(const byte_array_t, uint8_t);


uint32_t recv_byteArray(int, byte_array_t *, uint32_t);
uint32_t send_byteArray(int, const byte_array_t);

#ifdef USE_BIGNUM
void byteArray_append_len_bignum(byte_array_t, const bn_t);
void byteArray_append_bignum(byte_array_t, const bn_t);
void byteArray_to_bignum(const byte_array_t, bn_t);
void bignum_to_byteArray_u(const bn_t, byte_array_t);
void bignum_to_byteArray(const bn_t, byte_array_t);
#endif

#endif
