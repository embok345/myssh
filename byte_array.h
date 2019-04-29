#ifndef MYSSH_BYTEARRAY_H
#define MYSSH_BYTEARRAY_H

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <bignum.h>
#include <sys/socket.h>

typedef bignum* bn_t;
typedef struct byte_array* _byte_array_t;

_byte_array_t create_byteArray(uint32_t);
_byte_array_t set_byteArray(uint32_t, const uint8_t *);
_byte_array_t copy_byteArray(const _byte_array_t);
_byte_array_t tail_byteArray(const _byte_array_t, uint32_t);
_byte_array_t head_byteArray(const _byte_array_t, uint32_t);
_byte_array_t sub_byteArray(const _byte_array_t, uint32_t, uint32_t);
_byte_array_t str_to_byteArray(const char *);
void resize_byteArray(_byte_array_t, uint32_t);
void add_len_byteArray(_byte_array_t, uint32_t);
void remove_len_byteArray(_byte_array_t, uint32_t);
void free_byteArray(_byte_array_t);
void print_byteArray(const _byte_array_t);
void print_byteArray_hex(const _byte_array_t);
uint32_t get_byteArray_len(const _byte_array_t);
uint8_t get_byteArray_element(const _byte_array_t, uint32_t);
void set_byteArray_element(_byte_array_t, uint32_t, uint8_t);
void increment_byteArray(_byte_array_t);
void byteArray_append_str(_byte_array_t, const char *);
void byteArray_append_len_str(_byte_array_t, const char *);
void byteArray_append_byte(_byte_array_t, uint8_t);
void byteArray_append_bytes(_byte_array_t, const uint8_t*, uint32_t);
void byteArray_append_byteArray(_byte_array_t, const _byte_array_t);
void byteArray_append_len_byteArray(_byte_array_t, const _byte_array_t);
void byteArray_append_int(_byte_array_t, uint32_t);
void byteArray_append_long(_byte_array_t, uint64_t);
void byteArray_append_len_bignum(_byte_array_t, const bn_t);
void byteArray_append_bignum(_byte_array_t, const bn_t);
void byteArray_to_bignum(const _byte_array_t, bn_t);
void bignum_to_byteArray_u(const bn_t, _byte_array_t);
void bignum_to_byteArray(const bn_t, _byte_array_t);
uint32_t byteArray_to_int(const _byte_array_t, uint32_t);

void byteArray_strncpy(char *, _byte_array_t, uint32_t, uint32_t);

int8_t byteArray_strncmp(const _byte_array_t, const char *,
    uint32_t, uint32_t);
int8_t byteArray_ncmp(const _byte_array_t, uint32_t,
    const _byte_array_t, uint32_t, uint32_t);
uint8_t byteArray_equals(const _byte_array_t, const _byte_array_t);
uint8_t byteArray_contains(const _byte_array_t, uint8_t);

uint32_t recv_byteArray(int, _byte_array_t *, uint32_t);
uint32_t send_byteArray(int, const _byte_array_t);

#endif
