#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct byte_array {
  uint32_t len;
  uint8_t *arr;
} byte_array;
typedef byte_array* _byte_array_t;

_byte_array_t create_byteArray(uint32_t len) {
  _byte_array_t bytes = malloc(sizeof(byte_array));
  if(!bytes)
    return NULL;
  bytes->len = len;
  bytes->arr = malloc(len);
  if(!bytes->arr) {
    free(bytes);
    return NULL;
  }
  memset(bytes->arr, 0, len);
  return bytes;
}

_byte_array_t set_byteArray(uint32_t len, const uint8_t *bytes) {
  _byte_array_t ret = create_byteArray(len);
  memcpy(ret->arr, bytes, len);
  return ret;
}

void free_byteArray(_byte_array_t bytes) {
  free(bytes->arr);
  free(bytes);
}

uint32_t get_byteArray_len(const _byte_array_t bytes) {
  return bytes->len;
}

uint8_t get_byteArray_element(const _byte_array_t bytes, uint32_t index) {
  if(index >= bytes->len) return 0; //TODO it may be better to return an error
  return bytes->arr[index];
}

void set_byteArray_element(_byte_array_t bytes, uint32_t index, uint8_t val) {
  if(index < bytes->len) bytes->arr[index] = val;
}

void increment_byteArray(_byte_array_t in) {
  uint32_t pos = in->len-1;
  in->arr[pos] = (in->arr[pos]) + 1;
  while(in->arr[pos] == 0 && pos>0) {
    pos--;
    (in->arr[pos])++;
  }
}

void print_byteArray(const _byte_array_t bytes) {
  for(int i=0; i<bytes->len; i++) {
    printf("%"PRIu8"\n", bytes->arr[i]);
  }
}


