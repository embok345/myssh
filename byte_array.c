#include "byte_array.h"
#include "util.h"

typedef struct byte_array {
  uint32_t len;
  uint8_t *arr;
} byte_array;

byte_array_t create_byteArray(uint32_t len) {
  byte_array_t bytes = malloc(sizeof(byte_array));
  if(!bytes)
    return NULL;
  bytes->len = len;
  if(bytes->len == 0)
    bytes->arr = NULL;
  else {
    bytes->arr = malloc(len);
    if(!bytes->arr) {
      free(bytes);
      return NULL;
    }
    memset(bytes->arr, 0, len);
  }
  return bytes;
}

byte_array_t set_byteArray(uint32_t len, const uint8_t *bytes) {
  byte_array_t ret = create_byteArray(len);
  memcpy(ret->arr, bytes, len);
  return ret;
}

byte_array_t copy_byteArray(const byte_array_t in) {
  return set_byteArray(in->len, in->arr);
}

void clone_byteArray(const byte_array_t in, byte_array_t out) {
  out->len = in->len;
  out->arr = realloc(out->arr, in->len);
  memcpy(out->arr, in->arr, in->len);
}

byte_array_t tail_byteArray(const byte_array_t in, uint32_t index) {
  if(in->len <= index) {
    return create_byteArray(0);
  }
  byte_array_t out = create_byteArray(in->len - index);
  memcpy(out->arr, in->arr + index, in->len - index);
  return out;
}
byte_array_t head_byteArray(const byte_array_t in, uint32_t len) {
  if(len >= in->len) {
    return copy_byteArray(in);
  }
  byte_array_t out = create_byteArray(len);
  memcpy(out->arr, in->arr, len);
  return out;
}

byte_array_t sub_byteArray(const byte_array_t in, uint32_t offset, uint32_t len) {
  byte_array_t out = tail_byteArray(in, offset);
  resize_byteArray(out, len);
  return out;
}

byte_array_t str_to_byteArray(const char *in) {
  return set_byteArray(strlen(in), in);
}

void free_byteArray(byte_array_t bytes) {
  free(bytes->arr);
  free(bytes);
}

uint32_t get_byteArray_len(const byte_array_t bytes) {
  return bytes->len;
}

uint8_t get_byteArray_element(const byte_array_t bytes, uint32_t index) {
  if(index >= bytes->len) return 0; //TODO it may be better to return an error
  return bytes->arr[index];
}

void set_byteArray_element(byte_array_t bytes, uint32_t index, uint8_t val) {
  if(index < bytes->len) bytes->arr[index] = val;
}

void resize_byteArray(byte_array_t bytes, uint32_t len) {
  if(len <= bytes->len) {
    bytes->len = len;
    return;
  }
  uint32_t old_len = bytes->len;
  bytes->len = len;
  bytes->arr = realloc(bytes->arr, len);
  memset(bytes->arr + old_len, 0, bytes->len - old_len);
}

void remove_len_byteArray(byte_array_t bytes, uint32_t len) {
  if(len >= bytes->len) {
    bytes->len = 0;
    bytes->arr = realloc(bytes->arr, 0);
    return;
  }
  if(len == 0) {
    return;
  }
  bytes->len -= len;
  bytes->arr = realloc(bytes->arr, bytes->len);
}

void add_len_byteArray(byte_array_t bytes, uint32_t len) {
  if( len == 0 ) return;
  bytes->len += len;
  bytes->arr = realloc(bytes->arr, bytes->len);
  memset(bytes->arr + bytes->len - len, 0, len);
}
void byteArray_append_str(byte_array_t bytes, const char *str) {
  add_len_byteArray(bytes, strlen(str));
  memcpy(bytes->arr + bytes->len - strlen(str), str, strlen(str));
}
void byteArray_append_len_str(byte_array_t bytes, const char *str) {
  add_len_byteArray(bytes, 4 + strlen(str));
  int_to_bytes(strlen(str), bytes->arr + bytes->len - 4 - strlen(str));
  memcpy(bytes->arr + bytes->len - strlen(str), str, strlen(str));
}
void byteArray_append_byte(byte_array_t bytes, uint8_t byte) {
  add_len_byteArray(bytes, 1);
  bytes->arr[bytes->len - 1] = byte;
}
void byteArray_append_bytes(byte_array_t bytes1, const uint8_t *bytes2, uint32_t len) {
  add_len_byteArray(bytes1, len);
  memcpy(bytes1->arr + bytes1->len - len, bytes2, len);
}
void byteArray_append_len_byteArray(byte_array_t bytes1, const byte_array_t bytes2) {
  add_len_byteArray(bytes1, 4 + bytes2->len);
  int_to_bytes(bytes2->len, bytes1->arr + bytes1->len - 4 - bytes2->len);
  memcpy(bytes1->arr + bytes1->len - bytes2->len, bytes2->arr, bytes2->len);
}
void byteArray_append_byteArray(byte_array_t bytes1, const byte_array_t bytes2) {
  add_len_byteArray(bytes1, bytes2->len);
  memcpy(bytes1->arr + bytes1->len - bytes2->len, bytes2->arr, bytes2->len);
}

void byteArray_append_int(byte_array_t bytes, uint32_t val) {
  add_len_byteArray(bytes, 4);
  int_to_bytes(val, bytes->arr + bytes->len - 4);
}
void byteArray_append_int_le(byte_array_t bytes, uint32_t val) {
  add_len_byteArray(bytes, 4);
  int_to_bytes_le(val, bytes->arr + bytes->len - 4);
}
void byteArray_append_long(byte_array_t bytes, uint64_t val) {
  add_len_byteArray(bytes, 8);
  long_to_bytes(val, bytes->arr + bytes->len - 8);
}
void byteArray_append_long_le(byte_array_t bytes, uint64_t val) {
  add_len_byteArray(bytes, 8);
  long_to_bytes_le(val, bytes->arr + bytes->len - 8);
}

void increment_byteArray(byte_array_t in) {
  uint32_t pos = in->len-1;
  in->arr[pos] = (in->arr[pos]) + 1;
  while(in->arr[pos] == 0 && pos>0) {
    pos--;
    (in->arr[pos])++;
  }
}

uint32_t byteArray_to_int(const byte_array_t in, uint32_t offset) {
  uint32_t ret = 0;
  for(int i=0; i<4; i++) {
    if(offset + i >= in->len) break;
    ret <<= 8;
    ret += get_byteArray_element(in, offset+i);
  }
  return ret;
}

uint32_t byteArray_to_int_le(const byte_array_t in, uint32_t offset) {
  uint32_t ret = 0;
  for(int i=0; i<4; i++) {
    ret <<= 8;
    ret += get_byteArray_element(in, offset + 3 - i);
  }
  return ret;
}

int base64_to_byteArray(const char *in, byte_array_t out) {
  if(strlen(in)%4!=0)
    return 1;
  resize_byteArray(out, (strlen(in)/4)*3);
  uint32_t num = 0;
  int padding = 0;
  for(int j=0; j<strlen(in)/4; j++) {
    for(int i=0; i<4; i++) {
      num<<=6;
      if(isalpha(in[4*j + i]) && isupper(in[4*j + i])) {
        num+=in[4*j + i] - 'A';
      } else if(isalpha(in[4*j + i]) && islower(in[4*j + i])){
        num+=in[4*j + i] - 'a' + 26;
      } else if(isdigit(in[4*j + i])) {
        num+=in[4*j + i] - '0' + 52;
      } else if(in[4*j + i] == '+') {
        num+=62;
      } else if(in[4*j + i] == '/') {
        num+=63;
      } else if(in[4*j + i] == '=') {
        padding++;
      } else return 1;
    }
    switch(padding) {
      case 0:
              set_byteArray_element(out, (3*j)+2, num%256);
      case 1:
              set_byteArray_element(out, (3*j)+1, (num>>8)%256);
      case 2:
      case 3:
              set_byteArray_element(out, 3*j, (num>>16)%256);
      default: num=0;

    }
  }
  remove_len_byteArray(out, padding);
  return 0;
}


#ifdef USE_BIGNUM

void byteArray_append_len_bignum(byte_array_t bytes, const bn_t num) {
  byte_array_t num_bytes = create_byteArray(0);
  bignum_to_byteArray(num, num_bytes);
  byteArray_append_len_byteArray(bytes, num_bytes);
  free_byteArray(num_bytes);
}
void byteArray_append_bignum(byte_array_t bytes, const bn_t num) {
  byte_array_t num_bytes = create_byteArray(0);
  bignum_to_byteArray(num, num_bytes);
  byteArray_append_byteArray(bytes, num_bytes);
  free_byteArray(num_bytes);
}

void byteArray_to_bignum(const byte_array_t in, bn_t out) {
  bn_resize(out, in->len);
  for(int i=0; i<in->len; i++) {
    bn_setBlock(out, i, in->arr[in->len - i - 1]);
  }
  bn_removezeros(out);
}

void bignum_to_byteArray_u(const bn_t in, byte_array_t out) {
  resize_byteArray(out, bn_trueLength(in));
  for(int i=0; i<out->len; i++) {
    out->arr[i] = bn_getBlock(in, out->len - i - 1);
  }
}
void bignum_to_byteArray(const bn_t in, byte_array_t out) {
  if(bn_getBlock(in, bn_trueLength(in)-1) >= 128) {
    resize_byteArray(out, bn_trueLength(in) + 1);
    out->arr[0] = 0;
    for(int i=0; i<out->len-1; i++) {
      out->arr[i+1] = bn_getBlock(in, out->len - i - 2);
    }
  } else {
    bignum_to_byteArray_u(in, out);
  }
}
#endif

void print_byteArray(const byte_array_t bytes) {
  for(int i=0; i<bytes->len; i++) {
    printf("%"PRIu8" ", bytes->arr[i]);
  }
  printf("\n");
}
void print_byteArray_hex(const byte_array_t bytes) {
  for(int i=0; i<bytes->len; i++) {
    printf("%x ", bytes->arr[i]);
  }
  printf("\n");
}

int8_t byteArray_ncmp(const byte_array_t bytes1, uint32_t offset1,
    const byte_array_t bytes2, uint32_t offset2, uint32_t len) {
  for(int i=0; i<len; i++) {
    if(get_byteArray_element(bytes1, i+offset1) <
        get_byteArray_element(bytes2, i+offset2)) return -1;
    if(get_byteArray_element(bytes1, i+offset1) >
        get_byteArray_element(bytes2, i+offset2)) return 1;
  }
  return 0;
}

int8_t byteArray_strncmp(const byte_array_t bytes, const char *str,
                         uint32_t offset, uint32_t len) {
  if(len == 0) return 0;
  if(bytes->len <= offset) {
    if(strlen(str) != 0) return -1;
    return 0;
  }
  uint32_t byte_array_len = bytes->len - offset; //>0
  uint32_t str_len = strlen(str);
  if(str_len == 0) return 1;

  uint32_t min_len = (str_len < byte_array_len) ? str_len : byte_array_len;
  for(int i=0; i<min_len; i++) {
    if(get_byteArray_element(bytes, i+offset) < str[i]) return -1;
    if(get_byteArray_element(bytes, i+offset) > str[i]) return 1;
  }
  return 0;
}

uint8_t byteArray_equals(const byte_array_t in1, const byte_array_t in2) {
  if(in1->len != in2->len) {
    return 0;
  }
  if(memcmp(in1->arr, in2->arr, in1->len) != 0) {
    return 0;
  }
  return 1;
}

void byteArray_strncpy(char *str, const byte_array_t arr, uint32_t offset, uint32_t len) {
  if(offset + len > arr->len) len = arr->len - offset;
  memcpy(str, arr->arr + offset, len);
  str[len] = '\0';
}

uint8_t byteArray_contains(const byte_array_t arr, uint8_t to_find) {
  for(int i=0; i<arr->len; i++) {
    if(arr->arr[i] == to_find)
      return 1;
  }
  return 0;
}

uint32_t recv_byteArray(int socket, byte_array_t *bytes, uint32_t len) {
  *bytes = create_byteArray(len);
  return recv(socket, (*bytes)->arr, len, 0);
}

uint32_t send_byteArray(int socket, const byte_array_t bytes) {
  return send(socket, bytes->arr, bytes->len, 0);
}
