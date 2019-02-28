#include <inttypes.h>
#include <stdlib.h>

const uint32_t SHA256_INIT[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

typedef struct byte_array {
  uint32_t len;
  uint8_t *arr;
} byte_array;

byte_array *preprocess_sha_256(byte_array in) {
  byte_array *out = malloc(sizeof(byte_array));

  uint32_t l = in.len*8;
  uint32_t k = (959-(len%512))%512;
  out->arr = malloc(in.len+1+k+64);

  memcpy(out->arr, in.arr, in.len);
  out->arr[in.len] = 1;

  return out;
}

void sha_256(byte_array in) {
  
}

int main() {
  return 0;
}
