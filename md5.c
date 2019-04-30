#include "byte_array.h"
#include <math.h>

const uint32_t MD5_A = 0x67452301;
const uint32_t MD5_B = 0xefcdab89;
const uint32_t MD5_C = 0x98badcfe;
const uint32_t MD5_D = 0x10325476;

const uint8_t s[] = {7,12,17,22, 5,9,14,20, 4,11,16,23, 6,10,15,21};

byte_array_t md5_pad_message(const byte_array_t in) {
  uint64_t message_len = ((uint64_t)get_byteArray_len(in)) * 8;
  uint64_t pad_length = 64 - ((get_byteArray_len(in) + 9)%64);
  byte_array_t out = copy_byteArray(in);
  byteArray_append_byte(out, 1<<7);
  add_len_byteArray(out, pad_length);
  byteArray_append_long_le(out, message_len);
  return out;
}

uint32_t rotate(uint32_t in, uint8_t amount) {
  return (in<<amount) | (in>>(32-amount));
}

void md5(const byte_array_t in, byte_array_t *out) {
  byte_array_t padded_message = md5_pad_message(in);
  uint32_t a0 = MD5_A,b0=MD5_B,c0=MD5_C,d0=MD5_D;

  uint32_t T[64];
  for(int i=0; i<64; i++) {
    int64_t temp = floor((((int64_t)1)<<32) * sin(i+1));
    if(temp<0) {
      temp = -temp - 1;
    }
    T[i] = temp;
  }

  uint32_t message_len = get_byteArray_len(padded_message);

  for(uint32_t i=0; i<message_len/64; i++) {
    uint32_t *x = malloc(16*sizeof(uint32_t));
    for(int j=0; j<16; j++) {
      x[j] = byteArray_to_int_le(padded_message, 64*i + 4*j);
    }

    uint32_t A = a0, B=b0, C=c0, D=d0;
    for(uint8_t j=0; j<64; j++) {
      uint32_t F = 0;
      uint8_t g = 0;
      if(j<16) {
        F = (B&C)|((~B)&D);
        g = j;
      } else if(j<32) {
        F = (D&B)|((~D)&C);
        g = ((5*j)+1)%16;
      } else if(j<48) {
        F = B^C^D;
        g = ((3*j) + 5)%16;
      } else {
        F = C^(B|(~D));
        g = (7*j)%16;
      }
      F += A + T[j] + x[g];
      A = D;
      D = C;
      C = B;
      B += rotate(F, s[4*(j/16) + (j%4)]);
    }

    a0 += A;
    b0 += B;
    c0 += C;
    d0 += D;

    free(x);
  }
  *out = create_byteArray(0);
  byteArray_append_int_le(*out, a0);
  byteArray_append_int_le(*out, b0);
  byteArray_append_int_le(*out, c0);
  byteArray_append_int_le(*out, d0);

  free_byteArray(padded_message);
}
