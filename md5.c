#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <math.h>

const uint32_t MD5_A = 0x67452301;
const uint32_t MD5_B = 0xefcdab89;
const uint32_t MD5_C = 0x98badcfe;
const uint32_t MD5_D = 0x10325476;

const uint8_t s[] = {7,12,17,22, 5,9,14,20, 4,11,16,23, 6,10,15,21};

typedef struct byte_array_t {
  uint32_t len;
  uint8_t *arr;
} byte_array_t;

byte_array_t md5_pad_message(const byte_array_t in) {
  uint64_t message_len = ((uint64_t)in.len) * 8;
  uint64_t pad_length = 64 - ((in.len + 9)%64);
  byte_array_t out;
  out.len = in.len + pad_length + 9;
  out.arr = malloc(out.len);
  memcpy(out.arr, in.arr, in.len);
  out.arr[in.len] = 1<<7;
  memset(out.arr + in.len + 1, 0, pad_length);
  out.arr[in.len + 4 + pad_length] = (message_len>>24)%256;
  out.arr[in.len + 3 + pad_length] = (message_len>>16)%256;
  out.arr[in.len + 2 + pad_length] = (message_len>>8)%256;
  out.arr[in.len + 1 + pad_length] = message_len%256;

  out.arr[in.len + 8 + pad_length] = (message_len>>56)%256;
  out.arr[in.len + 7 + pad_length] = (message_len>>48)%256;
  out.arr[in.len + 6 + pad_length] = (message_len>>40)%256;
  out.arr[in.len + 5 + pad_length] = (message_len>>32)%256;
  return out;
}

uint32_t bytes_to_int(const uint8_t *in) {
  uint32_t ret = 0;
  for(int i=0; i<4; i++) {
    ret<<=8;
    ret+=in[3-i];
  }
  return ret;
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

  for(uint32_t i = 0; i<padded_message.len/64; i++) {
    uint32_t *x = malloc(16*sizeof(uint32_t));
    for(int j=0; j<16; j++) {
      x[j] = bytes_to_int(padded_message.arr + 64*i + 4*j);
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
  out->len = 16;
  out->arr = malloc(16);

  out->arr[0] = a0%256;
  out->arr[1] = (a0>>8)%256;
  out->arr[2] = (a0>>16)%256;
  out->arr[3] = (a0>>24)%256;

  out->arr[4] = b0%256;
  out->arr[5] = (b0>>8)%256;
  out->arr[6] = (b0>>16)%256;
  out->arr[7] = (b0>>24)%256;

  out->arr[8] = c0%256;
  out->arr[9] = (c0>>8)%256;
  out->arr[10] = (c0>>16)%256;
  out->arr[11] = (c0>>24)%256;

  out->arr[12] = d0%256;
  out->arr[13] = (d0>>8)%256;
  out->arr[14] = (d0>>16)%256;
  out->arr[15] = (d0>>24)%256;

  free(padded_message.arr);
}
