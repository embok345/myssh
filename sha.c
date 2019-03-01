#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

const uint32_t SHA256_INIT[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

const uint32_t SHA256_K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct byte_array_t {
  uint32_t len;
  uint8_t *arr;
} byte_array_t;

typedef struct sha_256_blocks_t {
  uint32_t noBlocks;
  uint32_t **blocks;
} sha_256_blocks_t;

void long_into_bytes(uint64_t in, uint8_t* out) {
  out[0] = (in>>56)%256;
  out[1] = (in>>48)%256;
  out[2] = (in>>40)%256;
  out[3] = (in>>32)%256;
  out[4] = (in>>24)%256;
  out[5] = (in>>16)%256;
  out[6] = (in>>8)%256;
  out[7] = in%256;
}

sha_256_blocks_t *preprocess_sha_256(const byte_array_t in) {
  byte_array_t paddedArray;
  uint32_t k = (120-((in.len+1)%64))%64;
  paddedArray.arr = malloc(in.len+1+k+8);
  paddedArray.len = in.len+k+9;
  memcpy(paddedArray.arr, in.arr, in.len);
  paddedArray.arr[in.len] = 128;
  for(uint32_t i=0; i<k; i++) {
    paddedArray.arr[in.len+1+i] = 0;
  }
  uint64_t len = ((uint64_t)in.len)<<3;
  long_into_bytes(len, (paddedArray.arr)+in.len+1+k);

  sha_256_blocks_t *out = malloc(sizeof(sha_256_blocks_t));
  out->noBlocks = paddedArray.len/64;
  out->blocks = malloc(out->noBlocks);
  for(uint32_t i=0; i<out->noBlocks; i++) {
    (out->blocks)[i] = malloc(64);
    for(uint32_t j=0; j<16; j++) {
      //This doesn't seem to work if you do it all on one line ?
      uint32_t newInt = ((uint32_t)paddedArray.arr[i*64 + j*4])<<24;
      newInt +=((uint32_t)paddedArray.arr[i*64+j*4+1])<<16;
      newInt += ((uint32_t)paddedArray.arr[i*64+j*4+2])<<8;
      newInt += (uint32_t)paddedArray.arr[i*64+j*4+3];
      out->blocks[i][j] = newInt;
    }
  }

  return out;

}

uint32_t rotate_bits(uint32_t x, int8_t n) {
  return (x>>n) + (x&(1<<(n-1)))<<(32-n);
}

uint32_t sha256_sigma_0(uint32_t x) {
  return rotate_bits(x, 7) ^ rotate_bits(x, 18) ^ (x>>3);
}
uint32_t sha256_sigma_1(uint32_t x) {
  return rotate_bits(x, 17) ^ rotate_bits(x, 19) ^ (x>>10);
}

uint32_t sha256_Sigma_0(uint32_t x) {
  return rotate_bits(x, 2) ^ rotate_bits(x, 13) ^ rotate_bits(x, 22);
}

uint32_t sha256_Sigma_1(uint32_t x) {
  return rotate_bits(x, 6) ^ rotate_bits(x, 11) ^ rotate_bits(x, 25);
}

uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x&y) ^ ~(x&z);
}
uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x&y) ^ (x&z) ^ (y&z);
}

void sha_256(byte_array_t in) {
  sha_256_blocks_t blocks = *preprocess_sha_256(in);

  uint32_t registers[8];
  uint32_t intermediate_hash[8];
  uint32_t W[64];
  for(uint8_t i=0; i<8; i++) {
    intermediate_hash[i] = SHA256_INIT[i];
  }

  for(uint32_t i=1; i<=blocks.noBlocks; i++) {
    for(uint8_t j=0; j<8; j++) {
      registers[j] = intermediate_hash[j];
    }
    for(uint8_t j=0; j<64; j++) {
      if(j<16) {
        W[j] = blocks.blocks[i][j];
        continue;
      }
      W[j] = sha256_sigma_1(W[j-2]) + W[j-7] +
             sha256_sigma_0(W[j-15]) + W[j-16];
    }
    for(uint8_t j=0; j<64; j++) {
      uint32_t ch = sha256_ch(registers[4], registers[5], registers[6]);
      uint32_t maj = sha256_maj(registers[0], registers[1], registers[2]);
      uint32_t Sigma_0 = sha256_Sigma_0(registers[0]);
      uint32_t Sigma_1 = sha256_Sigma_1(registers[4]);

      uint32_t temp1 = registers[7]+Sigma_1+ch+SHA256_K[j] + W[j];
      uint32_t temp2 = Sigma_0 + maj;
      registers[7] = registers[6];
      registers[6] = registers[5];
      registers[5] = registers[4];
      registers[4] = registers[3] + temp1;
      registers[3] = registers[2];
      registers[2] = registers[1];
      registers[1] = registers[0];
      registers[0] = temp1 + temp2;
    }
    for(uint8_t j=0; j<8; j++) {
      intermediate_hash[j] = registers[j] + intermediate_hash[j];
    }
  }
}

int main() {
  uint8_t *s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  byte_array_t str = {strlen(s), s};
  sha_256(str);

  return 0;
}
