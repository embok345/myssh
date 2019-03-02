#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define KEY_SIZE 8
#define NO_ROUNDS (KEY_SIZE+6)

const uint32_t RCON[11] = {0, 1<<24, 2<<24, 4<<24, 8<<24, 0x10<<24, 0x20<<24, 0x40<<24, 0x80<<24, 0x1B<<24, 0x36<<24};

const uint8_t SBOX[16][16]  = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

const uint8_t INV_SBOX[16][16] =
{{0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
 {0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
 {0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
 {0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
 {0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
 {0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
 {0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
 {0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
 {0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
 {0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
 {0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
 {0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
 {0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
 {0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
 {0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
 {0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}};

typedef struct state_matrix {
  uint8_t m[4][4];
} state_matrix;

typedef struct keys {
  uint32_t w[4*(NO_ROUNDS+1)];
} keys;

state_matrix zero_matrix() {
  state_matrix m;
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      m.m[i][j] = 0;
    }
  }
}
keys zero_keys() {
  keys k;
  for(int i=0; i<4*(NO_ROUNDS+1); i++) {
    k.w[i] = 0;
  }
}

state_matrix add_round_key(state_matrix in, uint32_t keys[4]) {
  //printf("%x, %x, %x, %x\n", keys[0], keys[1], keys[2], keys[3]);
  for(int i=0; i<4; i++) {
    in.m[0][i] ^= (keys[i]>>24)%256;
    in.m[1][i] ^= (keys[i]>>16)%256;
    in.m[2][i] ^= (keys[i]>>8)%256;
    in.m[3][i] ^= keys[i]%256;
  }
  return in;
}

state_matrix mix_columns(state_matrix in) {
  state_matrix out = zero_matrix();
  for(int i=0; i<4; i++) {
    out.m[0][i] = in.m[1][i] ^ in.m[2][i] ^ in.m[3][i] ^
      (in.m[0][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[0][i] >> 7))) ^
      (in.m[1][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[1][i] >> 7)));
    out.m[1][i] = in.m[0][i] ^ in.m[2][i] ^ in.m[3][i] ^
      (in.m[1][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[1][i] >> 7))) ^
      (in.m[2][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[2][i] >> 7)));
    out.m[2][i] = in.m[0][i] ^ in.m[1][i] ^ in.m[3][i] ^
      (in.m[2][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[2][i] >> 7))) ^
      (in.m[3][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[3][i] >> 7)));
    out.m[3][i] = in.m[0][i] ^ in.m[1][i] ^ in.m[2][i] ^
      (in.m[0][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[0][i] >> 7))) ^
      (in.m[3][i]<<1 ^ (0x1B & (uint8_t)((int8_t)in.m[3][i] >> 7)));
  }
  return out;
}

state_matrix inv_mix_columns(state_matrix in) {
  state_matrix out;
  uint8_t eights[4][4], fours[4][4], twos[4][4];
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      twos[i][j] = (in.m[i][j]<<1) ^ (0x1B & (uint8_t)((int8_t)in.m[i][j] >> 7));
      fours[i][j] = (twos[i][j]<<1) ^ (0x1B & (uint8_t)((int8_t)twos[i][j] >> 7));
      eights[i][j] = (fours[i][j]<<1) ^ (0x1B & (uint8_t)((int8_t)fours[i][j] >> 7));
    }
  }

  for(int i=0; i<4; i++) {
    //0e*(0,i) + 0b*(1,i) + 0d*(2,i) + 09*(3,i)
    out.m[0][i] = eights[0][i] ^ fours[0][i] ^ twos[0][i] ^//0e*(0,i)
                eights[1][i] ^ twos[1][i] ^ in.m[1][i] ^//0b*(1,i)
                eights[2][i] ^ fours[2][i] ^ in.m[2][i] ^//0d*(2,i)
                eights[3][i] ^ in.m[3][i];//09*(3,i)
    //09*(0,i) + 0e*(1,i) + 0b*(2,i) + 0d*(3,i)
    out.m[1][i] = eights[0][i] ^ in.m[0][i] ^//09
                eights[1][i] ^ fours[1][i] ^ twos[1][i] ^//0e
                eights[2][i] ^ twos[2][i] ^ in.m[2][i] ^//0b
                eights[3][i] ^ fours[3][i] ^ in.m[3][i];//0d
    //0d, 09, 0e, 0b
    out.m[2][i] = eights[0][i] ^ fours[0][i] ^ in.m[0][i] ^//0d
                eights[1][i] ^ in.m[1][i] ^//09
                eights[2][i] ^ fours[2][i] ^ twos[2][i] ^//0e
                eights[3][i] ^ twos[3][i] ^ in.m[3][i];//0b
    //0b, 0d, 09, 0e
    out.m[3][i] = eights[0][i] ^ twos[0][i] ^ in.m[0][i] ^//0b
                eights[1][i] ^ fours[1][i] ^ in.m[1][i] ^//0d
                eights[2][i] ^ in.m[2][i] ^//09
                eights[3][i] ^ fours[3][i] ^ twos[3][i];
  }

  return out;
}

state_matrix shift_rows(state_matrix in) {
  uint8_t temp = in.m[1][0];
  in.m[1][0] = in.m[1][1];
  in.m[1][1] = in.m[1][2];
  in.m[1][2] = in.m[1][3];
  in.m[1][3] = temp;
  temp = in.m[2][0];
  in.m[2][0] = in.m[2][2];
  in.m[2][2] = temp;
  temp = in.m[2][1];
  in.m[2][1] = in.m[2][3];
  in.m[2][3] = temp;
  temp = in.m[3][3];
  in.m[3][3] = in.m[3][2];
  in.m[3][2] = in.m[3][1];
  in.m[3][1] = in.m[3][0];
  in.m[3][0] = temp;
  return in;
}
state_matrix inv_shift_rows(state_matrix in) {
  uint8_t temp = in.m[1][3];
  in.m[1][3] = in.m[1][2];
  in.m[1][2] = in.m[1][1];
  in.m[1][1] = in.m[1][0];
  in.m[1][0] = temp;
  temp = in.m[2][0];
  in.m[2][0] = in.m[2][2];
  in.m[2][2] = temp;
  temp = in.m[2][1];
  in.m[2][1] = in.m[2][3];
  in.m[2][3] = temp;
  temp = in.m[3][0];
  in.m[3][0] = in.m[3][1];
  in.m[3][1] = in.m[3][2];
  in.m[3][2] = in.m[3][3];
  in.m[3][3] = temp;
  return in;
}

state_matrix sub_bytes(state_matrix in) {
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      uint8_t byte = in.m[i][j];
      in.m[i][j] = SBOX[byte>>4][byte%16];
    }
  }
  return in;
}

state_matrix inv_sub_bytes(state_matrix in) {
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      uint8_t byte = in.m[i][j];
      in.m[i][j] = INV_SBOX[byte>>4][byte%16];
    }
  }
  return in;
}

uint32_t sub_word(uint32_t in) {
  uint32_t out = 0;
  for(int i=0; i<4; i++) {
    uint8_t byte = in>>24;
    out += SBOX[byte>>4][byte%16];
    in<<=8;
    if(i<3) out<<=8;
  }
  return out;
}

uint32_t rot_word(uint32_t in) {
  uint8_t temp = in>>24;
  uint32_t out = in<<8;
  out += temp;
  return out;
}

keys expand_key(uint32_t k[KEY_SIZE]) {
  keys ks = zero_keys();
  uint32_t temp;
  int i=0;
  while(i<KEY_SIZE) {
    ks.w[i] = k[i];
    //printf("w[%d] = %x\n", i, ks.w[i]);
    i++;
  }

  while(i<4*(NO_ROUNDS+1)) {
    //printf("%d\n", i);
    temp = ks.w[i-1];
    //printf("temp = %x\n", temp);
    if(i%KEY_SIZE == 0) {
      //temp = sub_word(rot_word(temp)) ^ RCON[i/KEY_SIZE];
      temp = rot_word(temp);
      //printf("after rot_word = %x\n", temp);
      temp = sub_word(temp);
      //printf("after sub_word = %x\n", temp);
      //printf("rcon = %x\n", RCON[i/KEY_SIZE]);
      temp ^= RCON[i/KEY_SIZE];
      //printf("after xor with rcon = %x\n", temp);
    } else if(KEY_SIZE > 6 && (i%KEY_SIZE == 4)) {
      temp = sub_word(temp);
      //printf("after sub_word = %x\n", temp);
    }
    //printf("w[i-Nk] = %x\n", ks.w[i-KEY_SIZE]);
    ks.w[i] = ks.w[i-KEY_SIZE] ^ temp;
    //printf("w[i] = %x\n", ks.w[i]);
    i++;
    //printf("\n");
  }

  return ks;
}


void print_matrix(state_matrix in) {
 for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      printf("%x ", in.m[i][j]);
    }
    printf("\n");
  }
}

void print_matrix_linear(state_matrix in) {
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      printf("%x", in.m[j][i]);
    }
  }
  printf("\n");
}

state_matrix aes(state_matrix in, keys k) {
  state_matrix state = in;

  uint32_t roundKeys[4] = {k.w[0], k.w[1], k.w[2], k.w[3]};
  state = add_round_key(state, roundKeys);

  for(int round = 1; round<NO_ROUNDS; round++) {
    state = sub_bytes(state);
    state = shift_rows(state);
    state = mix_columns(state);
    roundKeys[0] = k.w[round*4];
    roundKeys[1] = k.w[round*4 + 1];
    roundKeys[2] = k.w[round*4 + 2];
    roundKeys[3] = k.w[round*4 + 3];
    state = add_round_key(state, roundKeys);
  }

  state = sub_bytes(state);
  state = shift_rows(state);
  roundKeys[0] = k.w[NO_ROUNDS*4];
  roundKeys[1] = k.w[NO_ROUNDS*4 + 1];
  roundKeys[2] = k.w[NO_ROUNDS*4 + 2];
  roundKeys[3] = k.w[NO_ROUNDS*4 + 3];
  state = add_round_key(state, roundKeys);

  return state;
}

state_matrix inv_aes(state_matrix in, keys k) {
  state_matrix state = in;
  uint32_t roundKeys[4] = {k.w[NO_ROUNDS*4], k.w[NO_ROUNDS*4+1],
                           k.w[NO_ROUNDS*4+2], k.w[NO_ROUNDS*4+3]};
  state = add_round_key(state, roundKeys);

  for(int round=NO_ROUNDS-1; round>=1; round--) {
    state = inv_shift_rows(state);
    state = inv_sub_bytes(state);
    roundKeys[0] = k.w[round*4];
    roundKeys[1] = k.w[round*4 + 1];
    roundKeys[2] = k.w[round*4 + 2];
    roundKeys[3] = k.w[round*4 + 3];
    state = add_round_key(state, roundKeys);
    state = inv_mix_columns(state);
  }
  state = inv_shift_rows(state);
  state = inv_sub_bytes(state);
  roundKeys[0] = k.w[0];
  roundKeys[1] = k.w[1];
  roundKeys[2] = k.w[2];
  roundKeys[3] = k.w[3];
  state = add_round_key(state, roundKeys);

  return state;
}

state_matrix from_byte_array(uint8_t plaintext[16]) {
  state_matrix out;
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      out.m[i][j] = plaintext[4*j+i];
    }
  }
  return out;
}
uint8_t* to_byte_array(state_matrix in) {
  uint8_t *ret = malloc(16);
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      ret[4*j+i] = in.m[i][j];
    }
  }
  return ret;
}

/*int main() {
  //uint8_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
  //                       0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint32_t key[KEY_SIZE] = {0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f,
                            0x10111213,0x14151617,0x18191a1b,0x1c1d1e1f};

  srand(time(NULL));
  uint8_t plaintext[16];
  for(int i=0; i<16; i++) {
    plaintext[i] = rand()%256;
    printf("%x", plaintext[i]);
  }
  printf("\n");

  state_matrix input = from_byte_array(plaintext);
  keys ks = expand_key(key);
  state_matrix enc = aes(input, ks);
  uint8_t *enc_text = to_byte_array(enc);
  for(int i=0; i<16;i++) {
    printf("%x", enc_text[i]);
  }
  printf("\n");
  uint8_t *dec_text = to_byte_array(inv_aes(enc, ks));
  for(int i=0; i<16;i++) {
    printf("%x", dec_text[i]);
  }
  printf("\n");
}*/
