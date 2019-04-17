#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "myssh.h"

//TODO comment

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
  uint8_t key_size; //=16, 24, or 32
  uint32_t *w;
} keys;

state_matrix zero_matrix() {
  state_matrix m;
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      m.m[i][j] = 0;
    }
  }
  return m;
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

keys expand_key(const _byte_array_t k) {
  uint32_t k_len = get_byteArray_len(k);
  //uint32_t k_len = k.len;
  keys ks;
  ks.key_size = k_len;
  ks.w = NULL;
  if(k_len != 16 && k_len != 24 && k_len != 32) {
    printf("Invalid key length\n");
    return ks;
  }
  uint8_t no_rounds = (k_len/4) + 6;
  ks.w = malloc(sizeof(uint32_t) * 4 * (no_rounds+1));
  uint32_t temp;
  int i=0;
  while(i<ks.key_size/4) {
    ks.w[i] = 0;
    for(int j=0; j<4; j++) {
      ks.w[i] <<= 8;
      if(4*i + j < k_len)
        //ks.w[i] += (uint32_t)k.arr[4*i+j];
        ks.w[i] += (uint32_t)get_byteArray_element(k, 4*i+j);
    }
    i++;
  }

  while(i<4*(no_rounds+1)) {
    temp = ks.w[i-1];
    if(i%(ks.key_size/4) == 0) {
      temp = rot_word(temp);
      temp = sub_word(temp);
      temp ^= RCON[i/(ks.key_size/4)];
    } else if((ks.key_size/4) > 6 && (i%(ks.key_size/4) == 4)) {
      temp = sub_word(temp);
    }
    ks.w[i] = ks.w[i-(ks.key_size/4)] ^ temp;
    i++;
  }

  return ks;
}

state_matrix __aes__(state_matrix in, keys k) {
  state_matrix state = in;
  uint8_t no_rounds = (k.key_size/4) + 6;

  uint32_t roundKeys[4] = {k.w[0], k.w[1], k.w[2], k.w[3]};
  state = add_round_key(state, roundKeys);

  for(int round = 1; round<no_rounds; round++) {
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
  roundKeys[0] = k.w[no_rounds*4];
  roundKeys[1] = k.w[no_rounds*4 + 1];
  roundKeys[2] = k.w[no_rounds*4 + 2];
  roundKeys[3] = k.w[no_rounds*4 + 3];
  state = add_round_key(state, roundKeys);

  return state;
}

state_matrix __inv_aes__(state_matrix in, keys k) {
  state_matrix state = in;
  uint8_t no_rounds = (k.key_size/4) + 6;
  uint32_t roundKeys[4] = {k.w[no_rounds*4], k.w[no_rounds*4+1],
                           k.w[no_rounds*4+2], k.w[no_rounds*4+3]};
  state = add_round_key(state, roundKeys);

  for(int round=no_rounds-1; round>=1; round--) {
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

state_matrix byteArray_to_stateMatrix(const _byte_array_t arr) {
  state_matrix out;
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      //if(4*j+i >= arr.len)
      //  out.m[i][j] = 0;
      //else
      //  out.m[i][j] = arr.arr[4*j+i];
      out.m[i][j] = get_byteArray_element(arr, 4*j + i);
    }
  }
  return out;
}

_byte_array_t stateMatrix_to_byteArray(state_matrix in) {
  _byte_array_t ret = create_byteArray(16);
  //byte_array_t ret;
  //ret.len = 16;
  //ret.arr = malloc(16);
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      //ret.arr[4*j+i] = in.m[i][j];
      set_byteArray_element(ret, 4*j+i, in.m[i][j]);
    }
  }
  return ret;
}

/*void increment_byte_array(byte_array_t in) {
  uint32_t pos = in.len-1;
  in.arr[pos] = (in.arr[pos]) + 1;
  while(in.arr[pos] == 0 && pos>0) {
    pos--;
    (in.arr[pos])++;
  }
}*/

//int aes_ctr(const byte_array_t in, const byte_array_t key,
//    byte_array_t *ctr, byte_array_t *out) {
int aes_ctr(const _byte_array_t in, const _byte_array_t key,
    _byte_array_t ctr, _byte_array_t *out) {

  uint32_t k_len = get_byteArray_len(key);
  if(k_len != 16 && k_len != 24 && k_len != 32) {
  //if(key.len != 16 && key.len != 24 && key.len !=32) {
    printf("Invalid key length\n");
    return 1;
  }

  uint32_t in_len = get_byteArray_len(in);
  if(in_len%16 != 0) {
  //if(in.len%16 != 0) {
    printf("Incorrect message length\n");
    return 2;
  }
  uint32_t ctr_len = get_byteArray_len(ctr);
  if(ctr_len != 16) {
  //if(ctr->len != 16) {
    printf("Incorrect IV length\n");
    return 3;
  }

  //out->len = in.len;
  //out->arr = malloc(out->len);
  *out = create_byteArray(in_len);

  keys k = expand_key(key);
  if(!k.w) return 4;

  //for(uint32_t i=0; i<in.len/16; i++) {
  for(uint32_t i=0; i<in_len/16; i++) {
    //state_matrix ctr_sm = byteArray_to_stateMatrix(*ctr);
    state_matrix ctr_sm = byteArray_to_stateMatrix(ctr);
    state_matrix aes_out_sm = __aes__(ctr_sm, k);
    //byte_array_t aes_out = stateMatrix_to_byteArray(aes_out_sm);
    _byte_array_t aes_out = stateMatrix_to_byteArray(aes_out_sm);
    uint32_t aes_out_len = get_byteArray_len(aes_out);
    for(uint32_t j=0; j<aes_out_len; j++) {
    //for(uint32_t j=0; j<aes_out.len; j++) {
      //out->arr[16*i + j] = in.arr[16*i + j] ^ aes_out.arr[j];
      set_byteArray_element(*out, 16*i + j,
          get_byteArray_element(in, 16*i+j) ^ get_byteArray_element(aes_out, j));
    }
    free_byteArray(aes_out);
    increment_byteArray(ctr);
  }

  free(k.w);

  return 0;
}
