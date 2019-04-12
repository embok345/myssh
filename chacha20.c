#include "myssh.h"

void print_state(uint32_t *state) {
  for(int i=0; i<4; i++) {
    for(int j=0; j<4; j++) {
      printf("%x ", state[4*i + j]);
    }
    printf("\n");
  }
}

void left_rotate(uint32_t *in, uint8_t amount) {
  *in = ((*in)<<amount) + ((*in)>>(32-amount));
}

void chacha_quarter(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
  *a += *b;
  *d ^= *a;
  left_rotate(d, 16);

  *c += *d;
  *b ^= *c;
  left_rotate(b, 12);

  *a += *b;
  *d ^= *a;
  left_rotate(d, 8);

  *c += *d;
  *b ^= *c;
  left_rotate(b, 7);
}

void chacha_rounds(uint32_t *state) {
  for(int i=0; i<10; i++) {
    chacha_quarter(&state[0], &state[4], &state[8], &state[12]);
    chacha_quarter(&state[1], &state[5], &state[9], &state[13]);
    chacha_quarter(&state[2], &state[6], &state[10], &state[14]);
    chacha_quarter(&state[3], &state[7], &state[11], &state[15]);

    chacha_quarter(&state[0], &state[5], &state[10], &state[15]);
    chacha_quarter(&state[1], &state[6], &state[11], &state[12]);
    chacha_quarter(&state[2], &state[7], &state[8], &state[13]);
    chacha_quarter(&state[3], &state[4], &state[9], &state[14]);
  }
}

uint8_t setup_state(byte_array_t key,
                    uint32_t counter,
                    byte_array_t nonce,
                    uint32_t *state) {
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  if(key.len != 32) return 1;
  for(int i=0; i<8; i++) {
    state[4 + i] = 0;
    for(int j=0; j<4; j++) {
      state[4 + i]<<=8;
      state[4 + i] += key.arr[4*(i+1) - j - 1];
    }
  }
  state[12] = counter;
  if(nonce.len != 12) return 1;
  for(int i=0; i<3; i++) {
    state[13 + i] = 0;
    for(int j = 0; j<4; j++) {
      state[13 + i] <<= 8;
      state[13 + i] += nonce.arr[4*(i+1) - j - 1];
    }
  }

}

byte_array_t state_to_bytes(uint32_t *state) {
  byte_array_t output;
  output.len = 64;
  output.arr = malloc(output.len);
  for(int i=0; i<16; i++) {
    output.arr[4*i] = state[i]%256;
    output.arr[(4*i)+1] = (state[i]>>8)%256;
    output.arr[(4*i)+2] = (state[i]>>16)%256;
    output.arr[(4*i)+3] = (state[i]>>24)%256;
  }
  return output;
}

byte_array_t chacha_block(byte_array_t key, uint32_t counter,
    byte_array_t nonce) {
  uint32_t *state = malloc(16*sizeof(uint32_t));
  uint32_t *working_state = malloc(16*sizeof(uint32_t));

  setup_state(key, counter, nonce, state);
  memcpy(working_state, state, 16*sizeof(uint32_t));

  chacha_rounds(working_state);

  for(int i=0; i<16; i++) {
    state[i] += working_state[i];
  }
  free(working_state);

  byte_array_t output = state_to_bytes(state);
  free(state);

  return output;
}

byte_array_t chacha(byte_array_t input, byte_array_t key,
    uint32_t *counter, byte_array_t nonce) {
  uint32_t no_blocks = input.len / 64;
  if(input.len % 64 != 0) no_blocks+=1;
  byte_array_t key_stream;
  key_stream.len = 64*no_blocks;
  key_stream.arr = malloc(key_stream.len);
  for(int i=0; i<no_blocks; i++) {
    byte_array_t block = chacha_block(key, (*counter)++, nonce);
    memcpy(key_stream.arr + (i*64), block.arr, block.len);
    free(block.arr);
  }
  byte_array_t output;
  output.len = input.len;
  output.arr = malloc(output.len);
  for(int i=0; i<output.len; i++) {
    output.arr[i] = key_stream.arr[i]^input.arr[i];
  }
  free(key_stream.arr);
  return output;
}

/*int main() {
  byte_array_t key;
  key.len = 32;
  key.arr = malloc(key.len);
  for(int i=0; i<key.len; i++) key.arr[i] = i;
  byte_array_t nonce;
  nonce.len = 12;
  nonce.arr = malloc(nonce.len);
  for(int i=0; i<nonce.len; i++) nonce.arr[i] = 0;
  nonce.arr[7] = 0x4a;
  byte_array_t plaintext;
  plaintext.len = 114;
  uint8_t text[] = {0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
0x74, 0x2e};
  plaintext.arr = text;
  uint32_t counter = 1;
  byte_array_t cipher = chacha(plaintext, key, &counter, nonce);
  for(int i=0; i<cipher.len; i++) {
    printf("%x ", cipher.arr[i]);
  }
  printf("\n");

  free(cipher.arr);
  free(key.arr);
  free(nonce.arr);
}
*/
