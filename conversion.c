#include "myssh.h"

uint32_t bytes_to_int(const uint8_t* bytes) {
  uint32_t out = bytes[0];
  out = (out<<8) + bytes[1];
  out = (out<<8) + bytes[2];
  out = (out<<8) + bytes[3];
  return out;
}
void int_to_bytes(uint32_t in, uint8_t *out) {
  out[0] = in>>24;
  out[1] = (in>>16)%256;
  out[2] = (in>>8)%256;
  out[3] = in%256;
}


packet bytes_to_packet(const uint8_t *bytes, int len) {
  packet p;
  p.packet_length = bytes_to_int(bytes);
  p.padding_length = bytes[4];
  p.payload = malloc(p.packet_length - p.padding_length - 1);
  memcpy(p.payload, bytes+5, p.packet_length - p.padding_length - 1);
  p.padding = malloc(p.padding_length);
  memcpy(p.padding, bytes+5+p.packet_length-p.padding_length-1, p.padding_length);

  p.mac.len = 0;    //TODO change this
  p.mac.arr = NULL; //TODO

  return p;
}

void packet_to_bytes(packet p, connection *c, byte_array_t *bytes) {

  byte_array_t to_encrypt;
  to_encrypt.len = p.packet_length + 4;
  to_encrypt.arr = malloc(to_encrypt.len);
  int_to_bytes(p.packet_length, to_encrypt.arr);
  to_encrypt.arr[4] = p.padding_length;
  memcpy(to_encrypt.arr + 5, p.payload, p.packet_length - p.padding_length - 1);
  memcpy(to_encrypt.arr + 5 + p.packet_length - p.padding_length - 1,
         p.padding, p.padding_length);

  if(c->enc_c2s) {
    //int success = aes_ctr(to_encrypt, c->enc_c2s->key, &(c->enciv_c2s), bytes);
    if(c->enc_c2s->enc(to_encrypt, c->enc_c2s->key, &(c->enc_c2s->iv), bytes)
        != 0)
      printf("Encryption failed!\n");
  } else {
    bytes->len = to_encrypt.len;
    bytes->arr = malloc(bytes->len);
    memcpy(bytes->arr, to_encrypt.arr, bytes->len);
  }
  free(to_encrypt.arr);

  if(c->mac_c2s) {
    printf("mac = ");
    for(int i=0; i<p.mac.len; i++) {
      printf("%x ", p.mac.arr[i]);
    }
    printf("\n");
    bytes->len += p.mac.len;
    bytes->arr = realloc(bytes->arr, bytes->len);
    memcpy(bytes->arr + bytes->len - p.mac.len, p.mac.arr, p.mac.len);
  }

  printf("\nSending bytes: ");
  for(int i=0; i<bytes->len; i++) {
    printf("%x ", bytes->arr[i]);
  }
  printf("\n");
}

uint32_t bignum_to_mpint(const bignum *in, uint8_t *blocks) {
  uint32_t len = bn_trueLength(in);
  uint32_t i=0;
  if(bn_getBlock(in, len-1) >= 128) {
    len++;
    i++;
    blocks[4] = 0;
  }
  int_to_bytes(len, blocks);
  for(; i<len; i++) {
    blocks[i+4] = bn_getBlock(in, len-i-1);
  }
  return len+4;
}

void mpint_to_bignum(const uint8_t *blocks, uint32_t len, bignum *out) {
  bn_resize(out, len);
  for(uint32_t i=0; i<len; i++) {
    bn_setBlock(out, i, blocks[len-i-1]);
  }
  bn_removezeros(out);
}
