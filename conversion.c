#include "myssh.h"

//TODO comment, clean up, are we sure we really need some of these?
//some of them are essentially dupes

packet bytes_to_packet(const uint8_t *bytes, int len) {
  packet p;
  p.packet_length = bytes_to_int(bytes);
  p.padding_length = bytes[4];
  p.payload = set_byteArray(p.packet_length - p.padding_length - 1,
      bytes+5);

  p.padding = malloc(p.padding_length);
  memcpy(p.padding, bytes+5+get_byteArray_len(p.payload), p.padding_length);

  p.mac = create_byteArray(0);

  return p;
}

void packet_to_bytes(packet p, connection *c, _byte_array_t *bytes) {

  _byte_array_t to_encrypt = create_byteArray(0);
  byteArray_append_int(to_encrypt, p.packet_length);
  byteArray_append_byte(to_encrypt, p.padding_length);
  byteArray_append_byteArray(to_encrypt, p.payload);
  byteArray_append_bytes(to_encrypt, p.padding, p.padding_length);

  if(c->enc_c2s) {
    if(c->enc_c2s->enc(to_encrypt, c->enc_c2s->key, c->enc_c2s->iv, bytes)
        != 0) {
      printf("Encryption failed\n"); //TODO Maybe do something better here
      return;
    }
  } else {
    *bytes = copy_byteArray(to_encrypt);
  }
  free_byteArray(to_encrypt);

  if(c->mac_c2s) {
    byteArray_append_byteArray(*bytes, p.mac);
  }
}
