#include "myssh.h"

void free_pak(packet p) {
  free_byteArray(p.payload);
  free(p.padding);
  free_byteArray(p.mac);
}

void copy_pak(const packet in, packet *out) {
  out->packet_length = in.packet_length;
  out->padding_length = in.padding_length;
  out->payload = copy_byteArray(in.payload);
  out->padding = malloc(out->padding_length);
  memcpy(out->padding, in.padding, out->padding_length);
  out->mac = copy_byteArray(in.mac);
}

packet clone_pak(const packet p) {
  packet out;
  out.packet_length = p.packet_length;
  out.padding_length = p.padding_length;
  out.payload = copy_byteArray(p.payload);
  out.padding = malloc(out.padding_length);
  memcpy(out.padding, p.padding, out.padding_length);
  out.mac = copy_byteArray(p.mac);
  return out;
}

int send_packet(const packet p, connection *c) {
  byte_array_t bytes;
  packet_to_bytes(p, c, &bytes);
  int bytes_sent = send_byteArray(c->socket, bytes);
  (c->sequence_number)++;
  free_byteArray(bytes);
  return bytes_sent;
}

packet build_packet(const byte_array_t in, connection *c) {
  packet p;

  uint8_t block_size;
  uint32_t in_len = get_byteArray_len(in);
  if(c->enc_c2s)
    block_size = c->enc_c2s->block_size;
  else
    block_size = 8;

  p.padding_length = block_size - ((in_len + 5)%block_size);
  if(p.padding_length<4)
    p.padding_length+=block_size;

  p.padding = malloc(p.padding_length);
  for(int i=0; i<p.padding_length; i++) {
    p.padding[i] = rand();
  }

  p.packet_length = in_len + p.padding_length + 1;

  p.payload = copy_byteArray(in);

  if(c->mac_c2s) {
    byte_array_t to_mac = create_byteArray(0);
    byteArray_append_int(to_mac, c->sequence_number);
    byteArray_append_int(to_mac, p.packet_length);
    byteArray_append_byte(to_mac, p.padding_length);
    byteArray_append_byteArray(to_mac, p.payload);
    byteArray_append_bytes(to_mac, p.padding, p.padding_length);
    c->mac_c2s->mac(to_mac, c->mac_c2s->key, c->mac_c2s->hash,
        c->mac_c2s->hash_block_size, &p.mac);
    free_byteArray(to_mac);
  } else {
    p.mac = create_byteArray(0);
  }

  return p;
}

/* Creates the KEXINIT packet, consisting of name lists of viable
 * algorithms for kex, encryption etc. See rfc4253§7.1. */
packet build_kex_init(connection *c) {

  byte_array_t message = create_byteArray(17);
  set_byteArray_element(message, 0, SSH_MSG_KEXINIT);
  //The first 16 bytes are a random 'cookie'
  for(int i=1; i<17; i++) {
    set_byteArray_element(message, i, rand());
  }

  build_name_list(NO_KEX_C_ALGOS, KEX_C_ALGOS, message);
  build_name_list(NO_KEY_C_ALGOS, KEY_C_ALGOS, message);

  build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message);
  build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message);

  build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message);
  build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message);

  build_name_list(NO_COM_ALGOS, COM_ALGOS, message);
  build_name_list(NO_COM_ALGOS, COM_ALGOS, message);
  byteArray_append_int(message, 0);
  byteArray_append_int(message, 0);
  byteArray_append_byte(message, 0);
  byteArray_append_int(message, 0);

  packet p = build_packet(message, c);

  free_byteArray(message);

  return p;
}

void build_name_list(uint32_t no_names,
                     const char *names[],
                     byte_array_t out) {
  uint32_t startPos = get_byteArray_len(out);
  uint32_t strLen = 0;
  byteArray_append_int(out, 0);
  for(int i=0; i<no_names-1; i++) {
    byteArray_append_str(out, names[i]);
    byteArray_append_byte(out, ',');
    strLen += strlen(names[i]) + 1;
  }
  byteArray_append_str(out, names[no_names-1]);
  strLen += strlen(names[no_names - 1]);

  for(int i=0; i<4; i++) {
    set_byteArray_element(out, startPos + i, (strLen>>(8*(3-i)))%256);
  }
}


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

void packet_to_bytes(packet p, connection *c, byte_array_t *bytes) {

  byte_array_t to_encrypt = create_byteArray(0);
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
