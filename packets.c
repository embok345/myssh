#include "myssh.h"

void free_pak(packet *p) {
  free(p->payload);
  free(p->padding);
  free(p->mac.arr);
}

packet build_kex_init(connection *c) {
  byte_array_t message;
  message.arr = malloc(2000);
  //uint8_t *message = malloc(2000);
  message.arr[0] = SSH_MSG_KEXINIT;
  for(int i=1; i<17; i++) {
    message.arr[i] = rand();
  }
  message.len = 17;

  message.len+=build_name_list(NO_KEX_ALGOS, KEX_ALGOS, message.arr+message.len);

  message.len+=build_name_list(NO_KEY_ALGOS, KEY_ALGOS, message.arr+message.len);

  message.len+=build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message.arr+message.len);
  message.len+=build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message.arr+message.len);

  message.len+=build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message.arr+message.len);
  message.len+=build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message.arr+message.len);

  message.len+=build_name_list(NO_COM_ALGOS, COM_ALGOS, message.arr+message.len);
  message.len+=build_name_list(NO_COM_ALGOS, COM_ALGOS, message.arr+message.len);

  int_to_bytes(0, message.arr+message.len);
  int_to_bytes(0, message.arr+message.len+4);
  message.len+=8;

  message.arr[message.len++]=0;

  int_to_bytes(0, message.arr+message.len);
  message.len+=4;

  packet p = build_packet(message, c);

  free(message.arr);

  return p;
}

int send_packet(packet p, connection *c) {
  byte_array_t bytes;
  packet_to_bytes(p, c, &bytes);
  send(c->socket, bytes.arr, bytes.len, 0);
  c->sequence_number++;
  free(bytes.arr);
}

packet build_packet(const byte_array_t in, connection *c) {
  packet p;

  uint8_t block_size;
  if(c->enc_c2s)
    block_size = c->enc_c2s->block_size;
  else
    block_size = 8;

  p.padding_length = block_size - ((in.len + 5)%block_size);
  if(p.padding_length<4)
    p.padding_length+=block_size;

  p.padding = malloc(p.padding_length);
  for(int i=0; i<p.padding_length; i++) {
    p.padding[i] = rand();
  }

  p.packet_length = in.len + p.padding_length + 1;

  p.payload = malloc(in.len);
  memcpy(p.payload, in.arr, in.len);

  if(c->mac_c2s) {
    byte_array_t to_mac;
    to_mac.len = p.packet_length + 8;
    to_mac.arr = malloc(to_mac.len);
    int_to_bytes(c->sequence_number, to_mac.arr);
    int_to_bytes(p.packet_length, to_mac.arr + 4);
    to_mac.arr[8] = p.padding_length;
    memcpy(to_mac.arr+9, p.payload, p.packet_length - p.padding_length - 1);
    memcpy(to_mac.arr+9+p.packet_length-p.padding_length-1, p.padding, p.padding_length);
    c->mac_c2s->mac(to_mac, c->mac_c2s->key, c->mac_c2s->hash,
        c->mac_c2s->hash_block_size, &p.mac);
    free(to_mac.arr);
  } else {
    p.mac.len = 0;
    p.mac.arr = NULL;
  }

  return p;
}

uint32_t build_name_list(uint32_t no_names, const char *names[], uint8_t *out_bytes) {
  uint32_t stringLength = 0;
  for(int i=0; i<no_names; i++) {
    memcpy(out_bytes+stringLength+4, names[i], strlen(names[i]));
    stringLength+=strlen(names[i]);
    if(i+1<no_names)
      (out_bytes+(stringLength++)+5)[0] = ',';
  }
  int_to_bytes(stringLength, out_bytes);
  return stringLength+4;
}
