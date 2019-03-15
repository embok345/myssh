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
  byte_array_t iv_copy;
  iv_copy.len = c->iv_c2s.len;
  iv_copy.arr = malloc(iv_copy.len);
  memcpy(iv_copy.arr, c->iv_c2s.arr, iv_copy.len);
  packet_to_bytes(p, c, &bytes);
  send(c->socket, bytes.arr, bytes.len, 0);
  c->sequence_number++;
  free(bytes.arr);
}

void make_mac(packet *p, connection *c) {
  byte_array_t ipad, opad;
  ipad.len = c->mac_c2s.len;
  opad.len = c->mac_c2s.len;
  ipad.arr = malloc(ipad.len);
  opad.arr = malloc(opad.len);
  memcpy(ipad.arr, c->mac_c2s.arr, ipad.len);
  memcpy(opad.arr, c->mac_c2s.arr, opad.len);
  if(c->mac_c2s.len < c->mac_block_size) {
    ipad.len = c->mac_block_size;
    opad.len = c->mac_block_size;
    ipad.arr = realloc(ipad.arr, ipad.len);
    opad.arr = realloc(opad.arr, opad.len);
    for(int i=c->mac_c2s.len; i<c->mac_block_size; i++) {
      ipad.arr[i] = 0;
      opad.arr[i] = 0;
    }
  } else if(c->mac_c2s.len > c->mac_block_size) {
    printf("This shouldn't be reached\n");
  }

  for(int i=0; i<ipad.len; i++) {
    ipad.arr[i] ^= 0x36;
    opad.arr[i] ^= 0x5c;
  }

  byte_array_t to_mac;
  to_mac.len = p->packet_length + 8;
  to_mac.arr = malloc(to_mac.len);
  int_to_bytes(c->sequence_number, to_mac.arr);
  int_to_bytes(p->packet_length, to_mac.arr + 4);
  to_mac.arr[8] = p->padding_length;
  memcpy(to_mac.arr + 9, p->payload, p->packet_length - p->padding_length - 1);
  memcpy(to_mac.arr + 9 + p->packet_length - p->padding_length - 1,
         p->padding, p->padding_length);

  ipad.len += to_mac.len;
  ipad.arr = realloc(ipad.arr, ipad.len);
  memcpy(ipad.arr + ipad.len - to_mac.len, to_mac.arr, to_mac.len);
  sha_256(ipad, &ipad);
  opad.len += ipad.len;
  opad.arr = realloc(opad.arr, opad.len);
  memcpy(opad.arr + opad.len - ipad.len, ipad.arr, ipad.len);
  sha_256(opad, &opad);

  p->mac.len = opad.len;
  p->mac.arr = malloc(p->mac.len);
  memcpy(p->mac.arr, opad.arr, p->mac.len);

  free(opad.arr);
  free(ipad.arr);
  free(to_mac.arr);
}

packet build_packet(const byte_array_t in, connection *c) {
  packet p;

  uint32_t block_size = (c->encryption_block_size<8) ? 8 : c->encryption_block_size;

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

  if(c->mac_block_size == 0) {
    p.mac.len = 0;
    p.mac.arr = NULL;
  } else {
    make_mac(&p, c);
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