#include "myssh.h"

//TODO comment

void free_pak(packet p) {
  free_byteArray(p.payload);
  free(p.padding);
  free_byteArray(p.mac);
}

void copy_pak(const packet in, packet *out) {
  out->packet_length = in.packet_length;
  out->padding_length = in.padding_length;
  //out->payload.len = in.payload.len;
  //out->payload.arr = malloc(out->payload.len);
  //memcpy(out->payload.arr, in.payload.arr, out->payload.len);
  out->payload = copy_byteArray(in.payload);
  out->padding = malloc(out->padding_length);
  memcpy(out->padding, in.padding, out->padding_length);
  //out->mac.len = in.mac.len;
  //out->mac.arr = malloc(out->mac.len);
  //memcpy(out->mac.arr, in.mac.arr, out->mac.len);
  out->mac = copy_byteArray(in.mac);
}

packet clone_pak(const packet p) {
  packet out;
  out.packet_length = p.packet_length;
  out.padding_length = p.padding_length;
  //out.payload.len = p.payload.len;
  //out.payload.arr = malloc(out.payload.len);
  //memcpy(out.payload.arr, p.payload.arr, out.payload.len);
  out.payload = copy_byteArray(p.payload);
  out.padding = malloc(out.padding_length);
  memcpy(out.padding, p.padding, out.padding_length);
  //out.mac.len = p.mac.len;
  //out.mac.arr = malloc(out.mac.len);
  //memcpy(out.mac.arr, p.mac.arr, out.mac.len);
  out.mac = copy_byteArray(p.mac);
  return out;
}

int send_packet(const packet p, connection *c) {
  _byte_array_t bytes;
  packet_to_bytes(p, c, &bytes);
  int bytes_sent = send_byteArray(c->socket, bytes);
  c->sequence_number++;
  free_byteArray(bytes);
  return bytes_sent;
}

packet build_packet(const _byte_array_t in, connection *c) {
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

  //p.payload = malloc(in.len);
  //p.payload.len = in.len;
  //p.payload.arr = malloc(p.payload.len);
  //memcpy(p.payload.arr, in.arr, p.payload.len);
  //memcpy(p.payload, in.arr, in.len);
  p.payload = copy_byteArray(in);

  if(c->mac_c2s) {
    _byte_array_t to_mac = create_byteArray(0);
    //to_mac.len = p.packet_length + 8;
    //to_mac.arr = malloc(to_mac.len);
    //int_to_bytes(c->sequence_number, to_mac.arr);
    byteArray_append_int(to_mac, c->sequence_number);
    //int_to_bytes(p.packet_length, to_mac.arr + 4);
    byteArray_append_int(to_mac, p.packet_length);
    //to_mac.arr[8] = p.padding_length;
    byteArray_append_byte(to_mac, p.padding_length);
    //memcpy(to_mac.arr+9, p.payload.arr, p.payload.len);
    byteArray_append_byteArray(to_mac, p.payload);
    //memcpy(to_mac.arr+9+p.payload.len, p.padding, p.padding_length);
    char *padding = malloc(p.padding_length + 1);
    memcpy(padding, p.padding, p.padding_length);
    padding[p.padding_length] = '\0';
    byteArray_append_str(to_mac, p.padding);
    free(padding);
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

  _byte_array_t message = create_byteArray(17);
  //message.len = 17;
  //message.arr = malloc(message.len);
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

  //message.len+=build_name_list(NO_KEX_C_ALGOS, KEX_C_ALGOS,
  //  message.arr+message.len);

  /*message.len+=build_name_list(NO_KEY_C_ALGOS, KEY_C_ALGOS, message.arr+message.len);

  message.len+=build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message.arr+message.len);
  message.len+=build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message.arr+message.len);

  message.len+=build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message.arr+message.len);
  message.len+=build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message.arr+message.len);

  message.len+=build_name_list(NO_COM_ALGOS, COM_ALGOS, message.arr+message.len);
  message.len+=build_name_list(NO_COM_ALGOS, COM_ALGOS, message.arr+message.len);*/

  //message.len += 13;
  //message.arr = realloc(message.arr, message.len);
  //int_to_bytes(0, message.arr+message.len-13);
  //int_to_bytes(0, message.arr+message.len-9);
  byteArray_append_int(message, 0);
  byteArray_append_int(message, 0);
  //message.len+=8;

  //(message.arr+message.len-5)[0]=0;
  byteArray_append_byte(message, 0);

  //int_to_bytes(0, message.arr+message.len);
  //message.len+=4;
  //int_to_bytes(0, message.arr + message.len - 4);
  byteArray_append_int(message, 0);

  packet p = build_packet(message, c);

  free_byteArray(message);

  return p;
}

void build_name_list(uint32_t no_names,
                     const char *names[],
                     _byte_array_t out) {
  uint32_t startPos = get_byteArray_len(out);
  uint32_t strLen = 0;
  //out->len += 4;
  byteArray_append_int(out, 0);
  for(int i=0; i<no_names-1; i++) {
    //out->len += strlen(names[i]) + 1;
    //out->arr = realloc(out->arr, out->len);
    //memcpy(out->arr + out->len - strlen(names[i]) - 1, names[i],
    //    strlen(names[i]));
    byteArray_append_str(out, names[i]);
    //out->arr[out->len - 1] = ',';
    byteArray_append_byte(out, ',');
    strLen += strlen(names[i]) + 1;
  }
  //out->len += strlen(names[no_names - 1]);
  //out->arr = realloc(out->arr, out->len);
  //memcpy(out->arr + out->len - strlen(names[no_names - 1]), names[no_names-1],
  //    strlen(names[no_names - 1]));
  byteArray_append_str(out, names[no_names-1]);
  strLen += strlen(names[no_names - 1]);

  for(int i=0; i<4; i++) {
    set_byteArray_element(out, startPos + i, (strLen>>(8*(3-i)))%256);
  }
  //int_to_bytes(strLen, out->arr + out->len - strLen - 4);
}
