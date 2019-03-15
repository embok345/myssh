#include "myssh.h"

uint8_t *I_C;
uint8_t *I_S;

void derive_keys(const bignum *, const byte_array_t, connection *);

int main() {

  srand(time(NULL));
  register_printf_specifier('B', bn_printf, bn_printf_info);

  int sock;
  struct sockaddr_in dest;

  sock = socket(AF_INET, SOCK_STREAM, 0);

  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr("142.93.230.76");
  dest.sin_port = htons(24318);

  connect(sock, (struct sockaddr *)&dest, sizeof(struct sockaddr_in));

  connection con;
  con.socket = sock;
  con.enc_c2s = NULL;
  con.enc_s2c = NULL;
  con.mac_c2s = NULL;
  con.mac_s2c = NULL;
  con.sequence_number = 0;

  if(start_connection(&con) == 1)
    return 1;


  printf("%s%s", I_C, I_S);

  bignum *K;
  byte_array_t exchange_hash;

  kex_init(&con, &K, &exchange_hash);

  //TODO move this into kex
  con.session_id = exchange_hash;
  con.enc_c2s = malloc(sizeof(enc_struct));
  con.enc_c2s->enc = aes_ctr;
  con.enc_c2s->dec = aes_ctr;
  con.enc_c2s->block_size=16;
  con.enc_c2s->key_size=32;
  con.enc_s2c = malloc(sizeof(enc_struct));
  con.enc_s2c->enc = aes_ctr;
  con.enc_s2c->dec = aes_ctr;
  con.enc_s2c->block_size=16;
  con.enc_s2c->key_size=32;
  con.mac_c2s = malloc(sizeof(mac_struct));
  con.mac_c2s->hash = sha_256;
  con.mac_c2s->mac = hmac;
  con.mac_c2s->hash_block_size = 64;
  con.mac_c2s->mac_output_size = 32;
  con.mac_s2c = malloc(sizeof(mac_struct));
  con.mac_s2c->hash = sha_256;
  con.mac_s2c->mac = hmac;
  con.mac_s2c->hash_block_size = 64;
  con.mac_s2c->mac_output_size = 32;
  derive_keys(K, exchange_hash, &con);

  bn_nuke(&K);

  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&con);

  uint8_t *msg = "ssh-userauth";
  byte_array_t service_request_message;
  service_request_message.len = strlen(msg) + 5;
  service_request_message.arr = malloc(service_request_message.len);
  service_request_message.arr[0] = SSH_MSG_SERVICE_REQUEST;
  int_to_bytes(strlen(msg), service_request_message.arr+1);
  memcpy(service_request_message.arr + 5, msg, strlen(msg));
  packet service_request_pak = build_packet(service_request_message, &con);
  send_packet(service_request_pak, &con);

  free_pak(&service_request_pak);
  free(service_request_message.arr);

  byte_array_t *user_auth_response_bytes;
  pthread_join(tid, (void **)&user_auth_response_bytes);

  printf("Received response: ");
  for(int i=0; i<user_auth_response_bytes->len; i++) {
    printf("%x ", user_auth_response_bytes->arr[i]);
  }
  printf("\n");
  free(user_auth_response_bytes->arr);
  free(user_auth_response_bytes);


  free(exchange_hash.arr);
  free(con.enc_c2s->key.arr);
  free(con.enc_c2s->iv.arr);
  free(con.enc_s2c->key.arr);
  free(con.enc_s2c->iv.arr);
  free(con.mac_s2c->key.arr);
  free(con.mac_c2s->key.arr);
  free(con.enc_c2s);
  free(con.enc_s2c);
  free(con.mac_c2s);
  free(con.mac_s2c);

  free(I_C);
  free(I_S);
  return 0;
}

void derive_keys(const bignum *K, const byte_array_t H, connection *c) {

  //TODO change to the correct hasing algorithm

  uint32_t prehash_len = 4 + bn_trueLength(K) + H.len + c->session_id.len + 1;
  if(bn_getBlock(K, bn_trueLength(K)-1) >= 128) {
    prehash_len++;
  }
  byte_array_t prehash;
  prehash.len = prehash_len;
  prehash.arr = malloc(prehash_len);
  uint32_t offset = bignum_to_mpint(K, prehash.arr);
  memcpy(prehash.arr+offset, H.arr, H.len);
  memcpy(prehash.arr+offset+H.len+1, c->session_id.arr, c->session_id.len);

  (prehash.arr+offset+H.len)[0] = 65;
  sha_256(prehash, &(c->enc_c2s->iv));
  c->enc_c2s->iv.len = c->enc_c2s->block_size;

  (prehash.arr+offset+H.len)[0] = 66;
  sha_256(prehash, &(c->enc_s2c->iv));
  c->enc_s2c->iv.len = c->enc_s2c->block_size;


  (prehash.arr+offset+H.len)[0] = 67;
  sha_256(prehash, &(c->enc_c2s->key));

  (prehash.arr+offset+H.len)[0] = 68;
  sha_256(prehash, &(c->enc_s2c->key));

  (prehash.arr+offset+H.len)[0] = 69;
  sha_256(prehash, &(c->mac_c2s->key));

  (prehash.arr+offset+H.len)[0] = 70;
  sha_256(prehash, &(c->mac_s2c->key));

  free(prehash.arr);
}

void *listener_thread(void *arg) {
  connection *c = (connection *)arg;

  uint32_t first_length;
  if(!c->enc_s2c)
    first_length = 4;
  else
    first_length = c->enc_s2c->block_size;

  byte_array_t first_block;
  first_block.len = first_length;
  first_block.arr = malloc(first_block.len);
  recv(c->socket, first_block.arr, first_block.len, 0);

  byte_array_t temp, *output;
  output = malloc(sizeof(byte_array_t));
  if(c->enc_s2c) {
    c->enc_s2c->dec(first_block, c->enc_s2c->key, &(c->enc_s2c->iv), &temp);
    output->len = temp.len;
    output->arr = malloc(output->len);
    memcpy(output->arr, temp.arr, output->len);
    free(temp.arr);
  } else {
    output->len = first_block.len;
    output->arr = malloc(output->len);
    memcpy(output->arr, first_block.arr, output->len);
  }
  free(first_block.arr);

  int to_receive = bytes_to_int(output->arr) + 4 - first_length;
  if(to_receive >= 35000) {
    printf("Invalid message length\n");
    return NULL;
  }

  byte_array_t next_blocks;
  next_blocks.len = to_receive;
  next_blocks.arr = malloc(to_receive);
  recv(c->socket, next_blocks.arr, to_receive, 0);

  //if(c->encryption_block_size != 0) {
  if(c->enc_s2c) {
    //aes_ctr(next_blocks, c->key_s2c, &(c->iv_s2c), &temp);
    c->enc_s2c->dec(next_blocks, c->enc_s2c->key,
        &(c->enc_s2c->iv), &temp);
    output->len += temp.len;
    output->arr = realloc(output->arr, output->len);
    memcpy(output->arr + first_block.len, temp.arr,
        output->len - first_block.len);
    free(temp.arr);
  } else {
    output->len += next_blocks.len;
    output->arr = realloc(output->arr, output->len);
    memcpy(output->arr + first_block.len, next_blocks.arr,
        output->len - first_block.len);
  }
  free(next_blocks.arr);

  if(c->mac_s2c) {
    output->len += c->mac_s2c->mac_output_size;
    output->arr = realloc(output->arr, output->len);
    recv(c->socket, output->arr + output->len - c->mac_s2c->mac_output_size,
        c->mac_s2c->mac_output_size, 0);
    //TODO we should check if the mac is the same
  }

  return (void *)output;

}

int start_connection(connection *c) {

  int I_C_len = strlen(VERSION) + 11;
  I_C = malloc(I_C_len);
  snprintf(I_C, I_C_len, "SSH-2.0-%s\r\n", VERSION);
  send(c->socket, I_C, I_C_len - 1, 0);

  byte_array_t identification_s_string;
  identification_s_string.arr = malloc(200);
  identification_s_string.len = recv(c->socket, identification_s_string.arr, 200, 0);

  while(identification_s_string.len < 4 ||
      memcmp(identification_s_string.arr, "SSH-", 3)!=0) {
    identification_s_string.len = recv(c->socket, identification_s_string.arr, 200, 0);
  }

  //remote_constr now starts with "SSH-"
  if(identification_s_string.len<8 ||
      memcmp(identification_s_string.arr+4, "2.0-", 4)!=0) {
    printf("Invalid protocol\n");
    free(identification_s_string.arr);
    return 1;
  }

  I_S = malloc(identification_s_string.len + 1);
  memcpy(I_S, identification_s_string.arr, identification_s_string.len);
  I_S[identification_s_string.len] = '\0';

  free(identification_s_string.arr);

  return 0;
}

void kex_init(connection *c, bignum **K, byte_array_t *exchange_hash) {
  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)c);

  packet kex_init_c_pak = build_kex_init(c);
  send_packet(kex_init_c_pak, c);

  byte_array_t *kex_init_s_bytes;
  pthread_join(tid, (void **)&kex_init_s_bytes);
  packet kex_init_s_pak = bytes_to_packet(kex_init_s_bytes->arr,
      kex_init_s_bytes->len);
  free(kex_init_s_bytes->arr);
  free(kex_init_s_bytes);
  //TODO We should really check here that the algorithms match up

  bignum *p, *g, *x, *e;
  bn_inits(4, &p, &g, &x, &e);
  bn_set(p, 256, DH_14_BLOCKS, 1);
  bn_conv_int2bn(2, g);
  bn_conv_int2bn(10000+(rand()%10000), x);
  bn_powmod(g, x, p, e);

  byte_array_t kex_dh_init_payload;
  uint32_t e_len = bn_trueLength(e);
  kex_dh_init_payload.len = e_len+5;
  if(bn_getBlock(e, e_len-1) >= 128)
    kex_dh_init_payload.len++;
  kex_dh_init_payload.arr = malloc(kex_dh_init_payload.len);
  kex_dh_init_payload.arr[0] = SSH_MSG_KEXDH_INIT;
  int_to_bytes((bn_getBlock(e, e_len-1)>=128) ? e_len+1 : e_len,
      kex_dh_init_payload.arr+1);
  int offset = 5;
  if(bn_getBlock(e, e_len-1)>=128) {
    kex_dh_init_payload.arr[5] = 0;
    offset++;
  }
  for(int i=0; i<e_len; i++) {
    kex_dh_init_payload.arr[i+offset] = bn_getBlock(e, e_len-i-1);
  }
  packet kex_dh_init_pak = build_packet(kex_dh_init_payload, c);
  free(kex_dh_init_payload.arr);
  send_packet(kex_dh_init_pak, c);
  free_pak(&kex_dh_init_pak);

  pthread_create(&tid, NULL, listener_thread, (void *)c);
  byte_array_t *kex_dh_reply_bytes;
  pthread_join(tid, (void **)&kex_dh_reply_bytes);
  packet kex_dh_reply_pak = bytes_to_packet(kex_dh_reply_bytes->arr,
      kex_dh_reply_bytes->len);
  free(kex_dh_reply_bytes->arr);
  free(kex_dh_reply_bytes);

  if(kex_dh_reply_pak.payload[0] == SSH_MSG_KEXDH_REPLY) {
    uint32_t len_K_S = bytes_to_int(kex_dh_reply_pak.payload+1);
    uint8_t *K_S = malloc(len_K_S);
    memcpy(K_S, kex_dh_reply_pak.payload+5,len_K_S);

    bignum *exponent, *n;
    bn_inits(2, &exponent, &n);
    uint32_t len_exp = bytes_to_int(K_S+11);
    uint32_t len_n = bytes_to_int(K_S+15+len_exp);
    mpint_to_bignum(K_S+15, len_exp, exponent);
    mpint_to_bignum(K_S+19+len_exp, len_n, n);

    uint32_t len_f = bytes_to_int(kex_dh_reply_pak.payload+5+len_K_S);
    uint8_t *f_bytes = malloc(len_f);
    memcpy(f_bytes, kex_dh_reply_pak.payload+9+len_K_S, len_f);
    bignum *f;
    bn_init(&f);
    mpint_to_bignum(f_bytes, len_f, f);
    free(f_bytes);
    bn_init(K);
    bn_powmod(f, x, p, *K);

    byte_array_t prehash;

    uint32_t hash_len = strlen(I_C) + 2 +
        strlen(I_S) + 2 +
        kex_init_c_pak.packet_length - kex_init_c_pak.padding_length + 3 +
        kex_init_s_pak.packet_length - kex_init_s_pak.padding_length + 3 +
        (len_K_S + 4) + (e_len + offset - 1) + (len_f + 4) +
        (((bn_getBlock(*K, bn_trueLength(*K) - 1)>=128) ? bn_trueLength(*K)+1 : bn_trueLength(*K)) + 4);

    prehash.len = hash_len;
    prehash.arr = malloc(hash_len);

    uint32_t hash_offset = 0;

    int_to_bytes(strlen(I_C)-2, prehash.arr);
    hash_offset+=4;
    memcpy(prehash.arr + hash_offset, I_C, strlen(I_C)-2);
    hash_offset+=strlen(I_C)-2;

    int_to_bytes(strlen(I_S)-2, prehash.arr+hash_offset);
    hash_offset+=4;
    memcpy(prehash.arr+hash_offset, I_S, strlen(I_S) - 2);
    hash_offset += strlen(I_S)-2;

    int_to_bytes(kex_init_c_pak.packet_length - kex_init_c_pak.padding_length - 1, prehash.arr+hash_offset);
    hash_offset += 4;
    memcpy(prehash.arr+hash_offset, kex_init_c_pak.payload, kex_init_c_pak.packet_length - kex_init_c_pak.padding_length - 1);
    hash_offset += kex_init_c_pak.packet_length - kex_init_c_pak.padding_length - 1;

    int_to_bytes(kex_init_s_pak.packet_length - kex_init_s_pak.padding_length - 1, prehash.arr+hash_offset);
    hash_offset += 4;
    memcpy(prehash.arr+hash_offset, kex_init_s_pak.payload, kex_init_s_pak.packet_length - kex_init_s_pak.padding_length - 1);
    hash_offset += kex_init_s_pak.packet_length - kex_init_s_pak.padding_length - 1;

    int_to_bytes(len_K_S, prehash.arr+hash_offset);
    hash_offset+=4;
    memcpy(prehash.arr+hash_offset, K_S, len_K_S);
    hash_offset+=len_K_S;

    bignum_to_mpint(e, prehash.arr+hash_offset);
    hash_offset += e_len+offset-1;

    bignum_to_mpint(f, prehash.arr+hash_offset);
    hash_offset += len_f + 4;

    bignum_to_mpint(*K, prehash.arr+hash_offset);
    hash_offset += (((bn_getBlock(*K, bn_trueLength(*K) - 1)>=128) ? bn_trueLength(*K)+1 : bn_trueLength(*K)) + 4);

    free_pak(&kex_init_c_pak);
    free_pak(&kex_init_s_pak);
    free(K_S);

    sha_256(prehash, exchange_hash);

    free(prehash.arr);

    byte_array_t signature_hash;
    sha_256(*exchange_hash, &signature_hash);

    //The final entry of the packet should be the signature
    uint32_t len_sig = bytes_to_int(kex_dh_reply_pak.payload+9+len_K_S+len_f);
    uint8_t *sig = malloc(len_sig);
    memcpy(sig, kex_dh_reply_pak.payload+13+len_K_S+len_f, len_sig);

    uint32_t label_len = bytes_to_int(sig);

    //Convert the signature to an int
    uint32_t S_len = bytes_to_int(sig+4+label_len);
    bignum *s, *em;
    bn_inits(2,&s,&em);
    mpint_to_bignum(sig+8+label_len, S_len, s);

    //Raise the signature to the power exponent, which is the public rsa
    //exponent of the server
    bn_powmod(s, exponent, n, em);
    //The final 32 bytes of this should be the same as the hash of the hash
    bn_littleblocks(em, 32, em);
    //TODO compare received hash sig and computed hash sig

    free(signature_hash.arr);
    bn_nukes(9, &e, &f, &x, &g, &p, &s, &exponent, &n, &em);

    free(sig);

    pthread_create(&tid, NULL, listener_thread, (void *)c);

    uint8_t new_keys_bytes[] = {SSH_MSG_NEWKEYS};
    byte_array_t new_keys = {1, new_keys_bytes};
    packet new_keys_pak = build_packet(new_keys, c);
    send_packet(new_keys_pak, c);
    free_pak(&new_keys_pak);

    byte_array_t *kex_new_keys_bytes;
    pthread_join(tid, (void **)&kex_new_keys_bytes);
    packet kex_new_keys_pak = bytes_to_packet(kex_new_keys_bytes->arr, kex_new_keys_bytes->len);
    for(int i=0; i<kex_new_keys_pak.packet_length - kex_new_keys_pak.padding_length - 1; i++) {
      printf("%"PRIu8" ", kex_new_keys_pak.payload[i]);
    }
    printf("\n");
    free_pak(&kex_new_keys_pak);
    free(kex_new_keys_bytes->arr);
    free(kex_new_keys_bytes);

    printf("kex completed\n\n");
  }

  free_pak(&kex_dh_reply_pak);
}
