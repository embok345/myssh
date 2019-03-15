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

  bignum *K;
  byte_array_t exchange_hash;

  start_connection(sock);

  printf("%s%s", I_C, I_S);

  connection con;
  con.socket = sock;
  con.encryption_block_size = 0;
  con.mac_block_size = 0;
  con.sequence_number = 0;

  kex_init(&con, &K, &exchange_hash);

  con.session_id = exchange_hash;
  con.encryption_block_size = 16;
  con.mac_block_size = 64;
  con.mac_output_size = 32;
  derive_keys(K, exchange_hash, &con);

  bn_nuke(&K);

  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  uint8_t *msg = "ssh-connection";
  byte_array_t service_request_message;
  service_request_message.len = strlen(msg) + 5;
  service_request_message.arr = malloc(service_request_message.len);
  service_request_message.arr[0] = SSH_MSG_SERVICE_REQUEST;
  int_to_bytes(strlen(msg), service_request_message.arr+1);
  memcpy(service_request_message.arr + 5, msg, strlen(msg));
  packet service_request_pak = build_packet(service_request_message, &con);
  send_packet(service_request_pak, &con);

  byte_array_t *user_auth_response_bytes;
  pthread_join(tid, (void **)&user_auth_response_bytes);

  printf("Received response: ");
  for(int i=0; i<user_auth_response_bytes->len; i++) {
    printf("%x ", user_auth_response_bytes->arr[i]);
  }
  byte_array_t decrypted_response;
  aes_ctr(*user_auth_response_bytes, con.key_s2c, &con.iv_s2c, &decrypted_response);
  printf("\ndecrypted response?: ");
  for(int i=0; i<decrypted_response.len; i++) {
    printf("%x ", decrypted_response.arr[i]);
  }
  printf("\n");


  free(exchange_hash.arr);

  free(I_C);
  free(I_S);
  return 0;
}

void derive_keys(const bignum *K, const byte_array_t H, connection *c) {

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

  sha_256(prehash, &(c->iv_c2s));
  c->iv_c2s.len = 16;

  (prehash.arr+offset+H.len)[0] = 66;
  sha_256(prehash, &(c->iv_s2c));
  c->iv_s2c.len = 16;

  (prehash.arr+offset+H.len)[0] = 67;
  sha_256(prehash, &(c->key_c2s));

  (prehash.arr+offset+H.len)[0] = 68;
  sha_256(prehash, &(c->key_s2c));

  (prehash.arr+offset+H.len)[0] = 69;//hmac requires 64 byte keys, this
  sha_256(prehash, &(c->mac_c2s)); //only gives 32 bytes. Should we pad with
                                   //0's, as in hmac spec, or do subsequent
                                   //hash's as in ssh spec?

  (prehash.arr+offset+H.len)[0] = 70;
  sha_256(prehash, &(c->mac_s2c));

}

void *listener_thread(void *arg) {
  uint8_t *output = malloc(35000);
  int sock = *((int *)arg);
  int len = recv(sock, output, 35000, 0);
  output = realloc(output, len);
  byte_array_t *arr = malloc(sizeof(byte_array_t));
  arr->len = len;
  arr->arr = output;
  return (void *)arr;
}

void start_connection(int sock) {
  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  int I_C_len = strlen(VERSION) + 11;
  I_C = malloc(I_C_len);
  snprintf(I_C, I_C_len, "SSH-2.0-%s\r\n", VERSION);
  send(sock, I_C, I_C_len - 1, 0);

  byte_array_t *identification_s_string;
  pthread_join(tid, (void **)&identification_s_string);
  while(identification_s_string->len < 4 ||
      memcmp(identification_s_string->arr, "SSH-", 3)!=0) {
    free(identification_s_string->arr);
    free(identification_s_string);
    pthread_create(&tid, NULL, listener_thread, (void *)&sock);
    pthread_join(tid, (void **)&identification_s_string);
  }

  //remote_constr now starts with "SSH-"
  if(identification_s_string->len<8 ||
      memcmp(identification_s_string->arr+4, "2.0-", 4)!=0) {
    printf("Invalid protocol\n");
    free(identification_s_string->arr);
    free(identification_s_string);
    return;
  }
  I_S = malloc(identification_s_string->len + 1);
  memcpy(I_S, identification_s_string->arr, identification_s_string->len);
  I_S[identification_s_string->len] = '\0';

  free(identification_s_string->arr);
  free(identification_s_string);
}

void kex_init(connection *c, bignum **K, byte_array_t *exchange_hash) {
  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&(c->socket));

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

  pthread_create(&tid, NULL, listener_thread, (void *)&(c->socket));
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

    uint8_t new_keys_bytes[] = {SSH_MSG_NEWKEYS};
    byte_array_t new_keys = {1, new_keys_bytes};
    packet new_keys_pak = build_packet(new_keys, c);
    send_packet(new_keys_pak, c);
    free_pak(&new_keys_pak);

    printf("kex completed\n\n");
  }

  free_pak(&kex_dh_reply_pak);
}

