#include "myssh.h"

uint8_t *V_C;
uint8_t *V_S;

void derive_keys(const bignum *, const byte_array_t, connection *);
void free_mac(mac_struct *);
void free_enc(enc_struct *);

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
  con.session_id = NULL;
  con.enc_c2s = NULL;
  con.enc_s2c = NULL;
  con.mac_c2s = NULL;
  con.mac_s2c = NULL;
  con.sequence_number = 0;

  packet_lock pak_lock;
  pak_lock.p = NULL;
  pthread_cond_t packet_handled = PTHREAD_COND_INITIALIZER;
  pthread_cond_t packet_present = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pak_lock.packet_handled = packet_handled;
  pak_lock.packet_present = packet_present;
  pak_lock.mutex = mutex;

  con.pak = pak_lock;

  if(start_connection(&con) == 1)
    return 1;

  printf("%s%s", V_C, V_S);

  pthread_t reader;
  pthread_create(&reader, NULL, reader_listener, (void *)&con);

  printf("Doing kex\n");

  if(kex_init(&con) == 1)
    return 1;

  printf("Done kex\n");

  printf("Doing auth\n");

  if(user_auth_publickey(&con, "locked", "rsa-sha2-256",
      "/home/poulter/.ssh/id_rsa2.pub",
      "/home/poulter/.ssh/id_rsa2") == 1)
    return 1;

  printf("Done auth\n");

  pthread_t global_requests;
  pthread_create(&global_requests, NULL, global_request_listener, (void *)&con);

  open_session(&con);

  pthread_join(reader, NULL);

  free(con.session_id->arr);
  free(con.session_id);
  free_enc(con.enc_c2s);
  free_enc(con.enc_s2c);
  free_mac(con.mac_c2s);
  free_mac(con.mac_s2c);

  free(V_C);
  free(V_S);
  return 0;
}

void free_enc(enc_struct *to_free) {
  free(to_free->key.arr);
  free(to_free->iv.arr);
  free(to_free);
}
void free_mac(mac_struct *to_free) {
  free(to_free->key.arr);
  free(to_free);
}

/* Starts the SSH connection by sending the version string to the
 * server, and making sure we get a valid response */
uint8_t start_connection(connection *c) {

  //Create and send the client version string
  int V_C_len = strlen(VERSION) + 11;
  V_C = malloc(V_C_len);
  snprintf(V_C, V_C_len, "SSH-2.0-%s\r\n", VERSION);
  send(c->socket, V_C, V_C_len - 1, 0);

  byte_array_t identification_s_string;
  //It's difficult to know exactly how long the server version string may be.
  //Hopefully 200 should be fine (really 7 should be sufficient,
  //as we just need "SSH-2.0" (though we need the whole thing for kex)).
  //TODO we could just read character by character
  identification_s_string.arr = malloc(200);
  identification_s_string.len = recv(c->socket, identification_s_string.arr, 200, 0);

  //The problem with this is we may keep trying to read
  //without a valid response, but the spec allows for initial
  //messages which are not the version string
  while(identification_s_string.len < 4 ||
      memcmp(identification_s_string.arr, "SSH-", 3)!=0) {
    identification_s_string.len = recv(c->socket, identification_s_string.arr, 200, 0);
  }

  //The string now starts with "SSH-"
  if(identification_s_string.len<8 ||
      memcmp(identification_s_string.arr+4, "2.0-", 4)!=0) {
    printf("Invalid protocol\n");
    free(identification_s_string.arr);
    return 1;
  }
  //TODO we should check that the string ends with "\r\n"

  V_S = malloc(identification_s_string.len + 1);
  memcpy(V_S, identification_s_string.arr, identification_s_string.len);
  V_S[identification_s_string.len] = '\0';

  free(identification_s_string.arr);

  return 0;
}

void copy_bytes(const uint8_t *in, uint32_t length, byte_array_t *out) {
  out->len = length;
  out->arr = malloc(length);
  memcpy(out->arr, in, length);
}

uint8_t byteArray_contains(const byte_array_t arr, uint8_t to_find) {
  for(int i=0; i<arr.len; i++) {
    if(arr.arr[i] == to_find)
      return 1;
  }
  return 0;
}

packet wait_for_packet(connection *c, int no_codes, ...) {
  packet received_packet;
  byte_array_t codes;
  codes.len = no_codes;
  codes.arr = malloc(no_codes);
  va_list valist;
  va_start(valist, no_codes);
  for(int i=0; i<no_codes; i++)
    codes.arr[i] = va_arg(valist, int);
  while(1) {
    //Acquire the lock, and check if there is a packet present
    pthread_mutex_lock(&(c->pak.mutex));
    while(!(c->pak.p)) {
      //Wait until a packet arrives
      pthread_cond_wait(&(c->pak.packet_present), &(c->pak.mutex));
    }
    //We now own the lock, and a packet is present
    if(c->pak.p->payload.len < 1 ||
        !byteArray_contains(codes, c->pak.p->payload.arr[0])) {
      //If we can't get a code, or the code is not the one we
      //want, wait till this packet is handled
      pthread_cond_wait(&(c->pak.packet_handled), &(c->pak.mutex));
      pthread_mutex_unlock(&(c->pak.mutex));
    } else {
      //If we have the message we want, copy it out
      received_packet = clone_pak(*(c->pak.p));
      free_pak(c->pak.p);
      c->pak.p = NULL;
      //Let the listener know we're done with the packet
      pthread_cond_broadcast(&(c->pak.packet_handled));
      pthread_mutex_unlock(&(c->pak.mutex));
      return received_packet;
    }
  }
}

uint8_t kex_init(connection *c) {
  //Send the kex init packet
  packet kex_init_c = build_kex_init(c);
  send_packet(kex_init_c, c);

  //Receive the kex init packet
  packet kex_init_s = wait_for_packet(c, 1, SSH_MSG_KEXINIT);

  /* Determine which algorithms will be used */
  uint32_t list_offset = 17;
  //Get the algorithms to use. These are the first client choice
  //which also occurs as a server choice.
  //TODO really we should pass the algo list which we sent as well.
  char **chosen_algos = get_chosen_algos(kex_init_s.payload.arr, &list_offset);
  if(!chosen_algos) {
    printf("Could not determine algorithms to use\n");
    return 1; //TODO return an error code
  }

  /*Set the functions hash functions to be used in key exchange */
  void (*kex_hash_fun)(const byte_array_t, byte_array_t *);
  void (*key_hash_fun)(const byte_array_t, byte_array_t *);
  uint32_t kex_hash_output_len;

  if(strcmp(chosen_algos[0], KEX_DH_GP14_SHA256) == 0) {
    kex_hash_fun = sha_256;
    kex_hash_output_len = 32;
  } else {
    //This of course should never be reached
    printf("KEX algorithm unsupported: %s\n", chosen_algos[0]);
    return 1;//TODO error code
  }
  if(strcmp(chosen_algos[1], KEY_RSA_SHA2_256) == 0)
    key_hash_fun = sha_256;
  else {
    //never reached
    printf("Public key algorithm unsupported: %s\n", chosen_algos[1]);
    return 1;//TODO error code
  }


  /* Set the encryption algorithms */
  enc_struct *new_enc_c2s, *new_enc_s2c;
  new_enc_c2s = malloc(sizeof(enc_struct));
  new_enc_s2c = malloc(sizeof(enc_struct));

  if(strcmp(chosen_algos[2], ENC_AES256_CTR) == 0) {
    new_enc_c2s->enc = aes_ctr;
    new_enc_c2s->dec = aes_ctr;
    new_enc_c2s->block_size = 16;
    new_enc_c2s->key_size = 32;
  } else if(strcmp(chosen_algos[2], ENC_AES192_CTR) == 0) {
    new_enc_c2s->enc = aes_ctr;
    new_enc_c2s->dec = aes_ctr;
    new_enc_c2s->block_size = 16;
    new_enc_c2s->key_size = 24;
  } else if(strcmp(chosen_algos[2], ENC_AES128_CTR) == 0) {
    new_enc_c2s->enc = aes_ctr;
    new_enc_c2s->dec = aes_ctr;
    new_enc_c2s->block_size = 16;
    new_enc_c2s->key_size = 16;
  } else {
    //never reached
    printf("Encryption algorithm not supported: %s\n", chosen_algos[2]);
    return 1;//TODO error code
  }

  if(strcmp(chosen_algos[3], ENC_AES256_CTR) == 0) {
    new_enc_s2c->enc = aes_ctr;
    new_enc_s2c->dec = aes_ctr;
    new_enc_s2c->block_size = 16;
    new_enc_s2c->key_size = 32;
  } else if(strcmp(chosen_algos[3], ENC_AES192_CTR) == 0) {
    new_enc_s2c->enc = aes_ctr;
    new_enc_s2c->dec = aes_ctr;
    new_enc_s2c->block_size = 16;
    new_enc_s2c->key_size = 24;
  } else if(strcmp(chosen_algos[3], ENC_AES128_CTR) == 0) {
    new_enc_s2c->enc = aes_ctr;
    new_enc_s2c->dec = aes_ctr;
    new_enc_s2c->block_size = 16;
    new_enc_s2c->key_size = 16;
  } else {
    //never reached
    printf("Encryption algorithm not supported: %s\n", chosen_algos[3]);
    return 1; //TODO error code
  }

  /* Set the mac algorithms */
  mac_struct *new_mac_c2s, *new_mac_s2c;
  new_mac_c2s = malloc(sizeof(mac_struct));
  new_mac_s2c = malloc(sizeof(mac_struct));

  if(strcmp(chosen_algos[4], MAC_HMAC_SHA256) == 0) {
    new_mac_c2s->hash = sha_256;
    new_mac_c2s->mac = hmac;
    new_mac_c2s->hash_block_size = 64;
    new_mac_c2s->mac_output_size = 32;
  } else {
    //never reached
    printf("MAC algorithm not supported: %s\n", chosen_algos[4]);
    return 1;//TODO error code
  }

  if(strcmp(chosen_algos[5], MAC_HMAC_SHA256) == 0) {
    new_mac_s2c->hash = sha_256;
    new_mac_s2c->mac = hmac;
    new_mac_s2c->hash_block_size = 64;
    new_mac_s2c->mac_output_size = 32;
  } else {
    //never reached
    printf("MAC algorithm not supported: %s\n", chosen_algos[5]);
    return 1;//TODO error code
  }

  //Compression must be none
  if(strcmp(chosen_algos[6], NONE) != 0 || strcmp(chosen_algos[7], NONE) != 0) {
    printf("Compression algorithm not supported: %s\n", chosen_algos[6]);
    return 1;
  }

  //Do the key exchange
  byte_array_t host_key, signature;
  bn_t e, f, K;
  kex_dh_14_rsa(c, &host_key, &e, &f, &K, &signature);
  //TODO obviously this would be different if using different algos.

  /*Compute the exchange hash, as in rfc4253§8*/
  byte_array_t vc, vs, ic, is, e_b, f_b, K_b;
  vc.len = strlen(V_C)-2;
  vs.len = strlen(V_S)-2;
  vc.arr = V_C;
  vs.arr = V_S;
  ic = kex_init_c.payload;
  is = kex_init_s.payload;
  bignum_to_byteArray(e, &e_b);
  bignum_to_byteArray(f, &f_b);
  bignum_to_byteArray(K, &K_b);
  //TODO the things going in to the hash may be different too.

  byte_array_t *exchange_hash = malloc(sizeof(byte_array_t));

  compute_exchange_hash(kex_hash_fun, exchange_hash, 8, vc, vs, ic, is,
      host_key, e_b, f_b, K_b);

  free(host_key.arr);
  free(e_b.arr);
  free(f_b.arr);
  free(K_b.arr);

  /*Compute the signature, and make sure it is the same as the one
   *received from the server */
  byte_array_t computed_signature;
  key_hash_fun(*exchange_hash, &computed_signature);
  for(int i=0; i<computed_signature.len; i++) {
    if(computed_signature.arr[i] !=
        signature.arr[signature.len-computed_signature.len+i])
      return 1;
  }
  //TODO we shouldn't do it in this way, we should encode the computed
  //signature properly with ASN.1, then check they are the same (I think
  //it says that somewhere in the specs)

  free(computed_signature.arr);
  free(signature.arr);
  for(int i=0; i<8; i++) {
    free(chosen_algos[i]);
  }
  free(chosen_algos);
  free_pak(&kex_init_c);
  free_pak(&kex_init_s);
  //free(kex_init_s);

  /* Compute the keys, and ivs as in rfc4253§7.2, namely as
   * HASH(K||exchange_hash||char||c->session_id), where char
   * ranges from 'A' to 'F', and K is encoded as mpint, the
   * rest as bytes */
  byte_array_t prehash = {0, NULL};
  bignum_into_mpint(K, &prehash);
  prehash.len += exchange_hash->len;
  prehash.arr = realloc(prehash.arr, prehash.len);
  memcpy(prehash.arr + prehash.len - exchange_hash->len, exchange_hash->arr,
      exchange_hash->len);
  uint32_t character_pos = prehash.len;
  prehash.len+=1;
  //If we don't have a session_id, use the exchange_hash, as it
  //will become the session_id
  if(!c->session_id) {
    prehash.len += exchange_hash->len;
    prehash.arr = realloc(prehash.arr, prehash.len);
    memcpy(prehash.arr + prehash.len - exchange_hash->len, exchange_hash->arr,
        exchange_hash->len);
  } else {
    prehash.len += c->session_id->len;
    prehash.arr = realloc(prehash.arr, prehash.len);
    memcpy(prehash.arr + prehash.len - c->session_id->len, c->session_id->arr,
        c->session_id->len);
  }

  prehash.arr[character_pos] = 'A';
  kex_hash_fun(prehash, &(new_enc_c2s->iv));
  //Resize the output of the hash to the correct size.
  if(new_enc_c2s->block_size > kex_hash_output_len) {
    //TODO enlarge the iv if the hash is too short
  } else {
    new_enc_c2s->iv.len = new_enc_c2s->block_size;
  }

  prehash.arr[character_pos] = 'B';
  kex_hash_fun(prehash, &(new_enc_s2c->iv));
  if(new_enc_s2c->block_size > kex_hash_output_len) {
    //TODO --"--
  } else {
    new_enc_s2c->iv.len = new_enc_s2c->block_size;
  }

  prehash.arr[character_pos] = 'C';
  kex_hash_fun(prehash, &(new_enc_c2s->key));
  if(new_enc_c2s->block_size > kex_hash_output_len) {
    //TODO --"--
  } else {
    new_enc_c2s->key.len = new_enc_c2s->key_size;
  }

  prehash.arr[character_pos] = 'D';
  kex_hash_fun(prehash, &(new_enc_s2c->key));
  if(new_enc_s2c->block_size > kex_hash_output_len) {
    //TODO --"--
  } else {
    new_enc_s2c->key.len = new_enc_s2c->key_size;
  }

  prehash.arr[character_pos] = 'E';
  kex_hash_fun(prehash, &(new_mac_c2s->key));
  prehash.arr[character_pos] = 'F';
  kex_hash_fun(prehash, &(new_mac_s2c->key));
  //TODO maybe we want to change the length of the mac keys?

  /* Send the NEWKEYS message */
  uint8_t new_keys_bytes[] = {SSH_MSG_NEWKEYS};
  byte_array_t new_keys = {1, new_keys_bytes};
  packet new_keys_pak = build_packet(new_keys, c);
  send_packet(new_keys_pak, c);
  free_pak(&new_keys_pak);

  //Wait to receive the new keys packet
  //We can't just call wait_for_packet, as we need to retain the mutex
  //in order to change the keys
  packet *new_keys_pak_s = NULL;
  while(!new_keys_pak_s) {
    pthread_mutex_lock(&(c->pak.mutex));
    while(!(c->pak.p)) {
      pthread_cond_wait(&(c->pak.packet_present), &(c->pak.mutex));
    }
    //We now own the lock, and a packet is present
    if(c->pak.p->payload.arr[0] == SSH_MSG_NEWKEYS) {
      //If we have the message we want, copy it out
      new_keys_pak_s = malloc(sizeof(packet));
      copy_pak(c->pak.p, new_keys_pak_s);
      free_pak(c->pak.p);
      c->pak.p = NULL;
      break;
    } else {
      //Otherwise, wait for the next packet to arrive
      pthread_cond_wait(&(c->pak.packet_handled), &(c->pak.mutex));
    }
  }

  //Set the new keys to be used
  if(!c->session_id)
    c->session_id = exchange_hash;
  if(c->enc_c2s)
    free_enc(c->enc_c2s);
  c->enc_c2s = new_enc_c2s;
  if(c->enc_s2c)
    free_enc(c->enc_s2c);
  c->enc_s2c = new_enc_s2c;
  if(c->mac_c2s)
    free_mac(c->mac_c2s);
  c->mac_c2s = new_mac_c2s;
  if(c->mac_s2c)
    free_mac(c->mac_s2c);
  c->mac_s2c = new_mac_s2c;

  pthread_cond_broadcast(&(c->pak.packet_handled));
  pthread_mutex_unlock(&(c->pak.mutex));

  bn_nukes(3, &e, &f, &K);
  free(prehash.arr);
  return 0;
}
