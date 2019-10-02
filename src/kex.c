#include "myssh.h"

/* Computes the hash of no_objects different byte_array_t's,
 * using the provided hash function, and stores the output
 * in out */
void compute_exchange_hash(void (*hash)(const byte_array_t, byte_array_t *),
                           byte_array_t *out,
                           int no_objects, ...) {

  va_list valist;
  va_start(valist, no_objects);

  byte_array_t prehash = create_byteArray(0);

  /* Go through each of the byte_arrays, and append it to the
   * previous ones. */
  for(int i=0; i<no_objects; i++) {
    byte_array_t obj = va_arg(valist, byte_array_t);
    byteArray_append_len_byteArray(prehash, obj);
  }

  //print_byteArray_hex(prehash);

  hash(prehash, out);

  //print_byteArray_hex(*out);

  free_byteArray(prehash);
  va_end(valist);
}

/* Performs the Diffie-Hellman key exchange using group 14 from
 * rfc3526§3. We compute 2^x mod p, where p is the prime defining
 * group 14, and x is a random number of our choice. Send it to the
 * server, which sends back its rsa public key, 2^y mod p, and
 * the signature of the exchange hash */
uint8_t kex_dh_14_rsa(connection *c,
    byte_array_t *K_S,  //The public key of the server, encoded as per
                        //rfc4253§6.6
    bn_t *e,            //=2^x mod p, where x is a random number known to us,
                        //and p is the prime of group 14
    bn_t *f,            //=2^y mod p, where y is a random number unknown to us.
    bn_t *K,            //=2^xy=e^y=f^x mod p, the shared secret
    byte_array_t *signature) { //The signature of the exchange hash

  /* Set up the numbers we need */
  bn_t p, g, x;
  if(!bn_inits(4, &p, &g, &x, e)) return 1;
  if(!bn_resize( p, 256 )) return 1;
  for( uint32_t i = 0; i < 256; i++) {
      bn_setBlock( p, i, DH_14_BLOCKS[i]);
  }
  bn_conv_ui2bn(2, g);
  bn_conv_ui2bn(10000+(rand()%10000), x);
  //TODO this is bad, but the code is too slow if a larger
  //exponent is chosen
  //Compute 2^x mod p
  bn_powmod(g, x, p, *e);

  /* Create the kexdh_init packet, which contains e */
  byte_array_t kex_dh_init_payload = create_byteArray(0);
  byteArray_append_byte(kex_dh_init_payload, SSH_MSG_KEXDH_INIT);
  byteArray_append_len_bignum(kex_dh_init_payload, *e);
  packet kex_dh_init_pak = build_packet(kex_dh_init_payload, c);
  send_packet(kex_dh_init_pak, c);
  free_pak(kex_dh_init_pak);
  free_byteArray(kex_dh_init_payload);

  packet kex_dh_reply = wait_for_packet(c, 1, SSH_MSG_KEXDH_REPLY);

  /* Retrieve the public key, f, and the signature */
  //TODO we should really check that we can access all of these things

  //The first object should be the public key
  uint32_t len_K_S = byteArray_to_int(kex_dh_reply.payload, 1);
  *K_S = sub_byteArray(kex_dh_reply.payload, 5, len_K_S);

  //The modulus (n) and exponent are encoded in the public key
  //as mpints, so put them into bignums
  bn_t exponent, n;
  if(!bn_inits(2, &exponent, &n)) return 1;
  //TODO it would be nice if we could do these in one step
  byte_array_t exponent_bytes = sub_byteArray(*K_S, 15,
      byteArray_to_int(*K_S, 11));
  byte_array_t n_bytes = sub_byteArray(*K_S, 19 + get_byteArray_len(exponent_bytes),
      byteArray_to_int(*K_S, 15+get_byteArray_len(exponent_bytes)));
  byteArray_to_bignum(exponent_bytes, exponent);
  byteArray_to_bignum(n_bytes, n);

  //bn_prnt_dec(exponent);
  //bn_prnt_dec(n);

  free_byteArray(exponent_bytes);
  free_byteArray(n_bytes);

  //The second object should be f = 2^y mod p
  uint32_t len_f = byteArray_to_int(kex_dh_reply.payload,
      5 + len_K_S);
  if(!bn_init(f)) return 1;
  byte_array_t f_bytes = sub_byteArray(kex_dh_reply.payload, 9 + len_K_S, len_f);
  byteArray_to_bignum(f_bytes, *f);
  free_byteArray(f_bytes);
  //bn_prnt_dec(*f);

  //Now we have f, we can compute K = f^x mod p
  if(!bn_init(K)) return 1;
  bn_powmod(*f, x, p, *K);

  //The final entry of the packet should be the signature
  uint32_t len_sig = byteArray_to_int(kex_dh_reply.payload,
      9 + len_f + len_K_S);
  byte_array_t sig = sub_byteArray(kex_dh_reply.payload,
      13+len_K_S+len_f, len_sig);
  uint32_t label_len = byteArray_to_int(sig, 0);
  //TODO we should really check the name is as expected

  //Convert the signature to an int
  bn_t s, em;
  if(!bn_inits(2,&s,&em)) return 1;
  uint32_t s_len = byteArray_to_int(sig, 4+label_len);
  byte_array_t s_bytes = sub_byteArray(sig, 8+label_len, s_len);
  byteArray_to_bignum(s_bytes, s);
  free_byteArray(s_bytes);

  //Raise the signature to the power exponent, which is the public rsa
  //exponent of the server
  bn_powmod(s, exponent, n, em);
  //then convert it back to a byte_array
  *signature = create_byteArray(0);
  bignum_to_byteArray_u(em, *signature);

  bn_deinits(7, &em, &s, &exponent, &n, &p, &g, &x);
  free_byteArray(sig);
  free_pak(kex_dh_reply);

  return 0;
}

/* Gets the algorithms to use for kex etc, based on the byte array
 * arr which should be the kex_init payload received from the server.
 * It picks out each name list, then sends that to get_chosen_algo
 * with the client algos for that algo type. Returns the list of
 * chosen algos, or NULL if an algo can't be chosen */
//TODO we should really change this to use a byte_array_t, and
//probably return the offset, and have the chosen algos as
//an argument
char **get_chosen_algos(const byte_array_t arr, uint32_t list_offset) {

  //There are 8 algorithm categories to chose in
  char **ret = malloc(8*sizeof(char *));

  //The first is kex
  //We get the length of the first name list
  //uint32_t name_list_len = bytes_to_int(arr + *list_offset);
  uint32_t name_list_len = byteArray_to_int(arr, list_offset);
  //Pass it off to compare with the client kex algos
  //ret[0] = get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, KEX_C_ALGOS, NO_KEX_C_ALGOS);
  byte_array_t name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  ret[0] = get_chosen_algo(name_list_bytes, KEX_C_ALGOS, NO_KEX_C_ALGOS);
  //If that returned null, a match wasn't found, so we can't continue
  if(!ret[0]) return NULL;
  //Move the list onwards
  list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  //the next is public key algos
  name_list_len = byteArray_to_int(arr, list_offset);
  name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  //ret[1] = get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, KEY_C_ALGOS, NO_KEY_C_ALGOS);
  ret[1] = get_chosen_algo(name_list_bytes, KEY_C_ALGOS, NO_KEY_C_ALGOS);
  if(!ret[1]) return NULL;
  list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  //client to server encryption algorithms
  name_list_len = byteArray_to_int(arr, list_offset);
  name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  //ret[2] = get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, ENC_ALGOS, NO_ENC_ALGOS);
  ret[2] = get_chosen_algo(name_list_bytes, ENC_ALGOS, NO_ENC_ALGOS);
  if(!ret[2]) return NULL;
  list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  //server to client encryption algorithms
  name_list_len = byteArray_to_int(arr, list_offset);
  name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  //ret[3] = get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, ENC_ALGOS, NO_ENC_ALGOS);
  ret[3] = get_chosen_algo(name_list_bytes, ENC_ALGOS, NO_ENC_ALGOS);
  if(!ret[3]) return NULL;
  list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  //client to server mac algorithms
  name_list_len = byteArray_to_int(arr, list_offset);
  name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  //ret[4] = get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, MAC_ALGOS, NO_MAC_ALGOS);
  ret[4] = get_chosen_algo(name_list_bytes, MAC_ALGOS, NO_MAC_ALGOS);
  if(!ret[4]) return NULL;
  list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  //server to client mac algorithms
  name_list_len = byteArray_to_int(arr, list_offset);
  name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  //ret[5] = get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, MAC_ALGOS, NO_MAC_ALGOS);
  ret[5] = get_chosen_algo(name_list_bytes, MAC_ALGOS, NO_MAC_ALGOS);
  if(!ret[5]) return NULL;
  list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  //client to server compression algorithms
  name_list_len = byteArray_to_int(arr, list_offset);
  name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  //ret[6]= get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, COM_ALGOS, NO_COM_ALGOS);
  ret[6] = get_chosen_algo(name_list_bytes, COM_ALGOS, NO_COM_ALGOS);
  if(!ret[6]) return NULL;
  list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  //server to client compression algorithms
  name_list_len = byteArray_to_int(arr, list_offset);
  name_list_bytes = sub_byteArray(arr, list_offset + 4, name_list_len);
  //ret[7] = get_chosen_algo(arr + *list_offset + 4,
  //    name_list_len, COM_ALGOS, NO_COM_ALGOS);
  ret[7] = get_chosen_algo(name_list_bytes, COM_ALGOS, NO_COM_ALGOS);
  if(!ret[7]) return NULL;
  // *list_offset+=name_list_len + 4;
  free_byteArray(name_list_bytes);

  return ret;
}

/* Get the chosen algo from the server list of algos, arr, and the client
 * list of algos, allowable_algos. It picks out the first algo which is on
 * client list which is also on the server list. If there are none in
 * common, return NULL. */
//TODO note that the kex algorithm is chosen in a slightly different way
char *get_chosen_algo(byte_array_t arr,
                      const char **allowable_algos,
                      uint32_t no_allowable_algos) {

  //If either of the lists is empty, there is no hope of finding a match
  if(get_byteArray_len(arr) == 0 || no_allowable_algos == 0) return NULL;

  /* Split up the server name list into its separate names */
  //As the length is non-zero, there is at least one algo
  uint32_t no_s_algos = 1;
  //The first name starts on the 0th character
  uint32_t word_start = 0;
  char **s_algos = malloc(no_s_algos*sizeof(char*));
  uint32_t len = get_byteArray_len(arr);
  for(int i=0; i<len; i++) {
    //If the current character is ',', we have reached the end of
    //the name, so copy the previous name.
    //if(arr[i] == ',') {
    if(get_byteArray_element(arr, i) == ',') {
      s_algos[no_s_algos-1] = malloc(i-word_start+1);
      //memcpy(s_algos[no_s_algos-1], arr+word_start, i-word_start);
      //s_algos[no_s_algos-1][i-word_start] = '\0';
      byteArray_strncpy(s_algos[no_s_algos-1], arr, word_start, i-word_start);
      //The next name starts on the next character
      word_start = i+1;
      //We have at least one more name
      s_algos = realloc(s_algos, (++no_s_algos)*sizeof(char*));
    }
  }
  //Once we reach the end, there is one final name
  s_algos[no_s_algos-1] = malloc(len-word_start+1);
  //memcpy(s_algos[no_s_algos-1], arr+word_start, len-word_start);
  //s_algos[no_s_algos-1][len - word_start] = '\0';
  byteArray_strncpy(s_algos[no_s_algos-1], arr, word_start, len-word_start);

  /* Search to find a match */
  char *chosen_algo = NULL;

  for(int i=0; i<no_allowable_algos; i++) {
    for(int j=0; j<no_s_algos; j++) {
      if(strcmp(allowable_algos[i], s_algos[j]) == 0) {
        //If the current names are the same, we have found our match
        chosen_algo = malloc(strlen(allowable_algos[i])+1);
        strcpy(chosen_algo, allowable_algos[i]);
        break;
      }
    }
    //If we have found a match, we needn't continue
    if(chosen_algo) break;
  }

  /* Clean up */
  for(int i=0; i<no_s_algos; i++) {
    free(s_algos[i]);
  }
  free(s_algos);

  return chosen_algo;
}


uint8_t kex(connection *c, const char *v_c, const char *v_s) {
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
  //char **chosen_algos = get_chosen_algos(kex_init_s.payload.arr, &list_offset);
  char **chosen_algos = get_chosen_algos(kex_init_s.payload, list_offset);
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

  //print_byteArray_hex(signature);

  /*Compute the exchange hash, as in rfc4253§8*/
  byte_array_t vc, vs, ic, is, e_b, f_b, K_b;
  vc = set_byteArray(strlen(v_c)-2, v_c);
  vs = set_byteArray(strlen(v_s)-2, v_s);
  ic = kex_init_c.payload;
  is = kex_init_s.payload;
  e_b = create_byteArray(0);
  f_b = create_byteArray(0);
  K_b = create_byteArray(0);
  bignum_to_byteArray(e, e_b);
  bignum_to_byteArray(f, f_b);
  bignum_to_byteArray(K, K_b);
  //TODO the things going in to the hash may be different too.

  byte_array_t exchange_hash;
  compute_exchange_hash(kex_hash_fun, &exchange_hash, 8, vc, vs, ic, is,
      host_key, e_b, f_b, K_b);

  free_byteArray(vc);
  free_byteArray(vs);
  free_byteArray(host_key);
  free_byteArray(e_b);
  free_byteArray(f_b);
  free_byteArray(K_b);

  /*Compute the signature, and make sure it is the same as the one
   *received from the server */
  byte_array_t computed_signature;
  key_hash_fun(exchange_hash, &computed_signature);
  byte_array_t sig_tail = tail_byteArray(signature,
      get_byteArray_len(signature) - get_byteArray_len(computed_signature));
  if(!byteArray_equals(sig_tail, computed_signature)) {
    printf("Signatures don't match\n");
    return 1;
  }
  //TODO we shouldn't do it in this way, we should encode the computed
  //signature properly with ASN.1, then check they are the same (I think
  //it says that somewhere in the specs)

  free_byteArray(computed_signature);
  free_byteArray(sig_tail);
  free_byteArray(signature);
  for(int i=0; i<8; i++) {
    free(chosen_algos[i]);
  }
  free(chosen_algos);
  free_pak(kex_init_c);
  free_pak(kex_init_s);

  /* Compute the keys, and ivs as in rfc4253§7.2, namely as
   * HASH(K||exchange_hash||char||c->session_id), where char
   * ranges from 'A' to 'F', and K is encoded as mpint, the
   * rest as bytes */
  byte_array_t prehash = create_byteArray(0);
  byteArray_append_len_bignum(prehash, K);
  byteArray_append_byteArray(prehash, exchange_hash);
  uint32_t character_pos = get_byteArray_len(prehash);
  byteArray_append_byte(prehash, 'A');
  //If we don't have a session_id, use the exchange_hash, as it
  //will become the session_id
  if(!c->session_id) {
    byteArray_append_byteArray(prehash, exchange_hash);
  } else {
    byteArray_append_byteArray(prehash, c->session_id);
  }

  kex_hash_fun(prehash, &(new_enc_c2s->iv));
  //Resize the output of the hash to the correct size.
  if(new_enc_c2s->block_size > kex_hash_output_len) {
    //TODO enlarge the iv if the hash is too short
  } else {
    resize_byteArray(new_enc_c2s->iv, new_enc_c2s->block_size);
  }

  //prehash.arr[character_pos] = 'B';
  set_byteArray_element(prehash, character_pos, 'B');
  kex_hash_fun(prehash, &(new_enc_s2c->iv));
  if(new_enc_s2c->block_size > kex_hash_output_len) {
    //TODO --"--
  } else {
    resize_byteArray(new_enc_s2c->iv, new_enc_s2c->block_size);
  }

  set_byteArray_element(prehash, character_pos, 'C');
  kex_hash_fun(prehash, &(new_enc_c2s->key));
  if(new_enc_c2s->block_size > kex_hash_output_len) {
    //TODO --"--
  } else {
    resize_byteArray(new_enc_c2s->key, new_enc_c2s->key_size);
  }

  set_byteArray_element(prehash, character_pos, 'D');
  kex_hash_fun(prehash, &(new_enc_s2c->key));
  if(new_enc_s2c->block_size > kex_hash_output_len) {
    //TODO --"--
  } else {
    resize_byteArray(new_enc_s2c->key, new_enc_s2c->key_size);
  }

  set_byteArray_element(prehash, character_pos, 'E');
  kex_hash_fun(prehash, &(new_mac_c2s->key));
  set_byteArray_element(prehash, character_pos, 'F');
  kex_hash_fun(prehash, &(new_mac_s2c->key));
  //TODO maybe we want to change the length of the mac keys?

  /* Send the NEWKEYS message */
  uint8_t new_keys_bytes[] = {SSH_MSG_NEWKEYS};
  byte_array_t new_keys = set_byteArray(1, new_keys_bytes);
  packet new_keys_pak = build_packet(new_keys, c);
  send_packet(new_keys_pak, c);
  free_pak(new_keys_pak);
  free_byteArray(new_keys);

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
    if(get_byteArray_element(c->pak.p->payload,0) == SSH_MSG_NEWKEYS) {
      //If we get the new keys packet, break out
      free_pak(*(c->pak.p));
      free(c->pak.p);
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

  //Notify that the packet has been dealt with
  pthread_cond_broadcast(&(c->pak.packet_handled));
  pthread_mutex_unlock(&(c->pak.mutex));

  bn_deinits(3, &e, &f, &K);
  free_byteArray(prehash);
  return 0;
}
