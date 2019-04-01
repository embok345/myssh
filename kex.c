#include "myssh.h"

/* Computes the hash of no_objects different byte_array_t's,
 * using the provided hash function, and stores the output
 * in out */
void compute_exchange_hash(void (*hash)(const byte_array_t, byte_array_t *),
                           byte_array_t *out,
                           int no_objects, ...) {

  va_list valist;
  va_start(valist, no_objects);

  byte_array_t prehash = {0, NULL};

  /* Go through each of the byte_arrays, and append it to the
   * previous ones. */
  for(int i=0; i<no_objects; i++) {
    byte_array_t obj = va_arg(valist, byte_array_t);
    byteArray_into_byteArray(obj, &prehash);
  }

  hash(prehash, out);
  free(prehash.arr);
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

  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)c);

  /* Set up the numbers we need */
  bn_t p, g, x;
  bn_inits(4, &p, &g, &x, e);
  bn_set(p, 256, DH_14_BLOCKS, 1);
  bn_conv_int2bn(2, g);
  bn_conv_int2bn(10000+(rand()%10000), x);
  //TODO this is bad, but the code is too slow if a larger
  //exponent is chosen
  //Compute 2^x mod p
  bn_powmod(g, x, p, *e);

  /* Create the kexdh_init packet, which contains e */
  byte_array_t kex_dh_init_payload;
  kex_dh_init_payload.len = 1;
  kex_dh_init_payload.arr = malloc(1);
  kex_dh_init_payload.arr[0] = SSH_MSG_KEXDH_INIT;
  bignum_into_mpint(*e, &kex_dh_init_payload);
  packet kex_dh_init_pak = build_packet(kex_dh_init_payload, c);
  free(kex_dh_init_payload.arr);
  send_packet(kex_dh_init_pak, c);
  free_pak(&kex_dh_init_pak);

  packet *kex_dh_reply;
  pthread_join(tid, (void **)&kex_dh_reply);
  if(kex_dh_reply->payload.arr[0] != SSH_MSG_KEXDH_REPLY) {
    return 1;//TODO error code
  }

  /* Retrieve the public key, f, and the signature */
  //TODO we should really check that we can access all of these things

  //The first object should be the public key
  K_S->len = bytes_to_int(kex_dh_reply->payload.arr + 1);
  K_S->arr = malloc(K_S->len);
  memcpy(K_S->arr, kex_dh_reply->payload.arr+5,K_S->len);

  //The modulus (n) and exponent are encoded in the public key
  //as mpints, so put them into bignums
  bn_t exponent, n;
  bn_inits(2, &exponent, &n);
  //TODO it would be nice if we could do these in one step
  uint32_t len_exp = bytes_to_int(K_S->arr+11);
  uint32_t len_n = bytes_to_int(K_S->arr+15+len_exp);
  mpint_to_bignum(K_S->arr+15, len_exp, exponent);
  mpint_to_bignum(K_S->arr+19+len_exp, len_n, n);

  //The second object should be f = 2^y mod p
  uint32_t len_f = bytes_to_int(kex_dh_reply->payload.arr+5+K_S->len);
  bn_init(f);
  mpint_to_bignum(kex_dh_reply->payload.arr + 9 + K_S->len, len_f, *f);

  //Now we have f, we can compute K = f^x mod p
  bn_init(K);
  bn_powmod(*f, x, p, *K);

  //The final entry of the packet should be the signature
  uint32_t len_sig = bytes_to_int(kex_dh_reply->payload.arr+9+K_S->len+len_f);
  uint8_t *sig = malloc(len_sig);
  memcpy(sig, kex_dh_reply->payload.arr+13+K_S->len+len_f, len_sig);
  uint32_t label_len = bytes_to_int(sig);
  //TODO we should really check the name is as expected

  //Convert the signature to an int
  uint32_t S_len = bytes_to_int(sig+4+label_len);
  bn_t s, em;
  bn_inits(2,&s,&em);
  mpint_to_bignum(sig+8+label_len, S_len, s);

  //Raise the signature to the power exponent, which is the public rsa
  //exponent of the server
  bn_powmod(s, exponent, n, em);
  //then convert it back to a byte_array
  signature->len = 0;
  signature->arr = NULL;
  bignum_to_byteArray_u(em, signature);

  bn_nukes(7, &em, &s, &exponent, &n, &p, &g, &x);
  free(sig);
  free_pak(kex_dh_reply);
  free(kex_dh_reply);
}

/* Gets the algorithms to use for kex etc, based on the byte array
 * arr which should be the kex_init payload received from the server.
 * It picks out each name list, then sends that to get_chosen_algo
 * with the client algos for that algo type. Returns the list of
 * chosen algos, or NULL if an algo can't be chosen */
//TODO we should really change this to use a byte_array_t, and
//probably return the offset, and have the chosen algos as
//an argument
char **get_chosen_algos(uint8_t* arr, uint32_t *list_offset) {

  //There are 8 algorithm categories to chose in
  char **ret = malloc(8*sizeof(char *));

  //The first is kex
  //We get the length of the first name list
  uint32_t name_list_len = bytes_to_int(arr + *list_offset);
  //Pass it off to compare with the client kex algos
  ret[0] = get_chosen_algo(arr + *list_offset + 4,
      name_list_len, KEX_C_ALGOS, NO_KEX_C_ALGOS);
  //If that returned null, a match wasn't found, so we can't continue
  if(!ret[0]) return NULL;
  //Move the list onwards
  *list_offset+=name_list_len + 4;

  //the next is public key algos
  name_list_len = bytes_to_int(arr + *list_offset);
  ret[1] = get_chosen_algo(arr + *list_offset + 4,
      name_list_len, KEY_C_ALGOS, NO_KEY_C_ALGOS);
  if(!ret[1]) return NULL;
  *list_offset+=name_list_len + 4;

  //client to server encryption algorithms
  name_list_len = bytes_to_int(arr + *list_offset);
  ret[2] = get_chosen_algo(arr + *list_offset + 4,
      name_list_len, ENC_ALGOS, NO_ENC_ALGOS);
  if(!ret[2]) return NULL;
  *list_offset+=name_list_len + 4;

  //server to client encryption algorithms
  name_list_len = bytes_to_int(arr + *list_offset);
  ret[3] = get_chosen_algo(arr + *list_offset + 4,
      name_list_len, ENC_ALGOS, NO_ENC_ALGOS);
  if(!ret[3]) return NULL;
  *list_offset+=name_list_len + 4;

  //client to server mac algorithms
  name_list_len = bytes_to_int(arr + *list_offset);
  ret[4] = get_chosen_algo(arr + *list_offset + 4,
      name_list_len, MAC_ALGOS, NO_MAC_ALGOS);
  if(!ret[4]) return NULL;
  *list_offset+=name_list_len + 4;

  //server to client mac algorithms
  name_list_len = bytes_to_int(arr + *list_offset);
  ret[5] = get_chosen_algo(arr + *list_offset + 4,
      name_list_len, MAC_ALGOS, NO_MAC_ALGOS);
  if(!ret[5]) return NULL;
  *list_offset+=name_list_len + 4;

  //client to server compression algorithms
  name_list_len = bytes_to_int(arr + *list_offset);
  ret[6]= get_chosen_algo(arr + *list_offset + 4,
      name_list_len, COM_ALGOS, NO_COM_ALGOS);
  if(!ret[6]) return NULL;
  *list_offset+=name_list_len + 4;

  //server to client compression algorithms
  name_list_len = bytes_to_int(arr + *list_offset);
  ret[7] = get_chosen_algo(arr + *list_offset + 4,
      name_list_len, COM_ALGOS, NO_COM_ALGOS);
  if(!ret[7]) return NULL;
  *list_offset+=name_list_len + 4;

  return ret;
}

/* Get the chosen algo from the server list of algos, arr, and the client
 * list of algos, allowable_algos. It picks out the first algo which is on
 * client list which is also on the server list. If there are none in
 * common, return NULL. */
//TODO note that the kex algorithm is chosen in a slightly different way
char *get_chosen_algo(uint8_t *arr, uint32_t len,
                      const char **allowable_algos,
                      uint32_t no_allowable_algos) {

  //If either of the lists is empty, there is no hope of finding a match
  if(len == 0 || no_allowable_algos == 0) return NULL;

  /* Split up the server name list into its separate names */
  //As the length is non-zero, there is at least one algo
  uint32_t no_s_algos = 1;
  //The first name starts on the 0th character
  uint32_t word_start = 0;
  char **s_algos = malloc(no_s_algos*sizeof(char*));
  for(int i=0; i<len; i++) {
    //If the current character is ',', we have reached the end of
    //the name, so copy the previous name.
    if(arr[i] == ',') {
      s_algos[no_s_algos-1] = malloc(i-word_start+1);
      memcpy(s_algos[no_s_algos-1], arr+word_start, i-word_start);
      s_algos[no_s_algos-1][i-word_start] = '\0';
      //The next name starts on the next character
      word_start = i+1;
      //We have at least one more name
      s_algos = realloc(s_algos, (++no_s_algos)*sizeof(char*));
    }
  }
  //Once we reach the end, there is one final name
  s_algos[no_s_algos-1] = malloc(len-word_start+1);
  memcpy(s_algos[no_s_algos-1], arr+word_start, len-word_start);
  s_algos[no_s_algos-1][len - word_start] = '\0';

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
