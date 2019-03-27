#include "myssh.h"

/* Tries to authenticate the user as per rfc4252, using
 * a public key
 * TODO comment
 */

int user_auth_publickey(connection *con,
                        const char *user,
                        const char *algo_name,
                        const char *pub_key_file,
                        const char *priv_key_file) {
  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)con);

  /* Send the userauth service request. This probably shouldn't be here as it
   * should probably only occur before the first auth attempt.
   * See rfc4253§10.
   */
  char *service_name = "ssh-userauth";
  byte_array_t service_request_message;
  service_request_message.len = 1;
  service_request_message.arr = malloc(1);
  service_request_message.arr[0] = SSH_MSG_SERVICE_REQUEST;
  string_into_byteArray(service_name, &service_request_message);
  packet service_request = build_packet(service_request_message, con);
  send_packet(service_request, con);

  free_pak(&service_request);
  free(service_request_message.arr);

  /*Receive the response to the userauth service request */
  packet *service_request_response;
  pthread_join(tid, (void **)&service_request_response);
  if(service_request_response->payload.len < 1) {
    return MYSSH_AUTH_FAIL;
  }
  //TODO check if the response is positive. This should either be a
  //success or a disconnect. There is no other option.
  free_pak(service_request_response);
  pthread_create(&tid, NULL, listener_thread, (void *)con);

  /* Prepare the userauth-request using publickey, as
   * per rfc4252§7 */
  service_name = "ssh-connection";
  uint8_t* method_name = "publickey";

  //Try to read the public key from the supplied file.
  //If it fails return an error.
  byte_array_t public_key;
  if(get_public_key(pub_key_file, &public_key) == 1)
    return 1; //TODO probably want this to be more desriptive

  byte_array_t userauth_request;
  userauth_request.len = 1;
  userauth_request.arr = malloc(userauth_request.len);
  userauth_request.arr[0] = SSH_MSG_USERAUTH_REQUEST;
  string_into_byteArray(user, &userauth_request);
  string_into_byteArray(service_name, &userauth_request);
  string_into_byteArray(method_name, &userauth_request);

  //We want to save the position of the boolean value, to change it
  //when we send the signature
  uint32_t boolean_bit = userauth_request.len;
  userauth_request.arr = realloc(userauth_request.arr, ++(userauth_request.len));
  userauth_request.arr[userauth_request.len - 1] = 0;

  string_into_byteArray(algo_name, &userauth_request);
  //It is possible that the public key format would not be correct,
  //but it is for now.
  byteArray_into_byteArray(public_key, &userauth_request);

  packet pk_query = build_packet(userauth_request, con);
  send_packet(pk_query, con);

  packet *pk_query_response;
  pthread_join(tid, (void **)&pk_query_response);
  if(pk_query_response->payload.arr[0] != SSH_MSG_USERAUTH_PK_OK) {
    return 1; //TODO return something better
  }
  free_pak(pk_query_response);
  pthread_create(&tid, NULL, listener_thread, (void *)con);

  /* Once the public key has been accepted in principle,
   * retrieve the private key, and compute the signature */
  bn_t n, d;
  bn_inits(2, &n, &d);
  uint32_t e; //In principle, e may not be a int32, but it usually is 2**16+1
  if(get_private_key(priv_key_file, n, &e, d) == 1)
    return 1; //TODO have better return values

  //The message to sign is session_id prepended to the previous message,
  //with the boolean set to TRUE
  byte_array_t to_sign;
  userauth_request.arr[boolean_bit] = 1;
  to_sign.len = userauth_request.len + con->session_id->len + 4;
  to_sign.arr = malloc(to_sign.len);
  int_to_bytes(con->session_id->len, to_sign.arr);
  memcpy(to_sign.arr + 4, con->session_id->arr, con->session_id->len);
  memcpy(to_sign.arr + con->session_id->len + 4, userauth_request.arr, userauth_request.len);

  byte_array_t sig_blob;
  sign_message(to_sign, algo_name, n, d, &sig_blob);

  //The signature is a string of algo_name prepended to the actual signature,
  //both encoded as strings
  byte_array_t sig;
  sig.len = 0;
  sig.arr = NULL;
  string_into_byteArray(algo_name, &sig);
  byteArray_into_byteArray(sig_blob, &sig);

  //Append the signature to the end of the previous message
  byteArray_into_byteArray(sig, &userauth_request);

  packet signed_pak = build_packet(userauth_request, con);
  send_packet(signed_pak, con);

  /* Wait to see if the authentication was successful */
  packet *userauth_response;
  pthread_join(tid, (void **)&userauth_response);
  if(userauth_response->payload.arr[0] != SSH_MSG_USERAUTH_SUCCESS)
    return 1;

  //TODO do clean up
  return 0;
}

//TODO comment
int sign_message(const byte_array_t to_sign,
                 const char* hash_algo,
                 const bn_t n, const bn_t d,
                 byte_array_t *sig) {
  if(strcmp(hash_algo, "rsa-sha2-256")!=0)
    return 1;

  byte_array_t hash;
  sha_256(to_sign, &hash);

  byte_array_t EM, T;
  EM.len = bn_trueLength(n);
  T.len = 19 + hash.len;
  if(EM.len < T.len + 11) return 1;

  T.arr = malloc(T.len);
  uint8_t der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
  memcpy(T.arr, der, 19);
  memcpy(T.arr + 19, hash.arr, hash.len);

  EM.arr = malloc(EM.len);
  EM.arr[0] = 0;
  EM.arr[1] = 1;
  for(int i=0; i<EM.len - T.len - 3; i++) {
    EM.arr[i+2] = 0xff;
  }
  EM.arr[EM.len - T.len - 1] = 0;
  memcpy(EM.arr + EM.len - T.len, T.arr, T.len);

  bn_t m, s;
  bn_inits(2, &m, &s);
  mpint_to_bignum(EM.arr, EM.len, m);
  bn_powmod(m, d, n, s);
  bignum_to_byteArray_u(s, sig);

  bn_nukes(2, &m, &s);
  free(EM.arr);
  free(T.arr);
  free(hash.arr);

  return 0;
}

int get_private_key(const char *file_name, bn_t n, uint32_t *e, bn_t d) {

  FILE *f;
  f = fopen(file_name, "r");

  if(!f) {
    printf("Couldn't open file\n");
    return 1;
  }
  char c;
  int len = 0;
  int mem_len = 100;
  char *private_key = malloc(mem_len);
  uint8_t body = 0;
  while((c=fgetc(f)) != -1) {
    if(c=='\n') {
      body = 1;
      continue;
    }
    if(body == 0) continue;
    if(c == '-') {
      body = 0;
      continue;
    }
    private_key[len++] = c;
    if(len >= mem_len) {
      private_key = realloc(private_key, mem_len+100);
      mem_len += 100;
    }
  }
  private_key[len] = '\0';
  fclose(f);
  byte_array_t private_key_bytes;
  if(base64_to_byteArray(private_key, &private_key_bytes) == 1)
    return 1;
  der_val_t *vals;
  int32_t no_vals = decode_der_string(private_key_bytes, &vals);
  if(no_vals!=1) return 1;
  if(vals[0].type != 0x30) return 1;
  der_seq_t seq = *((der_seq_t *)vals[0].value);
  if(seq.no_elements != 9) return 1;
  if(seq.elements[0].type != 2) return 1;
  der_int_t v = *((der_int_t*)seq.elements[0].value);
  if(v.type!=1 || *((uint8_t*)(v.value))!=0) return 1;
  if(seq.elements[1].type != 2) return 1;
  v = *((der_int_t*)seq.elements[1].value);
  if(v.type!=4) return 1;
  bn_clone(n, (bn_t)v.value);
  if(seq.elements[2].type != 2) return 1;
  v = *((der_int_t*)seq.elements[2].value);
  if(v.type!=2) return 1;
  *e = *((int32_t*)v.value);
  if(seq.elements[3].type != 2) return 1;
  v = *((der_int_t*)seq.elements[3].value);
  if(v.type!=4) return 1;
  bn_clone(d, (bn_t)(v.value));

  return 0;
}

int get_public_key(const char *file_name, byte_array_t *key) {

  FILE *f;
  f = fopen(file_name, "r");

  if(!f) {
    printf("Couldn't open file\n");
    return 1;
  }
  char c;
  int len = 0;
  int mem_len = 100;
  char *public_key = malloc(mem_len);
  uint8_t body = 0;
  while((c=fgetc(f)) != -1) {
    if(c==' ') {
      body = ~body;
      continue;
    }
    if(body == 0) continue;
    public_key[len++] = c;
    if(len >= mem_len) {
      public_key = realloc(public_key, mem_len+100);
      mem_len += 100;
    }
  }
  public_key[len] = '\0';
  fclose(f);

  return base64_to_byteArray(public_key, key);
}
