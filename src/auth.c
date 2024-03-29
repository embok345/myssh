#include "myssh.h"
#include <readline/readline.h>
#include <termio.h>


/* Send the userauth service request. */

int service_request(connection *con) {
  char *service_name = "ssh-userauth";
  byte_array_t service_request_message = create_byteArray(1);
  set_byteArray_element(service_request_message, 0, SSH_MSG_SERVICE_REQUEST);
  byteArray_append_len_str(service_request_message, service_name);
  packet service_request = build_packet(service_request_message, con);
  send_packet(service_request, con);

  free_pak(service_request);
  free_byteArray(service_request_message);

  /*Receive the response to the userauth service request */
  packet service_request_response =
      wait_for_packet(con, 1, SSH_MSG_SERVICE_ACCEPT);
  uint32_t pak_len = get_byteArray_len(service_request_response.payload);
  byte_array_t service_request_response_name =
      tail_byteArray(service_request_response.payload, 5);

  if( pak_len != strlen(service_name) + 5 ||
      byteArray_strncmp(service_request_response.payload, service_name, 5,
        strlen(service_name)) != 0 ) {
    printf("Service request failed\n");
    free_pak(service_request_response);
    return MYSSH_AUTH_FAIL;
  }
  free_pak(service_request_response);
  free_byteArray(service_request_response_name);
  return MYSSH_AUTH_SUCCESS;
}

/* Tries to authenticate a user with a password */
/* NOT IMPLEMENTED */
int user_auth_passwd(connection *con, const char *user) {
  return MYSSH_AUTH_FAIL;
}

int interactive_response(connection *con, byte_array_t message) {
  uint32_t offset = 1;
  char *name = get_byteArray_str(message, offset);
  if(!name) {
    return MYSSH_AUTH_FAIL;
  }
  offset += 4 + strlen(name);
  char *instruction = get_byteArray_str(message, offset);
  if(!instruction) {
    return MYSSH_AUTH_FAIL;
  }
  offset += 4 + strlen(instruction);
  char *lang = get_byteArray_str(message, offset);
  if(!lang) {
    return MYSSH_AUTH_FAIL;
  }
  offset += 4 + strlen(lang);

  if(strlen(name) > 0)
    printf("%s\n", name);
  if(strlen(instruction) > 0)
    printf("%s\n", instruction);

  uint32_t noPrompts = byteArray_to_int(message, offset);
  offset += 4;
  char *prompt;
  uint8_t echo;
  char **responses = malloc(noPrompts*sizeof(char *));
  for(int i=0; i<noPrompts; i++) {
    prompt = get_byteArray_str(message, offset);
    if(!prompt) {
      return MYSSH_AUTH_FAIL;
    }
    offset += 4 + strlen(prompt);
    echo = get_byteArray_element(message, offset);
    if(!echo) {
      echoOff();
      responses[i] = readline(prompt);
      echoOn();
      printf("\n");
    } else {
      responses[i] = readline(prompt);
    }
    free(prompt);
  }

  byte_array_t info_response = create_byteArray(1);
  set_byteArray_element(info_response, 0,
      SSH_MSG_USERAUTH_INFO_RESPONSE);
  byteArray_append_int(info_response, noPrompts);
  for(int i=0; i<noPrompts; i++) {
    byteArray_append_len_str(info_response, responses[i]);
    free(responses[i]);
  }
  free(responses);
  packet info_response_pak = build_packet(info_response, con);
  send_packet(info_response_pak, con);

  free(info_response);
  free_pak(info_response_pak);

  packet info_response_reply = wait_for_packet(con, 3,
      SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE,
      SSH_MSG_USERAUTH_INFO_REQUEST);

  uint8_t info_response_reply_code = get_byteArray_element(
      info_response_reply.payload, 0);

  if(info_response_reply_code == SSH_MSG_USERAUTH_SUCCESS) {
    printf("Successful auth!");
    free_pak(info_response_reply);
    return MYSSH_AUTH_SUCCESS;
  } else if(info_response_reply_code == SSH_MSG_USERAUTH_INFO_REQUEST) {
    int success = interactive_response(con, info_response_reply.payload);
    free_pak(info_response_reply);
    return success;
  } else {
    free_pak(info_response_reply);
    return MYSSH_AUTH_FAIL; //TODO may be a partial success still
  }
}

int user_auth_interactive(connection *con, const char *user) {
  printf("Trying to do interactive auth\n");
  char *service_name = "ssh-connection";
  char *method_name = "keyboard-interactive";

  byte_array_t userauth_request = create_byteArray(1);
  set_byteArray_element(userauth_request, 0, SSH_MSG_USERAUTH_REQUEST);
  byteArray_append_len_str(userauth_request, user);
  byteArray_append_len_str(userauth_request, service_name);
  byteArray_append_len_str(userauth_request, method_name);
  byteArray_append_int(userauth_request, 0);
  byteArray_append_int(userauth_request, 0);

  packet request_pak = build_packet(userauth_request, con);
  send_packet(request_pak, con);
  free_pak(request_pak);

  packet response_pak = wait_for_packet(con, 3,
      SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE,
      SSH_MSG_USERAUTH_INFO_REQUEST);
  uint8_t response_code =
      get_byteArray_element(response_pak.payload, 0);
  if(response_code == SSH_MSG_USERAUTH_FAILURE) {
    printf("Couldn't complete interactive auth");
    free_pak(response_pak);
    return MYSSH_AUTH_FAIL;//TODO get the reason
  } else if(response_code == SSH_MSG_USERAUTH_SUCCESS) {
    free_pak(response_pak);
    return MYSSH_AUTH_SUCCESS;
  } else if(response_code != SSH_MSG_USERAUTH_INFO_REQUEST) {
    //never reached
    free_pak(response_pak);
    return MYSSH_AUTH_FAIL;
  }
  //The response code is now info_request

  int success = interactive_response(con, response_pak.payload);
  free_pak(response_pak);
  return success;
}

/* Tries to authenticate the user as per rfc4252, using
 * a public key
 * TODO comment
 */
int user_auth_publickey(connection *con,
                        const char *user,
                        const char *algo_name,
                        const char *pub_key_file,
                        const char *priv_key_file) {

  if(service_request(con) != MYSSH_AUTH_SUCCESS) {
    return MYSSH_AUTH_FAIL;
  }

  /* Prepare the userauth-request using publickey, as
   * per rfc4252§7 */
  char *service_name = "ssh-connection";
  char *method_name = "publickey";

  //Try to read the public key from the supplied file.
  //If it fails return an error.
  byte_array_t public_key = create_byteArray(0);
  if(get_public_key(pub_key_file, public_key) == 1)
    return MYSSH_AUTH_FAIL;

  byte_array_t userauth_request = create_byteArray(1);
  set_byteArray_element(userauth_request, 0, SSH_MSG_USERAUTH_REQUEST);
  byteArray_append_len_str(userauth_request, user);
  byteArray_append_len_str(userauth_request, service_name);
  byteArray_append_len_str(userauth_request, method_name);

  //We want to save the position of the boolean value, to change it
  //when we send the signature
  uint32_t boolean_bit = get_byteArray_len(userauth_request);
  byteArray_append_byte(userauth_request, 0);

  byteArray_append_len_str(userauth_request, algo_name);
  //It is possible that the public key format would not be correct,
  //but it is for now.
  byteArray_append_len_byteArray(userauth_request, public_key);

  packet pk_query = build_packet(userauth_request, con);
  send_packet(pk_query, con);
  free_pak(pk_query);

  packet pk_query_response = wait_for_packet(con, 2,
      SSH_MSG_USERAUTH_PK_OK, SSH_MSG_USERAUTH_FAILURE);
  uint8_t pk_query_response_code =
      get_byteArray_element(pk_query_response.payload, 0);
  if(pk_query_response_code == SSH_MSG_USERAUTH_FAILURE) {
    printf("Public key not accepted\n");
    return MYSSH_AUTH_FAIL;//TODO get the reason
  } else if(pk_query_response_code != SSH_MSG_USERAUTH_PK_OK) {
    //never reached
    return MYSSH_AUTH_FAIL;
  } else if(
      get_byteArray_len(pk_query_response.payload) <
        strlen(algo_name) + get_byteArray_len(public_key) + 9 ||
      byteArray_strncmp(pk_query_response.payload, algo_name, 5,
        strlen(algo_name)) != 0 ||
      byteArray_ncmp(pk_query_response.payload, 9+strlen(algo_name),
        public_key, 0, get_byteArray_len(public_key)) != 0) {
    printf("Wrong public key accepted\n");
    return MYSSH_AUTH_FAIL;
  }

  free_byteArray(public_key);
  free_pak(pk_query_response);

  /* Once the public key has been accepted in principle,
   * retrieve the private key, and compute the signature */
  bn_t p, q, dP, dQ, qInv;
  if(!bn_inits(5, &p, &q, &dP, &dQ, &qInv)) return 1;
  if(get_private_key(priv_key_file, 5, p, q, dP, dQ, qInv) == 1)
    return 1;

  //The message to sign is session_id prepended to the previous message,
  //with the boolean set to TRUE
  set_byteArray_element(userauth_request, boolean_bit, 1);
  byte_array_t to_sign = create_byteArray(0);
  byteArray_append_len_byteArray(to_sign, con->session_id);
  byteArray_append_byteArray(to_sign, userauth_request);

  byte_array_t sig_blob = create_byteArray(0);
  sign_message(to_sign, algo_name, sig_blob, 5, p, q, dP, dQ, qInv);

  free_byteArray(to_sign);
  bn_deinits(5, &p, &q, &dP, &dQ, &qInv);

  //The signature is a string of algo_name prepended to the actual signature,
  //both encoded as strings
  byte_array_t sig = create_byteArray(0);
  byteArray_append_len_str(sig, algo_name);
  byteArray_append_len_byteArray(sig, sig_blob);
  free_byteArray(sig_blob);

  //Append the signature to the end of the previous message
  byteArray_append_len_byteArray(userauth_request, sig);
  free_byteArray(sig);

  packet signed_pak = build_packet(userauth_request, con);
  send_packet(signed_pak, con);

  free_byteArray(userauth_request);
  free_pak(signed_pak);

  /* Wait to see if the authentication was successful */
  packet userauth_response = wait_for_packet(con, 2,
      SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE);
  uint32_t userauth_response_code =
      get_byteArray_element(userauth_response.payload, 0);

  if(userauth_response_code == SSH_MSG_USERAUTH_FAILURE) {
    uint32_t length = 0;
    uint32_t noNames = 0;
    char **auths_can_proceed = get_byteArray_nameList(
        userauth_response.payload, 1, &length, &noNames);
    uint8_t partial_success = get_byteArray_element(
        userauth_response.payload, length + 1);

    free_pak(userauth_response);

    if(partial_success == 0 || noNames == 0) {
      printf("Auth failed\n");
      return MYSSH_AUTH_FAIL;
    }

    if(strcmp(auths_can_proceed[0], AUTH_PASSWD) == 0) {
      printf("Authenticatied with partial success1\n");
      return user_auth_passwd(con, user);
    }
    if(strcmp(auths_can_proceed[0], AUTH_INTERACTIVE) == 0) {
      printf("Authenticated with partial success2\n");
      return user_auth_interactive(con, user);
    }

  } else if(userauth_response_code == SSH_MSG_USERAUTH_SUCCESS) {
    free_pak(userauth_response);
    return MYSSH_AUTH_SUCCESS;
  } else {
    //never reached
    free_pak(userauth_response);
    return MYSSH_AUTH_FAIL;
  }
  return 0;
}

//TODO comment
int sign_message(const byte_array_t to_sign,
                 const char *hash_algo,
                 byte_array_t sig,
                 int no_vals, ...) {
  if(strcmp(hash_algo, "rsa-sha2-256")!=0)
    return 1;
  if(no_vals != 2 && no_vals != 5)
    return 1;

  va_list valist;
  va_start(valist, no_vals);
  bn_t n, d, p, q, dP, dQ, qInv;
  byte_array_t EM, T, hash;

  sha_256(to_sign, &hash);

  uint32_t em_len = 0;

  if(no_vals == 2) {
    n = va_arg(valist, bn_t);
    d = va_arg(valist, bn_t);
    //EM.len = bn_trueLength(n);
    em_len = bn_trueLength(n);
  } else {
    p = va_arg(valist, bn_t);
    q = va_arg(valist, bn_t);
    dP = va_arg(valist, bn_t);
    dQ = va_arg(valist, bn_t);
    qInv = va_arg(valist, bn_t);
    //EM.len = bn_trueLength(p) + bn_trueLength(q);//This may not be correct
    em_len = bn_trueLength(p) + bn_trueLength(q);
  }
  va_end(valist);

  //T.len = 19 + hash.len;
  //T = create_byteArray(19 + get_byteArray_len(hash));
  //if(EM.len < T.len + 11) return 1;
  if(em_len < get_byteArray_len(hash) + 30) {
    free_byteArray(hash);
    return 1;
  }

  //T.arr = malloc(T.len);
  uint8_t der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
  //memcpy(T.arr, der, 19);
  //memcpy(T.arr + 19, hash.arr, hash.len);
  T = set_byteArray(19, der);
  byteArray_append_byteArray(T, hash);

  //EM.arr = malloc(EM.len);
  //EM.arr[0] = 0;
  //EM.arr[1] = 1;
  //for(int i=0; i<EM.len - T.len - 3; i++) {
  //  EM.arr[i+2] = 0xff;
  //}
  //EM.arr[EM.len - T.len - 1] = 0;
  //memcpy(EM.arr + EM.len - T.len, T.arr, T.len);
  EM = create_byteArray(em_len - get_byteArray_len(T));
  set_byteArray_element(EM, 0, 0);
  set_byteArray_element(EM, 1, 1);
  for(int i=0; i<em_len - get_byteArray_len(T) - 3; i++) {
    set_byteArray_element(EM, i+2, 0xff);
  }
  set_byteArray_element(EM, em_len - get_byteArray_len(T) - 1, 0);
  byteArray_append_byteArray(EM, T);

  bn_t c, m;
  if(!bn_inits(2, &c, &m)) return 1;
  //mpint_to_bignum(EM.arr, EM.len, c);
  byteArray_to_bignum(EM, c);

  if(no_vals == 2) {
    bn_powmod(c, d, n, m);
  } else {
    bn_t m_1, m_2, h, t1, t2, t3;
    if(!bn_inits(6, &m_1, &m_2, &h, &t1, &t2, &t3)) return 1;
    bn_powmod(c, dP, p, m_1);
    bn_powmod(c, dQ, q, m_2);
    bn_sub(m_1, m_2, t1);
    bn_mul(t1, qInv, t2);
    bn_div_rem(t2, p, h);
    bn_mul(q, h, t3);
    bn_add(m_2, t3, m);
    bn_deinits(6, &m_1, &m_2, &h, &t1, &t2, &t3);
  }

  //bignum_to_byteArray_u(m, sig);
  bignum_to_byteArray_u(m, sig);

  bn_deinits(2, &c, &m);
  free_byteArray(EM);
  free_byteArray(T);
  free_byteArray(hash);

  return 0;
}

int get_private_key(const char *file_name, int no_elements, ...) {

  if(no_elements != 2 && no_elements !=5)
    return 1;

  FILE *fp;
  fp = fopen(file_name, "r");
  if(!fp) return 1;
  char line[200];
  if(!fgets(line, sizeof line, fp)) return 1;
  if(strcmp(line, "-----BEGIN RSA PRIVATE KEY-----\n") != 0) return 1;

  uint8_t encrypted = 0;
  char *key_file_contents_str = NULL;
  uint32_t key_file_contents_str_len = 0;
  if(!fgets(line, sizeof line, fp)) return 1;
  if(strcmp(line, "Proc-Type: 4,ENCRYPTED\n") == 0) {
    encrypted = 1;
  } else {
    key_file_contents_str = realloc(key_file_contents_str,
        key_file_contents_str_len + strlen(line));
    memcpy(key_file_contents_str + key_file_contents_str_len,
        line, strlen(line)-1);
    key_file_contents_str[key_file_contents_str_len + strlen(line) - 1] = '\0';
    key_file_contents_str_len += strlen(line) - 1;
  }

  byte_array_t iv_arr;

  if(encrypted) {
    if(!fgets(line, sizeof line, fp)) return 1;
    if(strncmp(line, "DEK-Info: ", 10) != 0) return 1;
    uint8_t break_point=0;
    for(int i=10; i<strlen(line); i++) {
      if(line[i] == ',') {
        break_point = i;
        break;
      }
    }
    char *dek_mode = malloc(break_point-9);
    char *iv_str = malloc(strlen(line) - break_point-1);
    strncpy(dek_mode, line + 10, break_point-10);
    dek_mode[break_point-10] = '\0';
    strncpy(iv_str, line+break_point+1, strlen(line)-break_point-2);
    iv_str[strlen(line)-break_point-2] = '\0';
    iv_arr = create_byteArray(strlen(iv_str)/2);
    for(int i=0; i<strlen(iv_str)/2; i++) {
      if(isdigit(iv_str[i*2])) {
        set_byteArray_element(iv_arr, i, (iv_str[i*2]-'0')<<4);
      } else if(isxdigit(iv_str[i*2])) {
        if(isupper(iv_str[i*2])) {
          set_byteArray_element(iv_arr, i, (iv_str[i*2]-'A'+10)<<4);
        } else
          set_byteArray_element(iv_arr, i, (iv_str[i*2]-'a'+10)<<4);
      } else {
        free(dek_mode);
        free(iv_str);
        free_byteArray(iv_arr);
        return 1;
      }

      if(isdigit(iv_str[(2*i)+1])) {
        set_byteArray_element(iv_arr, i,
            get_byteArray_element(iv_arr, i) + (iv_str[(i*2)+1]-'0'));
      } else if(isxdigit(iv_str[(2*i)+1])) {
        if(isupper(iv_str[(2*i)+1]))
          set_byteArray_element(iv_arr, i,
              get_byteArray_element(iv_arr, i) + (iv_str[(i*2)+1]-'A'+10));
        else
          set_byteArray_element(iv_arr, i,
              get_byteArray_element(iv_arr, i) + (iv_str[(i*2)+1]-'a'+10));
      } else {
        free(dek_mode);
        free(iv_str);
        free_byteArray(iv_arr);
        return 1;
      }
    }
    free(iv_str);
    free(dek_mode);
  }

  while(fgets(line, sizeof line, fp)) {
    if(strcmp(line, "-----END RSA PRIVATE KEY-----\n") == 0) break;
    key_file_contents_str = realloc(key_file_contents_str,
        key_file_contents_str_len + strlen(line));
    memcpy(key_file_contents_str + key_file_contents_str_len,
        line, strlen(line)-1);
    key_file_contents_str[key_file_contents_str_len + strlen(line) - 1] = '\0';
    key_file_contents_str_len += strlen(line) - 1;
  }
  fclose(fp);

  byte_array_t key_file_contents_arr = create_byteArray(0);
  base64_to_byteArray(key_file_contents_str, key_file_contents_arr);


  va_list args;
  va_start(args, no_elements);
  bn_t nums[no_elements];
  for(int i=0; i<no_elements; i++) {
    nums[i] = va_arg(args, bn_t);
  }
  va_end(args);

  if(encrypted) {
    const byte_array_t iv_bak = copy_byteArray(iv_arr);
    while(1) {
      echoOff();
      char *pwd_str = readline("Enter rsa private key password: ");
      echoOn();
      printf("\n");
      byte_array_t salt = head_byteArray(iv_arr, 8);
      byte_array_t priv_key_pwd = str_to_byteArray(pwd_str);
      free(pwd_str);
      byteArray_append_byteArray(priv_key_pwd, salt);
      free_byteArray(salt);

      byte_array_t hashed_pwd;
      md5(priv_key_pwd, &hashed_pwd);
      free_byteArray(priv_key_pwd);

      byte_array_t decrypted_priv_key;
      inv_aes_cbc(key_file_contents_arr, hashed_pwd, iv_arr, &decrypted_priv_key);
      free_byteArray(hashed_pwd);

      if((no_elements == 2 && decode_private_key(decrypted_priv_key,
          no_elements, nums[0], nums[1]) == 0) ||
         (no_elements == 5 && decode_private_key(decrypted_priv_key,
          no_elements, nums[0], nums[1], nums[2], nums[3], nums[4]) == 0)) {
        break;
      }
      free_byteArray(decrypted_priv_key);
      free_byteArray(iv_arr);
      iv_arr = copy_byteArray(iv_bak);
      printf("Wrong password.\n");
    }
  } else {
    if((no_elements == 2 && decode_private_key(key_file_contents_arr,
        no_elements, nums[0], nums[1])!=0) ||
       (no_elements == 5 && decode_private_key(key_file_contents_arr,
        no_elements, nums[0], nums[1], nums[2], nums[3], nums[4]) != 0))
      return 1;
  }

  /*FILE *f;
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

  byte_array_t private_key_bytes = create_byteArray(0);
  if(base64_to_byteArray(private_key, private_key_bytes) == 1) {
    free_byteArray(private_key_bytes);
    free(private_key);
    return 1;
  }

  free(private_key);

  va_list arg_list;
  va_start(arg_list, no_elements);
  if(decode_private_key(private_key_bytes, no_elements, arg_list)!=0)
    return 1;
  va_end(arg_list);

  free_byteArray(private_key_bytes);*/

  return 0;
}

int get_public_key(const char *file_name, byte_array_t key) {

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

  int ret = base64_to_byteArray(public_key, key);
  free(public_key);

  return ret;
}
