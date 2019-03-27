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

  if(start_connection(&con) == 1)
    return 1;

  printf("%s%s", V_C, V_S);

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

void *listener_thread(void *arg) {
  connection *c = (connection *)arg;

  //Read the first few bytes on the socket, to get the total length
  uint32_t block_size;
  if(!c->enc_s2c)
    //If the session isn't encrypted, just read 8 bytes (min length)
    block_size = 8;
  else
    //Otherwise read the blocksize of the encryption
    block_size = c->enc_s2c->block_size;
  byte_array_t first_block;
  first_block.len = block_size;
  first_block.arr = malloc(first_block.len);
  if(recv(c->socket, first_block.arr, first_block.len, 0) < block_size) {
    //If we don't receive the right number of bytes, there's an error
    printf("Received fewer than expected bytes\n");
    return NULL;
  }

  byte_array_t read, temp;
  if(c->enc_s2c) {
    //If there is encryption, try to decrypt the first block
    if(c->enc_s2c->dec(first_block, c->enc_s2c->key, &(c->enc_s2c->iv), &temp)
        != 0) {
      printf("Error when decrypting\n");
      return NULL;
    }
    read.len = temp.len;
    read.arr = malloc(read.len);
    memcpy(read.arr, temp.arr, read.len);
    free(temp.arr);
  } else {
    //Otherwise just copy the read bytes in
    read.len = first_block.len;
    read.arr = malloc(read.len);
    memcpy(read.arr, first_block.arr, read.len);
  }
  free(first_block.arr);

  //Initialise the packet with the packet length and padding length,
  //malloc the spaces for the payload and padding
  packet *p = malloc(sizeof(packet));
  p->packet_length = bytes_to_int(read.arr);
  p->padding_length = (read.arr)[4];
  if((p->packet_length + 4)%block_size != 0) {
    //Length of the packet must be a multiple of the block size
    printf("Invalid message length\n");
    return NULL;
  }
  p->payload.len = p->packet_length - p->padding_length - 1;
  p->payload.arr = malloc(p->payload.len);
  p->padding = malloc(p->padding_length);

  int to_receive = p->packet_length + 4 - block_size;
  if(to_receive >= 35000 || to_receive < 0) {
    //The maximum packet size is 35000 bytes.
    //Obviously there should be a non-negative number of bytes still to read.
    printf("Invalid message length\n");
    return NULL;
  }

  if(to_receive > 0) {
    //Receive the rest of the packet
    byte_array_t next_blocks;
    next_blocks.len = to_receive;
    next_blocks.arr = malloc(to_receive);
    if(recv(c->socket, next_blocks.arr, to_receive, 0) < to_receive) {
      printf("Received fewer than expected bytes\n");
      return NULL;
    }

    //Decrypt the new blocks
    if(c->enc_s2c) {
      if(c->enc_s2c->dec(next_blocks, c->enc_s2c->key, &(c->enc_s2c->iv), &temp)
          != 0) {
        printf("Error when decrypting\n");
        return NULL;
      }
      read.len += temp.len;
      read.arr = realloc(read.arr, read.len);
      memcpy(read.arr + first_block.len, temp.arr, read.len - first_block.len);
      free(temp.arr);
    } else {
      read.len += next_blocks.len;
      read.arr = realloc(read.arr, read.len);
      memcpy(read.arr + first_block.len, next_blocks.arr, read.len - first_block.len);
    }

    free(next_blocks.arr);
  }

  //Copy the decrypted bytes into the packet.
  //We could do this directly but the offsets and such may be tricky
  memcpy(p->payload.arr, read.arr + 5, p->payload.len);
  memcpy(p->padding, read.arr + 5 + p->payload.len, p->padding_length);

  //If there is a mac, get those blocks.
  if(c->mac_s2c) {
    read.len += c->mac_s2c->mac_output_size;
    read.arr = realloc(read.arr, read.len);
    if(recv(c->socket, read.arr + read.len - c->mac_s2c->mac_output_size,
        c->mac_s2c->mac_output_size, 0) < c->mac_s2c->mac_output_size) {
      printf("Received fewer than expected MAC bytes\n");
      return NULL;
    }
    //TODO we should check if the mac is the same
    p->mac.len = c->mac_s2c->mac_output_size;
    p->mac.arr = malloc(c->mac_s2c->mac_output_size);
    memcpy(p->mac.arr, read.arr + read.len - c->mac_s2c->mac_output_size,
        c->mac_s2c->mac_output_size);
  } else {
    p->mac.len = 0;
    p->mac.arr = NULL;
  }

  free(read.arr);
  return (void *)p;
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

uint8_t kex_init(connection *c) {
  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)c);

  //Send the kex init packet
  packet kex_init_c = build_kex_init(c);
  send_packet(kex_init_c, c);

  //Receive the kex init packet
  packet *kex_init_s;
  pthread_join(tid, (void **)&kex_init_s);
  //TODO check that it is actually a kex init packet

  /* Determine which algorithms will be used */
  uint32_t list_offset = 17;
  //Get the algorithms to use. These are the first client choice
  //which also occurs as a server choice.
  //TODO really we should pass the algo list which we sent as well.
  char **chosen_algos = get_chosen_algos(kex_init_s->payload.arr, &list_offset);
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
  is = kex_init_s->payload;
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
  free_pak(kex_init_s);

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
  pthread_create(&tid, NULL, listener_thread, (void *)c);
  uint8_t new_keys_bytes[] = {SSH_MSG_NEWKEYS};
  byte_array_t new_keys = {1, new_keys_bytes};
  packet new_keys_pak = build_packet(new_keys, c);
  send_packet(new_keys_pak, c);
  free_pak(&new_keys_pak);

  //Wait to receive the new keys packet
  packet *new_keys_pak_s;
  pthread_join(tid, (void **)&new_keys_pak_s);
  if(new_keys_pak_s->payload.arr[0] != SSH_MSG_NEWKEYS) {
    printf("Didn't get a new keys packet\n");
    return 1; //TODO error code
  }
  free_pak(new_keys_pak_s);

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

  bn_nukes(3, &e, &f, &K);
  free(prehash.arr);
  return 0;
}
