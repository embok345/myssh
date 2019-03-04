#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <inttypes.h>
#include <ctype.h>

#include "names.h"
#include "numbers.h"
#include <bignum.h>

typedef struct connection {
  struct sockaddr_in socket;
  int8_t encryption;
  int8_t mac;
  int8_t compression;
  int32_t sequence_number;
} connection;

typedef struct packet {
  uint32_t packet_length;
  uint8_t padding_length;
  uint8_t *payload;
  uint8_t *padding;
  uint8_t *mac;
} packet;

typedef struct byte_array {
  uint32_t len;
  uint8_t *arr;
} byte_array;

int init_connection(int);
void kex_init(int);
void *listener_thread(void *);
uint32_t packet_to_bytes(packet, uint8_t **);
packet bytes_to_packet(uint8_t *, int);
packet build_kex_init();
packet build_packet(uint8_t *, uint32_t);
void int_to_bytes(uint32_t, uint8_t *);
void mpint_to_bignum(uint8_t *, uint32_t, bignum *);

int main() {

  srand(time(NULL));
  register_printf_specifier('B', bn_printf, bn_printf_info);

  int sock;
  struct sockaddr_in dest;

  sock = socket(AF_INET, SOCK_STREAM, 0);

  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr("104.248.169.129");
  dest.sin_port = htons(24317);

  connect(sock, (struct sockaddr *)&dest, sizeof(struct sockaddr_in));

  //init_connection(sock);
  kex_init(sock);

  return 0;
}

void *listener_thread(void *arg) {
  uint8_t *output = malloc(35000);
  int sock = *((int *)arg);
  int len = recv(sock, output, 35000, 0);
  output = realloc(output, len);
  byte_array *arr = malloc(sizeof(byte_array));
  arr->len = len;
  arr->arr = output;
  return (void *)arr;
}

uint32_t bytes_to_int(uint8_t* bytes) {
  uint32_t out = bytes[0];
  out = (out<<8) + bytes[1];
  out = (out<<8) + bytes[2];
  out = (out<<8) + bytes[3];
  return out;
}

packet bytes_to_packet(uint8_t *bytes, int len) {
  packet p;
  p.packet_length = bytes_to_int(bytes);
  p.padding_length = bytes[4];
  p.payload = malloc(p.packet_length - p.padding_length - 1);
  memcpy(p.payload, bytes+5, p.packet_length - p.padding_length - 1);
  p.padding = malloc(p.padding_length);
  memcpy(p.padding, bytes+5+p.packet_length-p.padding_length-1, p.padding_length);
  return p;
}

uint32_t packet_to_bytes(packet p, uint8_t **bytes) {
  *bytes = malloc(p.packet_length + 4); //+mac length
  int_to_bytes(p.packet_length, *bytes);
  (*bytes)[4] = p.padding_length;
  memcpy((*bytes)+5, p.payload, p.packet_length-p.padding_length-1);
  memcpy((*bytes)+5+p.packet_length-p.padding_length-1, p.padding, p.padding_length);
  return p.packet_length + 4; //+mac length
}

void mpint_to_bignum(uint8_t *blocks, uint32_t len, bignum *out) {
  bn_resize(out, len);
  for(uint32_t i=0; i<len; i++) {
    bn_setBlock(out, i, blocks[len-i-1]);
  }
  bn_removezeros(out);
}

void kex_init(int sock) {

  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  int identification_c_string_len = strlen(VERSION)+11;
  uint8_t *identification_c_string = malloc(identification_c_string_len);
  snprintf(identification_c_string, identification_c_string_len,
      "SSH-2.0-%s\r\n", VERSION);
  send(sock, identification_c_string, identification_c_string_len, 0);

  byte_array *identification_s_string;
  pthread_join(tid, (void **)&identification_s_string);
  while(identification_s_string->len < 4 ||
      memcmp(identification_s_string->arr, "SSH-", 3)!=0) {
    //Then the command didn't start with "SSH-"
    //So keep listening
    //free(arr.arr);
    pthread_create(&tid, NULL, listener_thread, (void *)&sock);
    pthread_join(tid, (void **)&identification_s_string);
  }

  //remote_constr now starts with "SSH-"
  if(identification_s_string->len<8 ||
      memcmp(identification_s_string->arr+4, "2.0-", 4)!=0) {
    //Not a valid ssh protocol version
    printf("Invalid protocol\n");
    return;
  }

  printf("%s", identification_c_string);
  printf("%s", identification_s_string->arr);

  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  packet kex_init_c_pak = build_kex_init();
  uint8_t *kex_init_c_bytes;
  uint32_t messageLen = packet_to_bytes(kex_init_c_pak, &kex_init_c_bytes);
  send(sock, kex_init_c_bytes+1, messageLen, 0);
  free(kex_init_c_bytes);

  byte_array *kex_init_s_bytes;
  pthread_join(tid, (void **)&kex_init_s_bytes);
  packet kex_init_s_pak = bytes_to_packet(kex_init_s_bytes->arr,
      kex_init_s_bytes->len);
  //We should really check here that the algorithms match up

  bignum *p, *g, *x, *e;
  bn_inits(4, &p, &g, &x, &e);
  bn_set(p, 256, DH_14_BLOCKS, 1);
  bn_conv_int2bn(2, g);
  bn_rand(x, p);
  bn_powmod(g, x, p, e);
  printf("e = %B\n", e);

  uint32_t e_len = bn_trueLength(e);
  uint8_t *kex_dh_init_payload = malloc(e_len+6);
  kex_dh_init_payload[0] = SSH_MSG_KEXDH_INIT;
  int_to_bytes((bn_getBlock(e, e_len-1)>=128) ? e_len+1 : e_len,
      kex_dh_init_payload+1);
  int offset = 5;
  if(bn_getBlock(e, e_len-1)>=128) {
    kex_dh_init_payload[5] = 0;
    offset++;
  }
  for(int i=0; i<e_len; i++) {
    kex_dh_init_payload[i+offset] = bn_getBlock(e, e_len-i-1);
  }
  packet kex_dh_init_pak = build_packet(kex_dh_init_payload, e_len+offset);

  /*bytes = malloc(7);
  bytes[0] = SSH_MSG_KEXDH_INIT;
  int_to_bytes(2, bytes+1);
  bytes[5]=3;
  bytes[6]=233;
  pak = build_packet(bytes, 7);*/

  uint8_t *kex_dh_init_bytes;
  messageLen = packet_to_bytes(kex_dh_init_pak, &kex_dh_init_bytes);
  send(sock, kex_dh_init_bytes+1, messageLen, 0);

  printf("Sent key\n");
  free(kex_dh_init_bytes);

  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  byte_array *kex_dh_reply_bytes;
  pthread_join(tid, (void **)&kex_dh_reply_bytes);
  packet kex_dh_reply_pak = bytes_to_packet(kex_dh_reply_bytes->arr,
      kex_dh_reply_bytes->len);

  /*uint8_t * = malloc(35000);
  uint32_t receivedBytes = recv(sock, newBytes, 35000, 0);
  newBytes = realloc(newBytes, receivedBytes);
  pak = bytes_to_packet(newBytes, receivedBytes);
  //printf("received packet length: %"PRIu32"\n", pak.packet_length);
  //printf("received padding length: %"PRIu8"\n", pak.padding_length);
*/
  if(kex_dh_reply_pak.payload[0] == SSH_MSG_KEXDH_REPLY) {
    uint32_t len_K_S = bytes_to_int(kex_dh_reply_pak.payload+1);
    uint8_t *K_S = malloc(len_K_S);
    memcpy(K_S, kex_dh_reply_pak.payload+5,len_K_S);

    uint32_t len_f = bytes_to_int(kex_dh_reply_pak.payload+5+len_K_S);
    uint8_t *f_bytes = malloc(len_f);
    memcpy(f_bytes, kex_dh_reply_pak.payload+9+len_K_S, len_f);
    bignum *f;
    bn_init(&f);
    mpint_to_bignum(f_bytes, len_f, f);
    printf("f = %B\n", f);
    bignum *K;
    bn_init(&K);
    bn_powmod(f, x, p, K);
    printf("K = %B\n", K);

    uint32_t len_sig = bytes_to_int(kex_dh_reply_pak.payload+9+len_K_S+len_f);
    uint8_t *sig = malloc(len_sig);
    memcpy(sig, kex_dh_reply_pak.payload+13+len_K_S+len_f, len_sig);

    for(int i=0; i<strlen(identification_c_string); i++) {
      printf("%"PRId8" ", identification_c_string[i]);
    }
    printf("\n");
    for(int i=0; i<strlen(identification_s_string->arr); i++) {
      printf("%"PRId8" ", identification_s_string->arr[i]);
    }
    printf("\n");
  }
}

int init_connection(int sock) {

  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  int constr_len = strlen(VERSION)+11;
  char *constr = malloc(constr_len);
  snprintf(constr, constr_len, "SSH-2.0-%s\r\n", VERSION);
  send(sock, constr, constr_len, 0);

  byte_array *arr;
  pthread_join(tid, (void **)&arr);
  while(arr->len < 4 || memcmp(arr->arr, "SSH-", 3)!=0) {
    //Then the command didn't start with "SSH-"
    //So keep listening
    //free(arr.arr);
    pthread_create(&tid, NULL, listener_thread, (void *)&sock);
    pthread_join(tid, (void **)&arr);
  }

  //remote_constr now starts with "SSH-"

  if(arr->len<8 || memcmp(arr->arr+4, "2.0-", 4)!=0) {
    //Not a valid ssh protocol version
    printf("Invalid protocol\n");
    free(constr);
    //free(arr.arr);
    //free(remote_constr);
    return 0;
  }
  //Lets assume we can continue now.
  return 1;
}

void int_to_bytes(uint32_t in, uint8_t *out) {
  out[0] = in>>24;
  out[1] = (in>>16)%256;
  out[2] = (in>>8)%256;
  out[3] = in%256;
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

packet build_packet(uint8_t *message, uint32_t messageLength) {
  packet p;

  p.padding_length = 8 - ((messageLength+5)%8);
  if(p.padding_length<4)
    p.padding_length+=8;

  p.padding = malloc(p.padding_length);
  for(int i=0; i<p.padding_length; i++) {
    p.padding[i] = rand();
  }

  p.mac = NULL; //for now at least

  p.packet_length = messageLength + p.padding_length + 1;

  p.payload = message;

  return p;
}

packet build_kex_init() {
  uint8_t *message = malloc(2000);
  message[0] = SSH_MSG_KEXINIT;
  for(int i=1; i<17; i++) {
    message[i] = rand();
  }
  uint32_t messageLength = 17;

  messageLength+=build_name_list(NO_KEX_ALGOS, KEX_ALGOS, message+messageLength);

  messageLength+=build_name_list(NO_KEY_ALGOS, KEY_ALGOS, message+messageLength);

  messageLength+=build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message+messageLength);
  messageLength+=build_name_list(NO_ENC_ALGOS, ENC_ALGOS, message+messageLength);

  messageLength+=build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message+messageLength);
  messageLength+=build_name_list(NO_MAC_ALGOS, MAC_ALGOS, message+messageLength);

  messageLength+=build_name_list(NO_COM_ALGOS, COM_ALGOS, message+messageLength);
  messageLength+=build_name_list(NO_COM_ALGOS, COM_ALGOS, message+messageLength);

  int_to_bytes(0, message+messageLength);
  int_to_bytes(0, message+messageLength+4);
  messageLength+=8;

  message[messageLength++]=0;

  int_to_bytes(0, message+messageLength);
  messageLength+=4;

  packet p = build_packet(message, messageLength);

  return p;
}
