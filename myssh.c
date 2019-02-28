#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include "names.h"
#include "numbers.h"

typedef struct connection {
  struct sockaddr_in socket;
  int8_t encryption;
  int8_t compression;
  int32_t sequence_number;
} connection;

typedef struct packet {
  uint32_t packet_length;
  int8_t padding_length;
  int8_t *payload;
  int8_t *padding;
  int8_t *mac;
} packet;

void *listener_thread(void *arg) {
  char *buffer = malloc(35000);
  int sock = *((int *)arg);
  int len = recv(sock, buffer, 35000, 0);
  buffer[len] = '\0';
  return (void *)buffer;
}

int kex_init(int sock) {
  char *remote_constr = NULL;
  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  char *payload = malloc(35000);
  payload[0] = SSH_MSG_KEXINIT;
  for(int i=1;i<=16;i++) {
    payload[i] = rand()%256;
  }


  return 1;
}

int init_connection(int sock) {
  char *remote_constr = NULL;
  pthread_t tid;
  pthread_create(&tid, NULL, listener_thread, (void *)&sock);

  int constr_len = strlen(VERSION)+11;
  char *constr = malloc(constr_len);
  snprintf(constr, constr_len, "SSH-2.0-%s\r\n", VERSION);
  send(sock, constr, constr_len, 0);

  pthread_join(tid, (void **)&remote_constr);
  while(strlen(remote_constr) < 4 || strncmp(remote_constr, "SSH-", 3)!=0) {
    //Then the command didn't start with "SSH-"
    //So keep listening
    free(remote_constr);
    pthread_create(&tid, NULL, listener_thread, (void *)&sock);
    pthread_join(tid, (void **)&remote_constr);
  }

  //remote_constr now starts with "SSH-"

  if(strlen(remote_constr)<8 || strncmp(remote_constr+4, "2.0-", 4)!=0) {
    //Not a valid ssh protocol version
    printf("Invalid protocol\n");
    free(constr);
    free(remote_constr);
    return 0;
  }

  printf("%s", constr);
  printf("%s", remote_constr);

  //Lets assume we can continue now.
  return 1;
}

int main() {

  srand(time(NULL));

  int sock;
  struct sockaddr_in dest;

  sock = socket(AF_INET, SOCK_STREAM, 0);

  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr("104.248.169.129");
  dest.sin_port = htons(9001);

  connect(sock, (struct sockaddr *)&dest, sizeof(struct sockaddr_in));

  if(init_connection(sock)) {
    kex_init(sock);
  }

  close(sock);
  return 0;
}
