#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>

//struct socks {int sock1; int sock2;};

void sigpipe_handler(int a) {
  fprintf(stderr, "SIGPIPE error\n");
}

void *forwarder(void *args) {

  sigaction(SIGPIPE, &(struct sigaction){sigpipe_handler}, NULL);

  struct socks {int sock1; int sock2;} con = *((struct socks *)args);
  while(1) {
    char *buffer = malloc(1024);
    int recvd_bytes = recv(con.sock1, buffer, 1024, 0);
    //printf("Receieved message\n");
    //for(int i=0; i<recvd_bytes; i++) {
    //  printf("%c", buffer[i]);
    //}
    //printf("\n");
    if(recvd_bytes <= 0) break;
    int sent_bytes = send(con.sock2, buffer, recvd_bytes, 0);
    if(sent_bytes < recvd_bytes) break;
    free(buffer);
  }
  printf("Connection closed\n");
  return NULL;
}

void *start_connection(void *args) {
  int local_sock = *(int *)args;
  //printf("Received new connection\n");
  int read_bytes;
  uint8_t *buffer = malloc(3);
  read_bytes = recv(local_sock, buffer, 3, 0);
  if(!(read_bytes == 3 && buffer[0] == 5 && buffer[1] == 1 && buffer[2] == 0)) {
    printf("Unexpected first message\n");
    return NULL;
  }
  free(buffer);
  uint8_t send_bytes[2] = {5, 0};
  send(local_sock, send_bytes, 2, 0);
  buffer = malloc(10);
  read_bytes = recv(local_sock, buffer, 10, 0);
  if(read_bytes!=10 || buffer[0] != 5 || buffer[1]!=1 || buffer[2]!=0 ||
      buffer[3] != 1) {
    printf("Unexpected connection message\n");
    return NULL;
  }
  char *address_name = malloc(16);
  sprintf(address_name, "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
      buffer[4], buffer[5], buffer[6], buffer[7]);
  uint16_t port = (((uint16_t)buffer[8])<<8) + ((uint8_t)buffer[9]);
  //printf("Connection requested to %s:%"PRIu16"\n", address_name, port);

  free(buffer);

  struct sockaddr_in forward_port;
  memset(&forward_port, 0, sizeof forward_port);
  forward_port.sin_family = AF_INET;
  forward_port.sin_port = htons(port);
  forward_port.sin_addr.s_addr = inet_addr(address_name);
  free(address_name);
  int remote_sock = socket(AF_INET, SOCK_STREAM, 0);
  connect(remote_sock, (struct sockaddr *)&forward_port, sizeof(struct sockaddr_in));

  //printf("Connected to remote location\n");

  uint8_t response[10] = {5, 0, 0, 1, 127, 0, 0, 1, 19, 136};

  send(local_sock, response, 10, 0);

  struct socks{int sock1; int sock2;} con = {local_sock, remote_sock};
  pthread_t local_listener, remote_listener;
  pthread_create(&local_listener, NULL, forwarder, (void *)&con);
  struct socks con2 = {remote_sock, local_sock};
  pthread_create(&remote_listener, NULL, forwarder, (void *)&con2);

  printf("Opened connection\n");

  pthread_join(local_listener, NULL);
  pthread_join(remote_listener, NULL);

  return NULL;
}

int socks() {

  signal(SIGPIPE, NULL);

  int server_bind = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(5000);
  bind(server_bind, (struct sockaddr *)&address, sizeof(address));

  int addrlen = sizeof(address);
  listen(server_bind, 3);

  pthread_t *thread = malloc(1000*sizeof(pthread_t));
  int i=0;

  while(1) {
    int sock = accept(server_bind, (struct sockaddr*)&address, (socklen_t*)&addrlen); 
    pthread_create(&thread[i++], NULL, start_connection, (void *)&sock);
  }
}
