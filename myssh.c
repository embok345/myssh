#include "myssh.h"
#include <pwd.h>
#include <sys/types.h>

const char *LOG_NAME = "/home/poulter/myssh/log.log";

uint8_t get_host(const char *arg,
    char **uname, struct sockaddr_in *host) {
  uint32_t arg_len = strlen(arg);
  uint32_t host_name_start = 0;
  uint32_t host_name_end = arg_len - 1;
  for(int i=0; i<arg_len; i++) {
    if(arg[i] == '@') {
      //If we reach @, we have maybe reached the end of the username
      if(i == 0 || i==arg_len - 1 || host_name_start != 0) {
        //If @ is the first or last character, or we have already come across
        //a @, it is not valid
        return 1;
      }
      //Otherwise, extract it
      *uname = realloc(*uname, i+1);
      memcpy(*uname, arg, i);
      (*uname)[i] = '\0';
      host_name_start = i+1;
    }
    if(arg[i] == ':') {
      //If we reach : we have maybe reached the beginning of the port
      if(i == 0 || i == arg_len - 1) {
        //If it is the first or last character, it is not valid
        return 1;
      }
      char *port_str = malloc(arg_len - i);
      memcpy(port_str, arg+i+1, arg_len - i);
      if(!isdigit_str(port_str) || strlen(port_str) > 5) {
        free(port_str);
        return 1;
      }
      uint32_t port_int = atoi(port_str);
      free(port_str);
      if(port_int > 1<<16) {
        return 1;
      }
      host->sin_port = htons((uint16_t)port_int);
      host_name_end = i-1;
      break;
    }
  }

  uint32_t host_name_len = host_name_end - host_name_start + 1;
  if(host_name_len < 4)
    //Minumum length could by x.xx
    return 1;
  char *host_name = malloc(host_name_len + 1);
  memcpy(host_name, arg + host_name_start, host_name_len);
  host_name[host_name_len] = '\0';

  struct addrinfo hints, *res;
  char host_name_ip[NI_MAXHOST];
  memset(&hints, 0, sizeof hints);
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if(getaddrinfo(host_name, NULL, &hints, &res)) {
    free(host_name);
    return 1;
  }
  for(struct addrinfo *p = res; p; p = p->ai_next) {
    if(getnameinfo(p->ai_addr, p->ai_addrlen, host_name_ip,
        sizeof(host_name_ip), NULL, 0, NI_NUMERICHOST)) {
      freeaddrinfo(res);
      free(host_name);
      return 1;
    }
    host->sin_addr.s_addr = inet_addr(host_name_ip);
  }

  freeaddrinfo(res);
  free(host_name);

  return 0;
}

int main(int argc, char *argv[]) {

  srand(time(NULL));

  if(argc < 2) {
    fprintf(stderr, "Too few arguments\n");
    return 1;
  }

  uint32_t uname_len = strlen(getpwuid(geteuid())->pw_name);
  char *uname = malloc(uname_len + 1);
  memcpy(uname, getpwuid(geteuid())->pw_name, uname_len+1);
  struct sockaddr_in host;
  memset(&host, 0, sizeof host);
  host.sin_family = AF_INET;
  host.sin_port = htons(22);

  char *key_file;

  for(int i=1; i<argc; i++) {
    if(argv[i][0] != '-') {
      uint8_t gethost = get_host(argv[i], &uname, &host);
      if(gethost) {
        printf("Could not determine host\n");
        free(uname);
        return 1;
      }
    }
    if(strcmp(argv[i], "-k") == 0) {
      if(i+1>=argc) {
        free(uname);
        return 1;
      }
    }
  }

  int sock;
  sock = socket(AF_INET, SOCK_STREAM, 0);
  connect(sock, (struct sockaddr *)&host, sizeof(struct sockaddr_in));
  connection con = create_connection_struct(sock);

  char *v_c, *v_s;

  uint8_t version_exchange_ret = version_exchange(&con, &v_c, &v_s);
  if(version_exchange_ret) {
    fprintf(stderr, "Could not exchange versions\n");
    free_connection(con);
    free(uname);
    free(v_c);
    free(v_s);
    return 1;
  }

  start_reader(&con);

  printf("Doing kex\n");
  uint8_t kex_ret = kex(&con, v_c, v_s);
  if(kex_ret) {
    fprintf(stderr, "Could not complete kex\n");
    free_connection(con);
    free(uname);
    free(v_c);
    free(v_s);
    return 1;
  }
  printf("Done kex\n");

  //TODO change this to use the correct auth type
  uint8_t auth_ret = user_auth_publickey(&con, uname,
      "rsa-sha2-256", "../.ssh/id_rsa.pub", "../.ssh/id_rsa");
  if(auth_ret) {
    fprintf(stderr, "Could not complete auth for user %s", uname);
    free_connection(con);
    free(uname);
    free(v_c);
    free(v_s);
    return 1;
  }

  uint32_t remote_channel;
  uint8_t open_channel_ret = open_channel(&con, 10, &remote_channel);
  if(open_channel_ret) {
    fprintf(stderr, "Could not open channel\n");
    free_connection(con);
    free(uname);
    free(v_c);
    free(v_s);
    return 1;
  }

  char c;
  while(c = getch()) {
    send_channel_char(c, remote_channel, &con);
  }

  free_connection(con);

  free(uname);
  free(v_c);
  free(v_s);
  return 0;
}

/* Starts the SSH connection by sending the version string to the
 * server, and making sure we get a valid response */
uint8_t version_exchange(connection *c, char **v_c, char **v_s) {

  //Create and send the client version string
  int v_c_len = strlen(VERSION) + 11;
  *v_c = malloc(v_c_len);
  snprintf(*v_c, v_c_len, "SSH-2.0-%s\r\n", VERSION);
  send(c->socket, *v_c, v_c_len - 1, 0);

  //Initialise the server version string
  uint32_t v_s_len = 0;
  *v_s = malloc(v_s_len + 1);
  (*v_s)[0] = '\0';
  (*v_s)[1] = '\0';
  //Receive one character at a time
  //This is not really the best way to do it, but we don't know
  //how many characters there are going to be
  while(recv(c->socket, *v_s + v_s_len, 1, 0)) {
    //Resize the string to accomodate
    *v_s = realloc(*v_s, (++v_s_len)+1);
    (*v_s)[v_s_len] = '\0';
    //If the last two characters received were \r\n, we should be done
    if(v_s_len>=2 && strncmp((*v_s) + v_s_len - 2, "\r\n", 2)==0)
      break;
  }
  //If the server version string doesn't start with SSH-2.0, we can't connect
  if(strncmp(*v_s, "SSH-2.0", 7)!=0) {
    return 1;
  }

  //The spec asserts that there could be messages before the
  //version id string, but lets assume there aren't cos that
  //would be a bit silly

  return 0;
}
