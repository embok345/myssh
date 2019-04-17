#include "myssh.h"

char getch() {
  char buf = 0;
  struct termios old = {0};
  if(tcgetattr(0, &old) < 0)
    perror("tcsetattr()");
  old.c_lflag &= ~ICANON;
  old.c_lflag &= ~ECHO;
  old.c_cc[VMIN] = 1;
  old.c_cc[VTIME] = 0;

  if(tcsetattr(0, TCSANOW, &old) < 0)
    perror("tcsetattr ICANON");
  if(read(0, &buf, 1) < 0)
    perror("read()");

  old.c_lflag |= ICANON;
  old.c_lflag |= ECHO;

  if(tcsetattr(0, TCSADRAIN, &old) < 0)
    perror("tcsetattr ~ICANON");

  return buf;
}

uint8_t isdigit_s(const char *in) {
  uint32_t in_len = strlen(in);
  for(int i=0; i<in_len; i++) {
    if(!isdigit(in[i])) return 0;
  }
  return 1;
}

void int_to_bytes(uint32_t in, uint8_t *out) {
  out[0] = (in>>24)%256;
  out[1] = (in>>16)%256;
  out[2] = (in>>8)%256;
  out[3] = in%256;
}
uint32_t bytes_to_int(const uint8_t* bytes) {
  uint32_t out = bytes[0];
  out = (out<<8) + bytes[1];
  out = (out<<8) + bytes[2];
  out = (out<<8) + bytes[3];
  return out;
}
void long_to_bytes(uint64_t in, uint8_t* out) {
  out[0] = (in>>56)%256;
  out[1] = (in>>48)%256;
  out[2] = (in>>40)%256;
  out[3] = (in>>32)%256;
  out[4] = (in>>24)%256;
  out[5] = (in>>16)%256;
  out[6] = (in>>8)%256;
  out[7] = in%256;
}
