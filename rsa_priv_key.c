#include "myssh.h"

int inv_aes_cbc(const byte_array_t, const byte_array_t, byte_array_t*, byte_array_t*);
void md5(const byte_array_t in, byte_array_t *);

int get_priv_key(int argc, char *argv[]) {

  if(argc < 3) return 1;

  const char *priv_key_pwd = argv[2];
  const char *priv_key_name = argv[1];

  FILE *fp;
  fp = fopen(priv_key_name, "r");
  if(!fp) return 1;
  char line[200];
  if(!fgets(line, sizeof line, fp)) return 1;
  if(strcmp(line, "-----BEGIN RSA PRIVATE KEY-----\n") != 0) return 1;

  if(!fgets(line, sizeof line, fp)) return 1;
  if(strcmp(line, "Proc-Type: 4,ENCRYPTED\n") != 0) return 1;

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
  char *iv = malloc(strlen(line) - break_point-1);
  strncpy(dek_mode, line + 10, break_point-10);
  dek_mode[break_point-10] = '\0';
  strncpy(iv, line+break_point+1, strlen(line)-break_point-2);
  iv[strlen(line)-break_point-2] = '\0';

  printf("%s\n%s\n", dek_mode, iv);

  char *key_contents = NULL;
  uint32_t key_contents_len = 0;
  while(fgets(line, sizeof line, fp)) {
    if(strcmp(line, "-----END RSA PRIVATE KEY-----\n") == 0) break;
    key_contents = realloc(key_contents, key_contents_len + strlen(line));
    memcpy(key_contents + key_contents_len, line, strlen(line)-1);
    key_contents[key_contents_len + strlen(line) - 1] = '\0';
    key_contents_len += strlen(line) - 1;
  }

  byte_array_t key_val;
  base64_to_byteArray(key_contents, &key_val);

  byte_array_t iv_arr;
  iv_arr.len = strlen(iv)/2;
  iv_arr.arr = malloc(iv_arr.len);
  for(int i=0; i<strlen(iv)/2; i++) {
    if(isdigit(iv[i*2])) {
      iv_arr.arr[i] = (iv[i*2]-'0')<<4;
    } else if(isxdigit(iv[i*2])) {
      if(isupper(iv[i*2])) {
        iv_arr.arr[i] = (iv[i*2]-'A'+10)<<4;
      } else
        iv_arr.arr[i] = (iv[i*2]-'a'+10)<<4;
    } else return 1;

    if(isdigit(iv[(2*i)+1])) {
      iv_arr.arr[i] += (iv[(2*i)+1]-'0');
    } else if(isxdigit(iv[(2*i)+1])) {
      if(isupper(iv[(2*i)+1]))
        iv_arr.arr[i] += (iv[(2*i)+1]-'A'+10);
      else
        iv_arr.arr[i] += (iv[(2*i)+1]-'a'+10);
    } else return 1;

  }

  byte_array_t encryption_key;
  encryption_key.len = strlen(priv_key_pwd) + 8;
  encryption_key.arr = malloc(encryption_key.len);
  memcpy(encryption_key.arr, priv_key_pwd, strlen(priv_key_pwd));
  memcpy(encryption_key.arr + strlen(priv_key_pwd), iv_arr.arr, 8);

  byte_array_t hashed_passwd;
  md5(encryption_key, &hashed_passwd);

  byte_array_t decrypted_key;
  inv_aes_cbc(key_val, hashed_passwd, &iv_arr, &decrypted_key);

  for(int i=0; i<decrypted_key.len; i++) {
    printf("%x ", decrypted_key.arr[i]);
  }
  printf("\n");


  free(key_contents);
  free(dek_mode);
  free(iv);
  free(key_val.arr);
  fclose(fp);
}
