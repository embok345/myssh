#include "myssh.h"

//TODO comment

int base64_to_byteArray(const char *in, byte_array_t *out) {
  if(strlen(in)%4!=0)
    return 1;
  out->arr = malloc((strlen(in)/4)*3);
  uint32_t num = 0;
  int padding = 0;
  for(int j=0; j<strlen(in)/4; j++) {
    for(int i=0; i<4; i++) {
      //printf("4*j + i = %d\n", 4*j+i);
      num<<=6;
      if(isalpha(in[4*j + i]) && isupper(in[4*j + i])) {
        num+=in[4*j + i] - 'A';
      } else if(isalpha(in[4*j + i]) && islower(in[4*j + i])){
        num+=in[4*j + i] - 'a' + 26;
      } else if(isdigit(in[4*j + i])) {
        num+=in[4*j + i] - '0' + 52;
      } else if(in[4*j + i] == '+') {
        num+=62;
      } else if(in[4*j + i] == '/') {
        num+=63;
      } else if(in[4*j + i] == '=') {
        padding++;
      } else return 1;
    }
    //printf("These 4 characters: %"PRIu32"\n", num);
    switch(padding) {
      case 0: out->arr[(3*j) + 2] = num%256;
      case 1: out->arr[(3*j) + 1] = (num>>8)%256;
      case 2:
      case 3: out->arr[(3*j)] = (num>>16)%256;
      default: num=0;

    }
  }
  out->len = (strlen(in)/4) * 3;
  switch(padding) {
    case 3: out->len--;
    case 2: out->len--;
    case 1: out->len--;
  }
  return 0;
}


int32_t decode_der_string(const byte_array_t in, der_val_t **out) {
  *out = malloc(0*sizeof(der_val_t));
  int32_t no_elements = 0;
  for(int i=0; i<in.len; i++) {
    switch(in.arr[i]) {

      case 1: //Boolean
        if(i+2 >= in.len)  return -1;
        *out = realloc(*out, (++no_elements) * sizeof(der_val_t));
        if(in.arr[i+1]!=1) return -1;
        ((*out)[no_elements-1]).type = 1;
        ((*out)[no_elements-1]).value = malloc(sizeof(void *));
        *((int8_t *)((*out)[no_elements-1]).value) = (in.arr[i+2]==0) ? 0 : 1;
        i+=2;
        break;

      case 2: //Int
        if(i+1 >= in.len) return -1;
        uint32_t int_length = 0;
        uint8_t int_length_length = 0;
        if(in.arr[i+1] >= 128) {
          int_length_length = in.arr[i+1] - 128;
          if(int_length_length > 4) {
            printf("This integer is far too long lul\n");
            return -1;
          }
          if(i+1+int_length_length >= in.len) return -1;
          for(int j=0; j<int_length_length; j++) {
            int_length<<=8;
            int_length+=in.arr[i+2+j];
          }
        } else {
          int_length = in.arr[i+1];
        }
        i += int_length_length + 2;

        if(i+int_length > in.len) return -1;

        der_int_t *new_int;
        new_int = malloc(sizeof(der_int_t));
        if(int_length <= 1) {
          new_int->type = 1;
          new_int->value = malloc(sizeof(void *));
          *((int8_t *)new_int->value) = in.arr[i];
        } else if(int_length <= 4) {
          new_int->type = 2;
          new_int->value = malloc(sizeof(void *));
          *((int32_t *)new_int->value) = 0;
          for(int j=0; j<int_length; j++) {
            *((int32_t *)new_int->value) <<= 8;
            *((int32_t *)new_int->value) += (int32_t)in.arr[i+j];
          }
        } else if(int_length <= 8) {
          new_int->type = 3;
          new_int->value = malloc(sizeof(void *));
          *((int64_t *)new_int->value) = 0;
          for(int j=0; j<int_length; j++) {
            *((int64_t *)new_int->value) <<= 8;
            *((int64_t *)new_int->value) += (int64_t)in.arr[i+j];
          }
        } else {
          new_int->type = 4;
          new_int->value = malloc(sizeof(void *));
          bignum *new_bn;
          bn_init(&new_bn);
          bn_resize(new_bn, int_length);
          if(in.arr[i] >= 128) {
            bn_setnegative(new_bn);
            int j=0;
            while(in.arr[i+int_length-j-1] == 0 && j<int_length) {
              bn_setBlock(new_bn, j, in.arr[i + int_length - j - 1]);
              j++;
            }
            uint8_t currentBlock = in.arr[i+int_length-j-1];
            uint8_t newBlock = 0;
            int k=0;
            for(; k<8; k++) {
              if((currentBlock>>k)%2 == 1) {
                newBlock+=(1<<k);
                break;
              }
            }
            for(; k<8; k++) {
              if((currentBlock>>k)%2 == 0)
                newBlock+=(1<<k);
            }
            bn_setBlock(new_bn, j++, newBlock);
            for(; j<int_length; j++) {
              bn_setBlock(new_bn, j, ~(in.arr[i+int_length-j-1]));
            }

          } else {
            for(int j=0; j<int_length; j++) {
              bn_setBlock(new_bn, int_length-j-1, in.arr[i+j]);
            }
          }
          new_int->value = (void *)new_bn;
        }

        *out = realloc(*out, (++no_elements) * sizeof(der_val_t));
        ((*out)[no_elements-1]).type = 2;
        ((*out)[no_elements-1]).value = (void *)new_int;

        i+=int_length-1;

        break;

      case 3: //Bit string
        break;

      case 5: //Null
        if(i+1 >= in.len) return -1;
        if(in.arr[i+1] != 0) return -1;
        *out = realloc(*out, (++no_elements)*sizeof(der_val_t));
        ((*out)[no_elements-1]).type = 5;
        ((*out)[no_elements-1]).value = NULL;
        i+=1;
        break;

      case 6: //OID

        if(i+1 >= in.len) return -1;
        uint32_t oid_length = 0;
        uint8_t oid_length_length = 0;
        if(in.arr[i+1] >= 128) {
          oid_length_length = in.arr[i+1] - 128;
          if(oid_length_length > 4) {
            printf("This oid is far too long lul\n");
            return -1;
          }
          if(i+1+oid_length_length >= in.len) return -1;
          for(int j=0; j<oid_length_length; j++) {
            oid_length<<=8;
            oid_length+=in.arr[i+2+j];
          }
        } else {
          oid_length = in.arr[i+1];
        }
        i += oid_length_length + 2;

        if(i+oid_length > in.len) return -1;

        byte_array_t *oid = malloc(sizeof(byte_array_t));
        oid->len = oid_length;
        oid->arr = malloc(oid->len);
        memcpy(oid->arr, in.arr + i, oid_length);
        *out = realloc(*out, (++no_elements)*sizeof(der_val_t));
        ((*out)[no_elements-1]).type = 6;
        ((*out)[no_elements-1]).value = (void *)oid;
        i+=oid_length - 1;
        break;


      case 0x30: //Sequence
      case 4:    //Byte string  -- They seem to be essentially the same thing.

        if(i+1 >= in.len) return -1;
        uint32_t seq_length = 0;
        uint8_t seq_length_length = 0;
        if(in.arr[i+1] >= 128) {
          seq_length_length = in.arr[i+1] - 128;
          if(seq_length_length > 4) {
            printf("This sequence is far too long lul\n");
            return -1;
          }
          if(i+1+seq_length_length >= in.len) return -1;
          for(int j=0; j<seq_length_length; j++) {
            seq_length<<=8;
            seq_length+=in.arr[i+2+j];
          }
        } else {
          seq_length = in.arr[i+1];
        }
        i += seq_length_length + 2;

        if(i+seq_length > in.len) return -1;

        byte_array_t sub_arr;
        sub_arr.len = seq_length;
        sub_arr.arr = malloc(sub_arr.len);
        memcpy(sub_arr.arr, in.arr+i, seq_length);
        der_val_t *sub_vals;

        int32_t no_sub_vals = decode_der_string(sub_arr, &sub_vals);

        if(no_sub_vals == -1) return -1;

        der_seq_t *seq = malloc(sizeof(der_seq_t));
        seq->no_elements = no_sub_vals;
        seq->elements = sub_vals;

        *out = realloc(*out, (++no_elements) * sizeof(der_val_t));
        ((*out)[no_elements-1]).type = 0x30;
        ((*out)[no_elements-1]).value = (void *)seq;

        i+=seq_length-1;

        break;

      default: return -1;

    }
  }
  return no_elements;
}

void print_der_val(const der_val_t der) {
  if(der.type == 1) {
    if(*((int *)der.value) == 0) {
      printf("Boolean :: False\n");
    } else {
      printf("Boolean :: True\n");
    }
  }
  else if(der.type == 2) {
    der_int_t der_int = *((der_int_t *)der.value);
    switch(der_int.type) {
      case 1:
        printf("Integer :: %"PRId8"\n", *((uint8_t *)der_int.value));
        break;
      case 2:
        printf("Integer :: %"PRId32"\n", *((uint32_t *)der_int.value));
        break;
      case 3:
        printf("Integer :: %"PRId64"\n", *((uint64_t *)der_int.value));
        break;
      case 4:
        printf("Integer :: ");bn_prnt_dec((bignum *)der_int.value);
        break;
      default:
        printf("Unrecognized integer\n");
    }
  }
  else if(der.type == 5) {
    printf("null :: ");
  }
  else if(der.type == 6) {
    printf("OID :: i don't care lul\n");

  }
  else if(der.type == 0x30 || der.type == 4) {
    der_seq_t seq = *((der_seq_t*)der.value);
    printf("Sequence :: {\n");
    for(int i = 0; i<seq.no_elements; i++) {
      printf("  ");print_der_val(seq.elements[i]);
    }
    printf("}\n");
  } else {
    printf("Unknown Id: %"PRIu8"\n", der.type);
  }
}
/*
int main() {
  byte_array_t private_key_bytes;
  base64_to_byteArray(private_key, &private_key_bytes);
  der_val_t *vals;
  int32_t no_vals = decode_der_string(private_key_bytes, &vals);
  if(no_vals < 0) {
    printf("Something went wrong\n");
    return 1;
  }
  for(int i=0; i<no_vals; i++) {
    print_der_val(vals[i]);
  }
}*/
