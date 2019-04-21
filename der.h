#ifndef DER_H
#define DER_H


typedef struct der_val_t {
  uint8_t type;
  void *value;
} der_val_t;

typedef der_val_t der_int_t;

typedef struct der_seq_t {
  uint32_t no_elements;
  der_val_t *elements;
} der_seq_t;

int32_t decode_der_string(const byte_array_t, der_val_t **);
void print_der_val(const der_val_t);

#endif
