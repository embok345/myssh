#ifndef MYSSH_ENC_H
#define MYSSH_ENC_H

#include "byte_array.h"

void aes_ctr(const byte_array_t, const byte_array_t,
    byte_array_t, byte_array_t*);

void aes_cbc(const byte_array_t, const byte_array_t,
    byte_array_t, byte_array_t*);
void inv_aes_cbc(const byte_array_t, const byte_array_t,
    byte_array_t, byte_array_t*);

#endif
