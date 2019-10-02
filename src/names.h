#ifndef MYSSH_NAMES_H
#define MYSSH_NAMES_H

#include <inttypes.h>

extern const char *VERSION;

extern const char *NONE;

extern const uint32_t NO_KEX_C_ALGOS;
extern const char *KEX_DH_GP14_SHA256;
extern const char *KEX_C_ALGOS[];

extern const uint32_t NO_KEY_C_ALGOS;
extern const char *KEY_RSA_SHA2_256;
extern const char *KEY_C_ALGOS[];

extern const uint32_t NO_ENC_ALGOS;
extern const char *ENC_AES256_CTR;
extern const char *ENC_AES192_CTR;
extern const char *ENC_AES128_CTR;
extern const char *ENC_ALGOS[];

extern const uint32_t NO_MAC_ALGOS;
extern const char *MAC_HMAC_SHA256;
extern const char *MAC_ALGOS[];

extern const uint32_t NO_COM_ALGOS;
extern const char *COM_ALGOS[];

extern const char *AUTH_PUBKEY;
extern const char *AUTH_PASSWD;
extern const char *AUTH_HOST;
extern const char *AUTH_INTERACTIVE;

#endif
