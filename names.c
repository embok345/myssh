#include <inttypes.h>

const char *VERSION = "myssh_0.1.1";

const char *NONE = "none";

const uint32_t NO_KEX_C_ALGOS = 1;
const char *KEX_DH_GP14_SHA256 = "diffie-hellman-group14-sha256";
const char *KEX_C_ALGOS[] = {"diffie-hellman-group14-sha256"};

const uint32_t NO_KEY_C_ALGOS = 1;
const char *KEY_RSA_SHA2_256 = "rsa-sha2-256";
const char *KEY_C_ALGOS[] = {"rsa-sha2-256"};

const uint32_t NO_ENC_ALGOS = 3;
const char *ENC_AES256_CTR = "aes256-ctr";
const char *ENC_AES192_CTR = "aes192-ctr";
const char *ENC_AES128_CTR = "aes128-ctr";
const char *ENC_ALGOS[] = {"aes256-ctr", "aes192-ctr", "aes128-ctr"};

const uint32_t NO_MAC_ALGOS = 1;
const char *MAC_HMAC_SHA256 = "hmac-sha2-256";
const char *MAC_ALGOS[] = {"hmac-sha2-256"};

const uint32_t NO_COM_ALGOS = 1;
const char *COM_ALGOS[] = {"none"};
