#include "myssh.h"

const char *VERSION = "myssh_0.1.1";

const char *NONE = "none";

const uint32_t NO_KEX_ALGOS = 1;
const char *KEX_ALGOS[] = {"diffie-hellman-group14-sha256"};

const uint32_t NO_KEY_ALGOS = 1;
const char *KEY_ALGOS[] = {"rsa-sha2-256"};

const uint32_t NO_ENC_ALGOS = 1;
const char *ENC_ALGOS[] = {"aes256-ctr"};

const uint32_t NO_MAC_ALGOS = 1;
const char *MAC_ALGOS[] = {"hmac-sha2-256"};

const uint32_t NO_COM_ALGOS = 1;
const char *COM_ALGOS[] = {"none"};
