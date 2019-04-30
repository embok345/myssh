void sha_256(const byte_array_t, byte_array_t*);
void md5(const byte_array_t, byte_array_t*);

void hmac(const byte_array_t, const byte_array_t,
    void (*)(const byte_array_t, byte_array_t*), uint8_t, byte_array_t*);
