#include <inttypes.h>

char getch();
uint8_t isdigit_s(const char *);
void int_to_bytes(uint32_t, uint8_t*);
uint32_t bytes_to_int(const uint8_t *);
void long_to_bytes(uint64_t, uint8_t*);

