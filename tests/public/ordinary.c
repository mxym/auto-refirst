#include <stdint.h>
static volatile uint32_t marker = 0x41595231u;
int main(void) { return marker == 0x41595231u ? 0 : 1; }
