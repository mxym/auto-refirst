#include <stdint.h>
static const char child_name[] = "auto-refirst-public-runtime-child";
static volatile uint32_t parent_marker = 0x50415245u;
int main(void) { return (parent_marker == 0x50415245u && child_name[0]=='a') ? 0 : 3; }
