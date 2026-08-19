#include <stdint.h>
static volatile uint32_t child_marker = 0x4348494cu;
int main(void) { return child_marker == 0x4348494cu ? 0 : 2; }
