#include <stdint.h>
#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif
static const uint32_t KEY[4] = {0x11223344u,0x55667788u,0x99aabbccu,0xddeeff00u};
NOINLINE static void tea_decrypt(uint32_t v[2]) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720u;
    for (unsigned i=0;i<32;i++) {
        v1-=((v0<<4)+KEY[2])^(v0+sum)^((v0>>5)+KEY[3]);
        v0-=((v1<<4)+KEY[0])^(v1+sum)^((v1>>5)+KEY[1]);
        sum+=0x61C88647u;
    }
    v[0]=v0; v[1]=v1;
}
int main(void) { uint32_t v[2]={0x89abcdefu,0x01234567u}; tea_decrypt(v); return (int)(v[0]&1u); }
