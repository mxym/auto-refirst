#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int prts_zstd_decompress_frame(const void *src,size_t src_size,unsigned char **out,size_t *out_size,size_t *frame_size);
int prts_zstd_decompress_frame_limited(const void *src,size_t src_size,size_t max_output,unsigned char **out,size_t *out_size,size_t *frame_size,unsigned long long *decompressed_bound,int *limit_hit);
void prts_zstd_free(void *p);
#ifdef __cplusplus
}
#endif
