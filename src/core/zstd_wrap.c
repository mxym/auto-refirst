#include "prts/zstd_wrap.h"
#include <stdlib.h>
#include <string.h>
#include "../../third_party/zstd/zstddeclib.c"
int prts_zstd_decompress_frame_limited(const void *src,size_t src_size,size_t max_output,unsigned char **out,size_t *out_size,size_t *frame_size,unsigned long long *decompressed_bound,int *limit_hit){
    if(!src||!out||!out_size||src_size<6)return 0;
    *out=NULL;*out_size=0;if(frame_size)*frame_size=0;if(decompressed_bound)*decompressed_bound=0;if(limit_hit)*limit_hit=0;
    size_t fs=ZSTD_findFrameCompressedSize(src,src_size);if(ZSTD_isError(fs)||fs==0||fs>src_size)return 0;if(frame_size)*frame_size=fs;
    unsigned long long content=ZSTD_getFrameContentSize(src,fs);
    unsigned long long bound=(content!=ZSTD_CONTENTSIZE_UNKNOWN&&content!=ZSTD_CONTENTSIZE_ERROR)?content:ZSTD_decompressBound(src,fs);
    if(bound==0||bound==ZSTD_CONTENTSIZE_ERROR)return 0;
    if(decompressed_bound)*decompressed_bound=bound;
    if(bound>max_output||bound>(1ull<<31)){if(limit_hit)*limit_hit=1;return 0;}
    unsigned char *buf=(unsigned char*)malloc((size_t)bound?(size_t)bound:1);if(!buf)return 0;
    size_t got=ZSTD_decompress(buf,(size_t)bound,src,fs);if(ZSTD_isError(got)||got>max_output){free(buf);if(got>max_output&&limit_hit)*limit_hit=1;return 0;}
    *out=buf;*out_size=got;return 1;
}
int prts_zstd_decompress_frame(const void *src,size_t src_size,unsigned char **out,size_t *out_size,size_t *frame_size){
    return prts_zstd_decompress_frame_limited(src,src_size,(size_t)(1ull<<31),out,out_size,frame_size,NULL,NULL);
}
void prts_zstd_free(void*p){free(p);}
