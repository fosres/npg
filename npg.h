#ifndef __NPG_H__
#include <stdio.h>
unsigned char base64[64];

void build_decoding_table();

unsigned char * base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

void base64_cleanup();
#endif // __NPG_H__
