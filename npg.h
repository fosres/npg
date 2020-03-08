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

void verify_signed_message(unsigned char*m,unsigned long long *mlen_p,const unsigned char *sm,unsigned long long smlen,const unsigned char *pk);

void npg_open_pwd(unsigned char*m,const unsigned char *c,unsigned long long clen,const unsigned char *n,const unsigned char * pk,const unsigned char *sk);

#endif // __NPG_H__
