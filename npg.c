#include <stdio.h>
#include <sodium.h>
#include <string.h>

#define CHUNK_SIZE 4096

#define CONTEXT	"TESTING"

#define MAXSIZE	100	
static int
npg_encrypt(const char *target_file, const char *source_file,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE          *fp_t, *fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    } while (! eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int
npg_decrypt(const char *target_file, const char *source_file,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE          *fp_t, *fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
            goto ret; /* premature end (end of file reached before the end of the stream) */
        }
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    } while (! eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

void npg_genkeys(unsigned char * pk,unsigned char *sk)	{
	
	if (crypto_box_keypair(pk,sk) == -1)	{
		
		fprintf(stderr,"Error:Public-private key verification failed\n");

		return;
	}

}

void npg_format_pwd(unsigned char*c,const unsigned char * m,const unsigned long long int mlen,const unsigned char * n,const unsigned char*pk,const unsigned char*sk)	{

	if ( crypto_box_easy(c,m,mlen,n,pk,sk) == -1)	{
		
		fprintf(stderr,"Error:Failed to encrypt randomized key with public key\n");

		exit(1);

	}

}

int
main(int argc,char**argv)
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    if (sodium_init() != 0) {
        return 1;
    }

	unsigned char dest[2048];

	memcpy(dest,argv[1],strnlen(argv[1],2048));	
	strncat(dest,".npg\0",strnlen(dest,2048));
	
	unsigned char publickey[64]; 

	memset(publickey,0x0,64);

	unsigned char secretkey[64];
	
	memset(secretkey,0x0,64);

	npg_genkeys(publickey,secretkey);

	unsigned char encryption_subkey[64];

	unsigned char signature_subkey[64];

	crypto_kdf_derive_from_key(encryption_subkey,64,1,CONTEXT,secretkey);	
	
	crypto_kdf_derive_from_key(signature_subkey,64,2,CONTEXT,secretkey);	
	
	size_t i = 0;
	
	printf("Printing Encryption Subkey:\n");	
	
		while ( i < 64 )	{
		
		if ( i%32 == 0){putchar(0xa);putchar(0xa);}		

		printf("%.2x|",encryption_subkey[i]);
		
		i++;
	}	
	
	i = 0;
	
	putchar(0xa);putchar(0xa);

	printf("Printing Signature Subkey:\n");	

		while ( i < 64 )	{
		
		if ( i%32 == 0){putchar(0xa);putchar(0xa);}		

		printf("%.2x|",signature_subkey[i]);
		
		i++;
	}	
	
	putchar(0xa);	
	
	i = 0;
	
		unsigned char out[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	
		memset(out,0x0,crypto_pwhash_STRBYTES);
		
		sodium_mlock(out,crypto_pwhash_STRBYTES);
		unsigned char salt[crypto_pwhash_SALTBYTES];

		memset(salt,0x0,crypto_pwhash_SALTBYTES);

		sodium_mlock(salt,crypto_pwhash_SALTBYTES);

		unsigned char pwd[MAXSIZE+1];
	
		memset(pwd,0x0,MAXSIZE+1);
		
		sodium_mlock(pwd,MAXSIZE*sizeof(unsigned char));

		randombytes_buf(pwd,MAXSIZE);
		
		i = 0;
		
		if(crypto_pwhash(out,crypto_pwhash_STRBYTES,pwd,strnlen(pwd,MAXSIZE),salt,crypto_pwhash_OPSLIMIT_INTERACTIVE,crypto_pwhash_MEMLIMIT_INTERACTIVE,crypto_pwhash_ALG_DEFAULT) != 0)	{
				
				fprintf(stderr,"Error: Ran out of memory for pwhash\n");

				exit(1);
			}
		i = 0;
		printf("Printing argon2id hash of password that has length:%llu\n",crypto_pwhash_STRBYTES);

		while ( i < crypto_secretstream_xchacha20poly1305_KEYBYTES ) {
			
			printf("%.2x|",out[i]);
	
			i++;
		}		
	
	putchar(0xa);
	
	printf("Length of keybytes:%llu\n",crypto_secretstream_xchacha20poly1305_KEYBYTES);				
	if (npg_encrypt(dest,argv[1],out) != 0)	{

		fprintf(stderr,"Error:Failed to encrypt file\n");
		exit(1);
	}
	
	if (npg_decrypt("restore.txt",dest,out) != 0)	{

		fprintf(stderr,"Error:Failed to decrypt file\n");
		exit(1);
	}
	
	unsigned char cpk_pwd[crypto_box_MACBYTES + MAXSIZE+1];
	
	unsigned char nonce[crypto_box_NONCEBYTES];

	memset(cpk_pwd,0x0,crypto_box_MACBYTES+MAXSIZE+1);

	memset(nonce,0x0,crypto_box_NONCEBYTES);

	npg_format_pwd(cpk_pwd,pwd,MAXSIZE+1,nonce,publickey,encryption_subkey);

	i = 0;
	
	printf("Printing public key-encryption-subkey authenticated password whose length is %llu:\n",crypto_box_MACBYTES+MAXSIZE+1);
	
	while ( i < (crypto_box_MACBYTES + MAXSIZE + 1) )	{
		
		if(i%32==0){putchar(0xa);}
	
		printf("%.2x|",cpk_pwd[i]);

		i++;

	}
	
	i = 0;
	
	return 0;
}
