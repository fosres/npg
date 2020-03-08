#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

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
		
		fprintf(stderr,"Error:Public-private key generation failed\n");

		return;
	}

}

void npg_format_pwd(unsigned char*c,const unsigned char * m,const unsigned long long int mlen,const unsigned char * n,const unsigned char*pk,const unsigned char*sk)	{

	if ( crypto_box_easy(c,m,mlen,n,pk,sk) == -1)	{
		
		fprintf(stderr,"Error:Failed to encrypt randomized key with public key\n");

		exit(1);

	}

}

void mac_message(unsigned char*c,const unsigned char * m,const unsigned long long int mlen,const unsigned char * n,const unsigned char*pk,const unsigned char*sk)	{

	if ( crypto_box_easy(c,m,mlen,n,pk,sk) == -1)	{
		
		fprintf(stderr,"Error:Failed to encrypt randomized key with public key\n");

		exit(1);

	}

}
void npg_open_pwd(unsigned char*m,const unsigned char *c,unsigned long long clen,const unsigned char *n,const unsigned char * pk,const unsigned char *sk)	{

	if ( crypto_box_open_easy(m,c,clen,n,pk,sk) == -1 )	{
		fprintf(stderr,"Error:Failed to decrypt npg_password\n");

		exit(1);

	}	


}

unsigned char * file_to_arr(unsigned char*filename,unsigned long long int * file_len)	{
	
	FILE * in = 0;

	if ( (in = fopen(filename,"rb")) == NULL )	{
		fprintf(stderr,"Error:Failed to read file\n");
		fclose(in);

		exit(1);

	}

	fseek(in,0L,SEEK_END);

	*file_len = ftell(in);

	rewind(in);	

	unsigned char * dest = (unsigned char *)calloc(*file_len,sizeof(unsigned char));

	if ( fread(dest,1,*file_len,in) != (*file_len) )	{
		fprintf(stderr,"Error:Failed to copy file into array\n");
		
		fclose(in);

		free(dest);

		exit(1);

	}
	
	fclose(in);

	return dest;
}

void sign_message(unsigned char *sig,unsigned long long *siglen_p,const unsigned char * m,unsigned long long mlen,const unsigned char *sk)	{
	
	if (crypto_sign_detached(sig,siglen_p,m,mlen,sk)==-1)
	{
		fprintf(stderr,"Error:sign_message returned -1. Digital Signature may have failed\n");
	}

}

int verify_signed_message(unsigned char*m,unsigned long long int *mlen_p,const unsigned char *sm,unsigned long long int smlen,const unsigned char*pk)	{

	if (crypto_sign_open(m,mlen_p,sm,smlen,pk)==-1)		{
		fprintf(stderr,"Error:Failed to verify signed message. WARNING: There is a chance someone is trying to do something NASTY!!!\n");

		exit(1);	

	}

	else							{

		printf("Congrats, message verified\n");
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
	
	unsigned char publickey[crypto_box_PUBLICKEYBYTES]; 

	memset(publickey,0x0,crypto_box_PUBLICKEYBYTES);

	unsigned char secretkey[crypto_box_SECRETKEYBYTES];
	
	memset(secretkey,0x0,crypto_box_SECRETKEYBYTES);
	

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

	npg_format_pwd(cpk_pwd,pwd,MAXSIZE+1,nonce,publickey,signature_subkey);

	i = 0;
	
	printf("Printing public key-encryption-subkey authenticated password whose length is %llu:\n",crypto_box_MACBYTES+MAXSIZE+1);
	
	unsigned char * open_cpk_pwd = (unsigned char*)calloc(MAXSIZE+1,sizeof(unsigned char));
	
	npg_open_pwd(open_cpk_pwd,cpk_pwd,MAXSIZE+1+crypto_box_MACBYTES,nonce,publickey,signature_subkey);

	printf("Printing pwd:\n");

	i = 0;

	while ( i < (MAXSIZE+1) )	{
		if (i%32==0){putchar(0xa);}
		
		printf("%.2x|",pwd[i]);
	
		i++;

	}
	
	i = 0;

	putchar(0xa);
	
	printf("Printing open_cpk_pwd:\n");

	
	while ( i < (MAXSIZE+1) )	{
		if (i%32==0){putchar(0xa);}
		
		printf("%.2x|",open_cpk_pwd[i]);
	
		i++;

	}

	putchar(0xa);
	
	
	i = 0;
	
	unsigned long long int file_arr_len = 0;	
	
	unsigned char * file_arr = file_to_arr(argv[1],&file_arr_len);

	printf("file_arr_len:%llu\n",file_arr_len);

	unsigned long long int file_arr_signed_len = 0;	
		
	unsigned char * file_arr_signed = (unsigned char*)calloc(file_arr_signed_len,sizeof(unsigned char));

	unsigned char file_sig[crypto_sign_BYTES];

	memset(file_sig,0x0,crypto_sign_BYTES*sizeof(unsigned char));

	unsigned char * file_arr_recipient = (unsigned char*)calloc(file_arr_signed_len,sizeof(unsigned char));

	unsigned long long int file_arr_recipient_len = 0;


//	sign_message(file_sig,&file_arr_signed_len,file_arr,file_arr_len,secretkey);	
	
	unsigned char sign_input[5] = "This\0";	
	
	unsigned char sign_publickey[crypto_sign_PUBLICKEYBYTES];

	unsigned char sign_secretkey[crypto_sign_SECRETKEYBYTES];
	
	memset(sign_publickey,0x0,crypto_sign_PUBLICKEYBYTES*sizeof(unsigned char));

	memset(sign_secretkey,0x0,crypto_sign_SECRETKEYBYTES*sizeof(unsigned char));
	
	crypto_sign_keypair(sign_publickey,sign_secretkey);

	if (crypto_sign_detached(file_sig,NULL,file_arr,file_arr_len,sign_secretkey) == -1 )	{
		
		fprintf(stderr,"Error:crypto_sign_detached returned -1\n");

		exit(1);

	}	

	i = 0;

	printf("File signature size is:%llu\n",file_arr_signed_len);
	
	printf("Printing file signature\n");
	
	while ( i < file_arr_signed_len )	{
		
		printf("%.2x|",file_sig[i]);

		i++;
	}
	
	putchar(0xa);
#if 0
	verify_signed_message(file_arr_recipient,&file_arr_recipient_len,file_arr_signed,file_arr_signed_len,publickey);	
#endif
	printf("file_arr_len is %llu\n",file_arr_len);

	printf("Verifying crypto_signature\n");

	if ( crypto_sign_verify_detached(file_sig,file_arr,file_arr_len,sign_publickey) != 0 )	{
		
		fprintf(stderr,"Error:Signed message verification failed!\n");

	}

	else											{
		printf("Congrats: Verification of signature worked\n");

	}
	
	i = 0;
	
	printf("file_arr_recipient_len:%llu\n",file_arr_recipient_len);
	
	printf("Printing file_arr_recipient_byte contents:\n");

	while ( i < file_arr_recipient_len )	{
		
		printf("%.2x|",file_arr_recipient[i]);

		i++;
	}
	
	free(file_arr);	
	
	free(file_arr_signed);			
	
	free(file_arr_recipient);

	return 0;
}
