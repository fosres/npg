#include <stdio.h>
#include <sodium.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "npg.h"
#define CHUNK_SIZE 4096

#define CONTEXT	"TESTING"

#define MAXSIZE	100	
unsigned char * decrypt_email_message(unsigned char*radix64,size_t radix64_len,unsigned char sign_publickey[crypto_sign_PUBLICKEYBYTES],unsigned char *pk,unsigned char*sk)	{
	

	size_t radix64_decoded_len = 0;

	unsigned char * radix64_decoded = base64_decode(radix64,radix64_len,&radix64_decoded_len);

	size_t i = 0,n = 0;
	
	//First Eight Octets represent length of forthcoming string for public-private key symmetric key
	
	unsigned long long length_of_public_private_symm_key= 0;

	unsigned long long int first_eight = 0;
	
	while ( i < 8 )	{
		
		first_eight += radix64_decoded[i];

		first_eight <<= 8;
		
		i++;
	} 			
	
	n = 0;

	unsigned char * pubkey_encrypted_symm_key = (unsigned char*)calloc(length_of_public_private_symm_key,sizeof(unsigned char));

	while ( (n < length_of_public_private_symm_key) && (i < radix64_decoded_len ) )	{
	
		pubkey_encrypted_symm_key[i] = radix64_decoded[i];

		n++;

		i++;
	}
		
	//The following now accounts for the MAC-authenticated encrypted email message body			

	//Eight octets representing forthcoming string of encrypted email message	

	unsigned long long int smlen = 0;

	n = 0;				

	while ( (n < 8) && ( i < radix64_decoded_len) )	{
		
		smlen += radix64_decoded[i];

		smlen <<= 8;
		
		i++;

		n++;
	} 		

	//String of octets representing string of an encrypted email message

	unsigned char * sm = (unsigned char*)calloc(smlen,sizeof(unsigned char));

	n = 0;

	while ( (n < smlen) && ( i < radix64_decoded_len) )	{
		
		sm[i] = radix64_decoded[i];	
				
		i++;

		n++;
	}

	free(radix64_decoded);		
	
	free(pubkey_encrypted_symm_key);

	unsigned long long int mlen = smlen-crypto_sign_BYTES;	
	
	unsigned char * m = (unsigned char*)calloc(mlen,sizeof(unsigned char));
	
	verify_signed_message(m,&mlen,sm,smlen,sign_publickey);

	//The following is to decrypt the password

	free(m);

	free(sm);

	unsigned char decrypted_password[length_of_public_private_symm_key-crypto_box_MACBYTES];

	unsigned char nonce[crypto_box_NONCEBYTES];

	memset(nonce,0x0,crypto_box_NONCEBYTES);

	npg_open_pwd(decrypted_password,pubkey_encrypted_symm_key,length_of_public_private_symm_key,nonce,pk,sk);	

}


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

void sign_message_detached(unsigned char *sig,unsigned long long *siglen_p,const unsigned char * m,unsigned long long mlen,const unsigned char *sk)	{
	
	if ( crypto_sign_detached(sig,siglen_p,m,mlen,sk) == -1 )	{
		
		fprintf(stderr,"Error:crypto_sign_detached returned -1\n");

		exit(1);

	}	

}

void sign_message(unsigned char *sm,unsigned long long *smlen_p,const unsigned char *m,unsigned long long mlen,const unsigned char *sk)	{
	
	crypto_sign(sm,smlen_p,m,mlen,sk);

}

void verify_signed_message(unsigned char*m,unsigned long long *mlen_p,const unsigned char *sm,unsigned long long smlen,const unsigned char *pk)	{
	
	if (crypto_sign_open(m,mlen_p,sm,smlen,pk) == -1)	{

		fprintf(stderr,"Error:Failed to verify signed message\n");

		exit(1);
	}	

}

int verify_detached_signed_message(unsigned char*sig,const unsigned char *m,unsigned long long mlen,unsigned char *pk)	{

	if ( crypto_sign_verify_detached(sig,m,mlen,pk) != 0 )	{
		
		fprintf(stderr,"Error:Signed message verification failed!\n");

	}

	else							{
		printf("Congrats! Verification of message succeeded\n");

	}


}

#if 0
int verify_signed_message(unsigned char *sm,unsigned long long *smlen_p,const unsigned char *m,unsigned long long int mlen,const unsigned char *sk)	{
	
	if ( crypto_sign_verify	

}
#endif

size_t gen_email_message(unsigned char * pubkey_encrypted_sym_key,unsigned long long int pesk_len,unsigned char* encrypted_email,unsigned long long int mlen,unsigned char*filename)	{
		
		size_t i = 0;

		unsigned char * binout = (unsigned char*)calloc(pesk_len+mlen,sizeof(unsigned char));

		unsigned char * binout_p = binout;
		
		unsigned char filename_output[2048];

		memset(filename_output,0x0,2048);

		strncat(filename_output,filename,2048);

		strncat(filename_output,".msg\0",9);			

#if 0	
		//One octet giving version number of packet type
		
		*binout_p++ = 3;	

		//Eight-octet number that gives key ID of public key to which session

		//key is encrypted.
		
		i = 0;

		while ( i < 7 )	{
			
			*bin_out+p++ = 0;

			i++;
		}
		
		*binout_p++ = 1;

		//One-octet public-key algorithm:crypto_box_easy()

		*binout_p++ = 100;
#endif		
		//Eight octets representing length of forthcoming string for public-key protected symmetric key
		
		i = 0;

		unsigned long long int temp_len = pesk_len;

		while ( i < 8 )	{
			
			*binout_p++ = (temp_len & 0xff00000000000000) >> 56;		

			temp_len <<= 8;

			i++;
		}		
		
		//String of octets that is the encrypted session key.

		i = 0;

		while ( i < pesk_len )	{
			
			*binout_p++ = pubkey_encrypted_sym_key[i];

			i++;
		}		
		
		//The following now accounts for the MAC-authenticated encrypted email message body			

		//Eight octets representing forthcoming string of encrypted email message	
		
		temp_len = mlen;
		
		while ( i < 8 )	{
			
			*binout_p++ = (temp_len & 0xff00000000000000) >> 56;		

			temp_len <<= 8;

			i++;
		}

		//String of octets representing string of encrypted email message

		i = 0;

		while ( i < mlen )	{
			
			*binout_p++ = encrypted_email[i];

			i++;
		}		
		
		FILE * in = 0;

		if ( (in = fopen(filename_output,"wb")) == NULL )	{

			fprintf(stderr,"Error:Failed to create file\n");

			exit(1);
		}
 		
		i = 0;
		
		while ( i < ( pesk_len + mlen ) )	{
			
	//		fprintf(in,"%c",binout[i]);		

			i++;

		}		
		
		size_t base64_binout_len = 0;

		unsigned char * base64_binout = base64_encode(binout,pesk_len + mlen,&base64_binout_len);			
		free(binout);

		printf("Size of base64_binout:%llu\n",base64_binout_len);
		
		i = 0;
		
		while ( i < ( base64_binout_len ) )	{
			
			fprintf(in,"%c",base64_binout[i]);		

			i++;

		}		

	//	free(binout);

		free(base64_binout);		

		return base64_binout_len;
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
	
	unsigned char * file_arr = file_to_arr(dest,&file_arr_len);

	unsigned long long int file_arr_signed_len = crypto_sign_BYTES + file_arr_len;	
		
	unsigned char * file_arr_signed = (unsigned char*)calloc(file_arr_signed_len,sizeof(unsigned char));

	unsigned char file_sig[crypto_sign_BYTES];

	memset(file_sig,0x0,crypto_sign_BYTES*sizeof(unsigned char));

	unsigned char * file_arr_recipient = (unsigned char*)calloc(file_arr_signed_len,sizeof(unsigned char));

	unsigned long long int file_arr_recipient_len = 0;

	
	unsigned char sign_input[5] = "This\0";	
	
	unsigned char sign_publickey[crypto_sign_PUBLICKEYBYTES];

	unsigned char sign_secretkey[crypto_sign_SECRETKEYBYTES];
	
	memset(sign_publickey,0x0,crypto_sign_PUBLICKEYBYTES*sizeof(unsigned char));

	memset(sign_secretkey,0x0,crypto_sign_SECRETKEYBYTES*sizeof(unsigned char));
	
	crypto_sign_keypair(sign_publickey,sign_secretkey);

#if 0
	sign_message_detached(file_sig,NULL,file_arr,file_arr_len,sign_secretkey);
#endif
	sign_message(file_arr_signed,&file_arr_signed_len,file_arr,file_arr_len,sign_secretkey);
	
	printf("Verifying crypto_signature\n");

	verify_signed_message(file_arr_recipient,&file_arr_recipient_len,file_arr_signed,file_arr_signed_len,sign_publickey);	

	i = 0;

	printf("Signed file size is:%llu\n",file_arr_signed_len);
	
	putchar(0xa);
	
	printf("file_arr_len is %llu\n",file_arr_len);

	printf("Verifying crypto_signature\n");
	
	//verify_detached_signed_message(file_sig,file_arr,file_arr_len,sign_publickey);
	
	i = 0;
	
	printf("file_arr_recipient_len:%llu\n",file_arr_recipient_len);
	
	build_decoding_table();	
	
	unsigned char arr[3] = {'M','a','n'};	
	
	size_t len = 0;
	
	unsigned char * base64out = base64_encode(arr,3,&len);
	
	i = 0;

	while ( i < len )	{	
		
		printf("%c",base64out[i]);

		i++;

	}
	
	putchar(0xa);
	
	size_t base64in_len = 0;

	unsigned char * base64in = base64_decode(base64out,len,&base64in_len);

	i = 0;
	
	putchar(0xa);
	
	while ( i < base64in_len )	{
		
		printf("%c",base64in[i]);

		i++;
	}
	
	putchar(0xa);
	
	size_t base64_open_cpk_pwdlen = 0;

	unsigned char * base64_open_cpk_pwd = base64_encode(open_cpk_pwd,MAXSIZE+1,&base64_open_cpk_pwdlen);

	i = 0;

	while ( i < base64_open_cpk_pwdlen )	{
		
		printf("%c",base64_open_cpk_pwd[i]);

		i++;
	}
	
	putchar(0xa);

	size_t base64_open_cpk_pwd_decode_len = 0;

	unsigned char * base64_open_cpk_pwd_decode = base64_decode(base64_open_cpk_pwd,base64_open_cpk_pwdlen,&base64_open_cpk_pwd_decode_len);
	
	free(file_arr);

	gen_email_message(cpk_pwd,crypto_box_MACBYTES + MAXSIZE+1,file_arr_signed,file_arr_signed_len,dest);
	
	free(file_arr_signed);
	
	free(file_arr_recipient);

	free(base64_open_cpk_pwd);

	free(base64_open_cpk_pwd_decode);

	base64_cleanup();	

	free(base64out);

	free(base64in);

	free(open_cpk_pwd);
	
	return 0;

}
