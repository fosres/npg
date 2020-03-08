#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include "npg.h"
void decrypt_email_message(unsigned char*radix64,size_t radix64_len,unsigned char sign_publickey[crypto_sign_PUBLICKEYBYTES],unsigned char *pk,unsigned char*sk)	{
	

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
	
	unsigned long long int mlen = smlen-crypto_sign_BYTES;	
	
	unsigned char * m = (unsigned char*)calloc(mlen,sizeof(unsigned char));
	
	verify_signed_message(m,&mlen,sm,smlen,sign_publickey);

	//The following is to decrypt the password

	unsigned char decrypted_password[length_of_public_private_symm_key-crypto_box_MACBYTES];

	unsigned char nonce[crypto_box_NONCEBYTES];

	memset(nonce,0x0,crypto_box_NONCEBYTES);

	npg_open_pwd(decrypted_password,pubkey_encrypted_symm_key,length_of_public_private_symm_key,nonce,pk,sk);	

}

