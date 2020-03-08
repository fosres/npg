#include <stdio.h>
#include <sodium.h>
#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4

int main(void)					{
unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];
crypto_sign_keypair(pk, sk);

unsigned char sig[crypto_sign_BYTES];

unsigned char test[5]="Test\0";

crypto_sign_detached(sig, NULL, test,5, sk);

if (crypto_sign_verify_detached(sig,test,5, pk) != 0) {
    /* Incorrect signature! */

	fprintf(stderr,"Failed to verify detached signature\n");
}
	return 0;
}
