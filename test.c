#include <stdio.h>
#include <string.h>

int main(void)	{
	
	unsigned long long int pesk_len = 0x0102030405060708;
	
	unsigned char pesk_bytes[8];

	memcpy(pesk_bytes,&pesk_len,8);

	size_t i = 0;

	while ( i < 8 )	{
		
		printf("%.2x",(pesk_len & 0xff00000000000000) >> 56);

		pesk_len <<= 8;

		i++;
	}		

	return 0;
}
