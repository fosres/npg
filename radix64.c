#include <stdio.h>
//#include <sodium.h>
#include "npg.h"

void base2_to_base64_init(void)	{

	unsigned short i = 0;

	unsigned char c = 'A';

	while ( i < 26 )	{
		
		base64[i] = ((i<<8) & 0x00);

		base64[i] |= c;

		i++;

		c++;

	}

	c = 'a';

	while ( i < 52 )	{

		base64[i] = ((i << 8) & 0x00);

		base64[i] |= c;

		i++;

		c++;
	}
		
	c = '0';

	while ( i < 62 )	{

		base64[i] = ((i << 8) & 0x00);

		base64[i] |= c;

		i++;

		c++;
	}

	c = '+';

	base64[i] = ((i << 8) & 0x00);

	base64[i] |= c;

	i++;

	c = '/';

	base64[i] = ((i << 8) & 0x00);

	base64[i] |= c;

	i++;
}

unsigned char base64_to_six(int c)	{

	if ( c >= 'A' && c <= 'Z' )	{

		return (c-'A') + 0;
	}

	else if ( c >= 'a' && c <= 'z' )	{
		
		return (c-'a')+26;
	}

	else if (c >= '0' && c <= '9')		{
		
		return (c-'0')+52;		

	}

	else if ( c == '+' )			{
		
		return 62;

	}

	else if ( c == '/')			{
		
		return 63;

	}

	else					{
		
		return -1;

	}

}

	
void base2_to_base64(unsigned char *bp,unsigned long long int len)	{
	
	unsigned char base64char = 0, carry_byte = 0, last_six_bits = 0;

	size_t ret_bytes = 0; 

	while (isspace(*bp++))
		;
	
	unsigned long long int i = 0;
	
	while (i < len )	{
		
		base64char = *bp++;i++;

		carry_byte = 0;

		carry_byte |= ( (base64char & 0b00000011 ) << 4 );

		base64char &= 0b11111100;

		base64char >>= 2;

		printf("%c",base64[base64char] & 0x00ff);


		last_six_bits = base64[base64char];
		
		base64char = 0;

		if ( i >= len )	{
			
			break;

		}

		else		{

			i++;base64char = *bp++;
		}	

		carry_byte |= ( (base64char & 0xf0) >> 4 );

		printf("%c",base64[carry_byte]);

		last_six_bits = base64[carry_byte];

		carry_byte = 0; carry_byte = (base64char & 0x0f) << 2;base64char = 0;

		if ( i >= len )	{
			
			break;

		}

		else		{

			i++;base64char = *bp++;
		}

		carry_byte |= (base64char & 0b11000000) >> 6;	

		printf("%c",base64[carry_byte] & 0x00ff);

		carry_byte = 0;

		base64char &= 0b00111111;

		printf("%c",base64[base64char]&0x00ff);last_six_bits = base64[base64char];

		if ( i >= len )	{
			
			break;

		}

		else		{

			i++;base64char = *bp++;
		}
		
	}

	if (i >= len)	{
		return;	
	}

	if ((last_six_bits & 0x0f) == 0x0)	{
		
		printf("%s","==");

	}

	else if ((last_six_bits & 0x03) == 0x0)	{
		printf("%c",'=');
	}

}

int main(int argc,char**argv)	{
	
	base2_to_base64_init();
		
	unsigned char arr[3];
	
	size_t i = 0;

	while ( i < 64 )	{
		printf("%c",base64[i] & 0x00ff);
		i++;
	}
	return 0;
}

