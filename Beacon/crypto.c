#include "pch.h"

#include "tomcrypt.h"
#include "tomcrypt_hash.h"

int gHashSha256;
int gAesCipher;

char gCbcKey[16];
char gHmacKey[16];
char gIv[16];

symmetric_key gRijndaelSymkey;
void CryptoSetupSha256AES(char* in)
{

#define INIT_VECTOR "abcdefghijklmnop"

	char mask[sizeof(gCbcKey) + sizeof(gHmacKey)];
	long maskLen = sizeof(mask);

	register_hash(&sha256_desc);
	gHashSha256 = find_hash(sha256_desc.name);

	if (hash_memory(gHashSha256, (unsigned char*)in, 16, mask, &maskLen) != CRYPT_OK)
	{
		exit(1);
	}

	memcpy(gCbcKey, mask, sizeof(gCbcKey));
	memcpy(gHmacKey, mask + sizeof(gCbcKey), sizeof(gHmacKey));
	memcpy(gIv, INIT_VECTOR, STRLEN(INIT_VECTOR));

	register_cipher(&aes_desc);
	gAesCipher = find_cipher(aes_desc.name);

	if(rijndael_setup(gCbcKey, sizeof(gCbcKey), 0, &gRijndaelSymkey) != CRYPT_OK)
	{
		exit(1);
	}
	
}
