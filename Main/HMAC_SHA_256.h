// HMAC_SHA_256.h

#ifndef _HMAC_SHA_256_h
#define _HMAC_SHA_256_h

#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

class HMAC_SHA_256 {
public:
	HMAC_SHA_256();
	//HMAC SHA-256
	void hmac(uint8_t *key, uint64_t keyLength, uint8_t *text, uint64_t textLength, uint8_t *output);

private:
	uint32_t K[64];		//tablica stalych slow SHA-256

						//SHA-256
	void hash(uint8_t *input, uint64_t inputLength, uint8_t *output);

	//operacja Ch
	uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
	//operacja Maj
	uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
	//przesuniecie bitowe w prawo o n: x >> n
	uint32_t rightShift(uint32_t x, uint32_t n);
	//rotacja bitowa w prawo o n
	uint32_t rotateRight(uint32_t x, uint32_t n);
	//operacja duza_sigma_0
	uint32_t upperSigma0(uint32_t x);
	//operacja duza_sigma_1
	uint32_t upperSigma1(uint32_t x);
	//operacja mala_sigma_0
	uint32_t lowerSigma0(uint32_t x);
	//operacja mala_sigma_1
	uint32_t lowerSigma1(uint32_t x);
};

#endif

