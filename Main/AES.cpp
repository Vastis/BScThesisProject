#include "AES.h"

#pragma region Constants
const byte
rConLoc[16][4] = {
	{ 0x00 , 0x00 , 0x00 , 0x00 },//instead of substracting
	{ 0x01 , 0x00 , 0x00 , 0x00 },
	{ 0x02 , 0x00 , 0x00 , 0x00 },
	{ 0x04 , 0x00 , 0x00 , 0x00 },
	{ 0x08 , 0x00 , 0x00 , 0x00 },
	{ 0x10 , 0x00 , 0x00 , 0x00 },
	{ 0x20 , 0x00 , 0x00 , 0x00 },
	{ 0x40 , 0x00 , 0x00 , 0x00 },
	{ 0x80 , 0x00 , 0x00 , 0x00 },
	{ 0x1B , 0x00 , 0x00 , 0x00 },
	{ 0x36 , 0x00 , 0x00 , 0x00 },
	{ 0x6C , 0x00 , 0x00 , 0x00 },
	{ 0xD8 , 0x00 , 0x00 , 0x00 },
	{ 0xAB , 0x00 , 0x00 , 0x00 },
	{ 0x1B , 0x00 , 0x00 , 0x00 },
	{ 0x4D , 0x00 , 0x00 , 0x00 },
},
sBoxEnLoc[16][16] = {
	{ 0x63 , 0x7c , 0x77 , 0x7b , 0xf2 , 0x6b , 0x6f , 0xc5 , 0x30 , 0x01 , 0x67 , 0x2b , 0xfe , 0xd7 , 0xab , 0x76 },
	{ 0xca , 0x82 , 0xc9 , 0x7d , 0xfa , 0x59 , 0x47 , 0xf0 , 0xad , 0xd4 , 0xa2 , 0xaf , 0x9c , 0xa4 , 0x72 , 0xc0 },
	{ 0xb7 , 0xfd , 0x93 , 0x26 , 0x36 , 0x3f , 0xf7 , 0xcc , 0x34 , 0xa5 , 0xe5 , 0xf1 , 0x71 , 0xd8 , 0x31 , 0x15 },
	{ 0x04 , 0xc7 , 0x23 , 0xc3 , 0x18 , 0x96 , 0x05 , 0x9a , 0x07 , 0x12 , 0x80 , 0xe2 , 0xeb , 0x27 , 0xb2 , 0x75 },
	{ 0x09 , 0x83 , 0x2c , 0x1a , 0x1b , 0x6e , 0x5a , 0xa0 , 0x52 , 0x3b , 0xd6 , 0xb3 , 0x29 , 0xe3 , 0x2f , 0x84 },
	{ 0x53 , 0xd1 , 0x00 , 0xed , 0x20 , 0xfc , 0xb1 , 0x5b , 0x6a , 0xcb , 0xbe , 0x39 , 0x4a , 0x4c , 0x58 , 0xcf },
	{ 0xd0 , 0xef , 0xaa , 0xfb , 0x43 , 0x4d , 0x33 , 0x85 , 0x45 , 0xf9 , 0x02 , 0x7f , 0x50 , 0x3c , 0x9f , 0xa8 },
	{ 0x51 , 0xa3 , 0x40 , 0x8f , 0x92 , 0x9d , 0x38 , 0xf5 , 0xbc , 0xb6 , 0xda , 0x21 , 0x10 , 0xff , 0xf3 , 0xd2 },
	{ 0xcd , 0x0c , 0x13 , 0xec , 0x5f , 0x97 , 0x44 , 0x17 , 0xc4 , 0xa7 , 0x7e , 0x3d , 0x64 , 0x5d , 0x19 , 0x73 },
	{ 0x60 , 0x81 , 0x4f , 0xdc , 0x22 , 0x2a , 0x90 , 0x88 , 0x46 , 0xee , 0xb8 , 0x14 , 0xde , 0x5e , 0x0b , 0xdb },
	{ 0xe0 , 0x32 , 0x3a , 0x0a , 0x49 , 0x06 , 0x24 , 0x5c , 0xc2 , 0xd3 , 0xac , 0x62 , 0x91 , 0x95 , 0xe4 , 0x79 },
	{ 0xe7 , 0xc8 , 0x37 , 0x6d , 0x8d , 0xd5 , 0x4e , 0xa9 , 0x6c , 0x56 , 0xf4 , 0xea , 0x65 , 0x7a , 0xae , 0x08 },
	{ 0xba , 0x78 , 0x25 , 0x2e , 0x1c , 0xa6 , 0xb4 , 0xc6 , 0xe8 , 0xdd , 0x74 , 0x1f , 0x4b , 0xbd , 0x8b , 0x8a },
	{ 0x70 , 0x3e , 0xb5 , 0x66 , 0x48 , 0x03 , 0xf6 , 0x0e , 0x61 , 0x35 , 0x57 , 0xb9 , 0x86 , 0xc1 , 0x1d , 0x9e },
	{ 0xe1 , 0xf8 , 0x98 , 0x11 , 0x69 , 0xd9 , 0x8e , 0x94 , 0x9b , 0x1e , 0x87 , 0xe9 , 0xce , 0x55 , 0x28 , 0xdf },
	{ 0x8c , 0xa1 , 0x89 , 0x0d , 0xbf , 0xe6 , 0x42 , 0x68 , 0x41 , 0x99 , 0x2d , 0x0f , 0xb0 , 0x54 , 0xbb , 0x16 }
},
sBoxDeLoc[16][16] = {
	{ 0x52 , 0x09 , 0x6a , 0xd5 , 0x30 , 0x36 , 0xa5 , 0x38 , 0xbf , 0x40 , 0xa3 , 0x9e , 0x81 , 0xf3 , 0xd7 , 0xfb },
	{ 0x7c , 0xe3 , 0x39 , 0x82 , 0x9b , 0x2f , 0xff , 0x87 , 0x34 , 0x8e , 0x43 , 0x44 , 0xc4 , 0xde , 0xe9 , 0xcb },
	{ 0x54 , 0x7b , 0x94 , 0x32 , 0xa6 , 0xc2 , 0x23 , 0x3d , 0xee , 0x4c , 0x95 , 0x0b , 0x42 , 0xfa , 0xc3 , 0x4e },
	{ 0x08 , 0x2e , 0xa1 , 0x66 , 0x28 , 0xd9 , 0x24 , 0xb2 , 0x76 , 0x5b , 0xa2 , 0x49 , 0x6d , 0x8b , 0xd1 , 0x25 },
	{ 0x72 , 0xf8 , 0xf6 , 0x64 , 0x86 , 0x68 , 0x98 , 0x16 , 0xd4 , 0xa4 , 0x5c , 0xcc , 0x5d , 0x65 , 0xb6 , 0x92 },
	{ 0x6c , 0x70 , 0x48 , 0x50 , 0xfd , 0xed , 0xb9 , 0xda , 0x5e , 0x15 , 0x46 , 0x57 , 0xa7 , 0x8d , 0x9d , 0x84 },
	{ 0x90 , 0xd8 , 0xab , 0x00 , 0x8c , 0xbc , 0xd3 , 0x0a , 0xf7 , 0xe4 , 0x58 , 0x05 , 0xb8 , 0xb3 , 0x45 , 0x06 },
	{ 0xd0 , 0x2c , 0x1e , 0x8f , 0xca , 0x3f , 0x0f , 0x02 , 0xc1 , 0xaf , 0xbd , 0x03 , 0x01 , 0x13 , 0x8a , 0x6b },
	{ 0x3a , 0x91 , 0x11 , 0x41 , 0x4f , 0x67 , 0xdc , 0xea , 0x97 , 0xf2 , 0xcf , 0xce , 0xf0 , 0xb4 , 0xe6 , 0x73 },
	{ 0x96 , 0xac , 0x74 , 0x22 , 0xe7 , 0xad , 0x35 , 0x85 , 0xe2 , 0xf9 , 0x37 , 0xe8 , 0x1c , 0x75 , 0xdf , 0x6e },
	{ 0x47 , 0xf1 , 0x1a , 0x71 , 0x1d , 0x29 , 0xc5 , 0x89 , 0x6f , 0xb7 , 0x62 , 0x0e , 0xaa , 0x18 , 0xbe , 0x1b },
	{ 0xfc , 0x56 , 0x3e , 0x4b , 0xc6 , 0xd2 , 0x79 , 0x20 , 0x9a , 0xdb , 0xc0 , 0xfe , 0x78 , 0xcd , 0x5a , 0xf4 },
	{ 0x1f , 0xdd , 0xa8 , 0x33 , 0x88 , 0x07 , 0xc7 , 0x31 , 0xb1 , 0x12 , 0x10 , 0x59 , 0x27 , 0x80 , 0xec , 0x5f },
	{ 0x60 , 0x51 , 0x7f , 0xa9 , 0x19 , 0xb5 , 0x4a , 0x0d , 0x2d , 0xe5 , 0x7a , 0x9f , 0x93 , 0xc9 , 0x9c , 0xef },
	{ 0xa0 , 0xe0 , 0x3b , 0x4d , 0xae , 0x2a , 0xf5 , 0xb0 , 0xc8 , 0xeb , 0xbb , 0x3c , 0x83 , 0x53 , 0x99 , 0x61 },
	{ 0x17 , 0x2b , 0x04 , 0x7e , 0xba , 0x77 , 0xd6 , 0x26 , 0xe1 , 0x69 , 0x14 , 0x63 , 0x55 , 0x21 , 0x0c , 0x7d }
};
#pragma endregion

AES::AES() {
	this->mode = "AES-256";
	setConstants();
	setTables();
}
AES::AES(String &mode) {
	this->mode = mode;
	setConstants();
	setTables();
}
String AES::getMode() {
	return mode;
}

void AES::encrypt(byte *input, unsigned int inputLength, byte *key, byte *output)
{
	int wordsNo = 4 * (roundsNo + 1);
	byte **word = new byte*[wordsNo];
	keyExpansion(key, word, wordsNo);

	int k = 0;
	int blocks = (inputLength - 1) / 16 + 1;

	byte **cipherText = new byte*[blocks];
	byte tmp[16];
	for (int i = 0; i < blocks - 1; i++) {
		for (int j = 0; j < 16; j++) {
			tmp[j] = input[k];
			k++;
		}
		cipherText[i] = new byte[16];
		aesEn(tmp, 16, word, cipherText[i]);
	}
	int lastBlockLen = inputLength - k;
	for (int i = 0; i < lastBlockLen; i++) {
		tmp[i] = input[k];
		k++;
	}
	cipherText[blocks - 1] = new byte[16];
	aesEn(tmp, lastBlockLen, word, cipherText[blocks - 1]);
	k = 0;
	for (int i = 0; i < blocks; i++) {
		for (int j = 0; j < 16; j++) {
			output[k] = cipherText[i][j];
			k++;
		}
	}
	for (int i = 0; i < blocks; i++) free(cipherText[i]);
	free(cipherText);
	for (int i = 0; i < wordsNo; i++) free(word[i]);
	free(word);
}
void AES::decrypt(byte *input, unsigned int inputLength, byte *key, byte *output)
{
	int wordsNo = 4 * (roundsNo + 1);
	byte **word = new byte*[wordsNo];
	keyExpansion(key, word, wordsNo);

	int k = 0;
	int blocks = inputLength / 16;
	byte **plainText = new byte*[blocks];
	byte tmp[16];
	for (int i = 0; i < blocks; i++) {
		for (int j = 0; j < 16; j++) {
			tmp[j] = input[k];
			k++;
		}
		plainText[i] = new byte[16];
		aesDe(tmp, 16, word, plainText[i]);
	}
	k = 0;
	for (int i = 0; i < blocks; i++) {
		for (int j = 0; j < 16; j++) {
			output[k] = plainText[i][j];
			k++;
		}
	}
	for (int i = 0; i < blocks; i++) free(plainText[i]);
	free(plainText);
	for (int i = 0; i < wordsNo; i++) free(word[i]);
	free(word);
}

void AES::setConstants()
{
	if (this->mode == "AES-128") {
		keyLength = 128;
		keyColumnsNo = 4;
		roundsNo = 10;
	}
	else if (this->mode == "AES-192") {
		keyLength = 192;
		keyColumnsNo = 6;
		roundsNo = 12;
	}
	else if (this->mode == "AES-256") {
		keyLength = 256;
		keyColumnsNo = 8;
		roundsNo = 14;
	}
	else {
		this->mode = "AES-256";
		keyLength = 256;
		keyColumnsNo = 8;
		roundsNo = 14;
	}
}
void AES::setTables() {
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			sBoxEn[i][j] = sBoxEnLoc[i][j];
			sBoxDe[i][j] = sBoxDeLoc[i][j];
		}
		for (int j = 0; j < 4; j++) rCon[i][j] = rConLoc[i][j];
	}

}

void AES::intoState(byte *input, unsigned int inputLength, byte **state)
{
	byte *stateVector = new byte[16];
	for (int i = 0; i < inputLength; i++) stateVector[i] = input[i];
	for (int i = inputLength; i < 16; i++) stateVector[i] = 0;
	int k = 0;
	for (int i = 0; i < 4; i++) state[i] = new byte[4];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[j][i] = stateVector[k];
			k++;
		}
	}
	free(stateVector);
}
void AES::intoBytes(byte **input, byte *output)
{
	int k = 0;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			output[k] = input[j][i];
			k++;
		}
	}
}

void AES::rotateRight(byte *word)
{
	byte tmp = word[3];
	word[3] = word[2];
	word[2] = word[1];
	word[1] = word[0];
	word[0] = tmp;
}
void AES::rotateLeft(byte *word)
{
	byte tmp = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = tmp;
}
void AES::exclusive(byte *result, byte *word1, byte *word2)
{
	for (int i = 0; i < 4; i++) result[i] = word1[i] ^ word2[i];
}
byte AES::mul2(byte a)
{
	byte result = a;
	if (result >= 0x80) {
		result = result << 1;
		result ^= 0x1b;
	}
	else result = result << 1;
	return result;
}
byte AES::recursiveMul2(byte a, int flag)
{
	if (flag == 0) return a;
	else recursiveMul2(mul2(a), flag - 1);
}
byte AES::mul(byte a, byte b)
{
	byte result = 0;
	for (int i = 0; i < 4; i++) {
		bool bit = b % 2;
		if (bit) result ^= recursiveMul2(a, i);
		b = b >> 1;
	}
	return result;
}

void AES::keyExpansion(byte *key, byte **word, unsigned int wordsNo)
{
	int i = 0;
	while (i < keyColumnsNo) {
		word[i] = new byte[4];
		for (int j = 0; j < 4; j++) word[i][j] = key[4 * i + j];
		i++;
	}
	while (i < wordsNo) {
		word[i] = new byte[4];
		byte *temp = new byte[4];
		for (int j = 0; j < 4; j++) temp[j] = word[i - 1][j];
		if (i%keyColumnsNo == 0) {
			rotateLeft(temp);
			subWord(temp);
			exclusive(temp, temp, rCon[i / keyColumnsNo]);
		}
		else if (keyColumnsNo > 6 && i%keyColumnsNo == 4) subWord(temp);
		exclusive(word[i], word[i - keyColumnsNo], temp);
		free(temp);
		i++;
	}
}
void AES::getRoundKey(byte **word, int round, byte **roundKey)
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++)
			roundKey[j][i] = word[4 * round + i][j];
	}
}

byte AES::subByte(byte c)
{
	byte x = c >> 4;
	byte y = c - (x << 4);
	return sBoxEn[x][y];
}
void AES::subWord(byte *word)
{
	for (int i = 0; i < 4; i++) {
		word[i] = subByte(word[i]);
	}
}
byte AES::invSubByte(byte c)
{
	byte x = c >> 4;
	byte y = c - (x << 4);
	return sBoxDe[x][y];
}
void AES::invSubWord(byte *word)
{
	for (int i = 0; i < 4; i++) {
		word[i] = invSubByte(word[i]);
	}
}

void AES::addRoundKey(byte **state, byte **roundKey)
{
	for (int i = 0; i < 4; i++) exclusive(state[i], state[i], roundKey[i]);
}

void AES::subBytes(byte **state)
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = subByte(state[i][j]);
		}
	}
}
void AES::shiftRows(byte **state)
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < i; j++) {
			rotateLeft(state[i]);
		}
	}
}
void AES::mixColumns(byte **state)
{
	byte **tmp = new byte*[4];
	for (int i = 0; i < 4; i++) {
		tmp[i] = new byte[4];
		for (int j = 0; j < 4; j++) {
			tmp[i][j] = state[i][j];
		}
	}
	for (int j = 0; j < 4; j++) {
		state[0][j] = mul(tmp[0][j], 2) ^ mul(tmp[1][j], 3) ^ tmp[2][j] ^ tmp[3][j];
		state[1][j] = tmp[0][j] ^ mul(tmp[1][j], 2) ^ mul(tmp[2][j], 3) ^ tmp[3][j];
		state[2][j] = tmp[0][j] ^ tmp[1][j] ^ mul(tmp[2][j], 2) ^ mul(tmp[3][j], 3);
		state[3][j] = mul(tmp[0][j], 3) ^ tmp[1][j] ^ tmp[2][j] ^ mul(tmp[3][j], 2);
	}
	for (int i = 0; i < 4; i++) free(tmp[i]);
	free(tmp);
}
void AES::rnd(byte **state, byte **roundKey)
{
	subBytes(state);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, roundKey);
}

void AES::invSubBytes(byte **state)
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = invSubByte(state[i][j]);
		}
	}
}
void AES::invShiftRows(byte **state)
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < i; j++) {
			rotateRight(state[i]);
		}
	}
}
void AES::invMixColumns(byte **state)
{
	byte **tmp = new byte*[4];
	for (int i = 0; i < 4; i++) {
		tmp[i] = new byte[4];
		for (int j = 0; j < 4; j++) tmp[i][j] = state[i][j];
	}
	for (int j = 0; j < 4; j++) {
		state[0][j] = mul(tmp[0][j], 0x0e) ^ mul(tmp[1][j], 0x0b) ^ mul(tmp[2][j], 0x0d) ^ mul(tmp[3][j], 0x09);
		state[1][j] = mul(tmp[0][j], 0x09) ^ mul(tmp[1][j], 0x0e) ^ mul(tmp[2][j], 0x0b) ^ mul(tmp[3][j], 0x0d);
		state[2][j] = mul(tmp[0][j], 0x0d) ^ mul(tmp[1][j], 0x09) ^ mul(tmp[2][j], 0x0e) ^ mul(tmp[3][j], 0x0b);
		state[3][j] = mul(tmp[0][j], 0x0b) ^ mul(tmp[1][j], 0x0d) ^ mul(tmp[2][j], 0x09) ^ mul(tmp[3][j], 0x0e);
	}
	for (int i = 0; i < 4; i++) free(tmp[i]);
	free(tmp);
}
void AES::rndDe(byte **state, byte **roundKey)
{
	addRoundKey(state, roundKey);
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state);
}

void AES::aesEn(byte *input, unsigned int inputLength, byte **word, byte *output)
{
	byte **state = new byte*[4];
	intoState(input, inputLength, state);
	byte **roundKey = new byte*[4];
	for (int i = 0; i < 4; i++) roundKey[i] = new byte[4];

	getRoundKey(word, 0, roundKey);
	addRoundKey(state, roundKey);
	for (int roundNo = 1; roundNo < roundsNo; roundNo++) {
		getRoundKey(word, roundNo, roundKey);
		rnd(state, roundKey);
	}
	subBytes(state);
	shiftRows(state);
	getRoundKey(word, roundsNo, roundKey);
	addRoundKey(state, roundKey);

	intoBytes(state, output);

	for (int i = 0; i < 4; i++) free(roundKey[i]);
	free(roundKey);
	for (int i = 0; i < 4; i++) free(state[i]);
	free(state);
}
void AES::aesDe(byte *input, unsigned int inputLength, byte **word, byte *output)
{
	byte **state = new byte*[4];
	intoState(input, inputLength, state);
	byte **roundKey = new byte*[4];
	for (int i = 0; i < 4; i++) roundKey[i] = new byte[4];

	getRoundKey(word, roundsNo, roundKey);
	addRoundKey(state, roundKey);
	invShiftRows(state);
	invSubBytes(state);
	for (int roundNo = 1; roundNo < roundsNo; roundNo++) {
		getRoundKey(word, roundsNo - roundNo, roundKey);
		rndDe(state, roundKey);
	}
	getRoundKey(word, 0, roundKey);
	addRoundKey(state, roundKey);

	intoBytes(state, output);

	for (int i = 0; i < 4; i++) free(roundKey[i]);
	free(roundKey);
	for (int i = 0; i < 4; i++) free(state[i]);
	free(state);
}