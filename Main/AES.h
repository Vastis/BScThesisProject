#ifndef _AES_h
#define _AES_h

#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

class AES {
public:
	AES();				//domyslny wariant algorytmu - AES-256
	AES(String &mode);	//wariant algorytmu mode: (AES-128 / AES-192 / AES-256)

						//zwraca uzywany wariant algorytmu
	String getMode();
	//szyfrowanie
	void encrypt(byte *input, unsigned int inputLength, byte *key, byte *output);
	//deszyfrowanie
	void decrypt(byte *input, unsigned int inputLength, byte *key, byte *output);

private:
	byte	rCon[16][4],		//tablica stalych slow
		sBoxEn[16][16],		//tablica podstawieniowa szyfrowania
		sBoxDe[16][16];		//tablica podstawieniowa deszyfrowania
	String	mode;				//uzywany wariant algorytmu
	int		keyLength,			//dlugosc klucza w bitach
		keyColumnsNo,		//dlugosc klucza w slowach 4-bajtowych
		roundsNo;			//ilosc rund

							//ustalenie stalych zaleznych od wariantu algorytmu
	void setConstants();
	//wypelnienie tablic wartosciami
	void setTables();

	//konwersja tablicy bajtow na Stan
	void intoState(byte* input, unsigned int inputLength, byte **state);
	//konwersja Stanu na tablice bajtow
	void intoBytes(byte **input, byte *output);

	//rotacja bajtow w prawo
	void rotateRight(byte *word);
	//rotacja bajtow w lewo
	void rotateLeft(byte *word);
	//xor poszczegolnych bajtow tablic word1 i word2
	void exclusive(byte *result, byte *word1, byte *word2);
	//mnozenie a*2 mod m(x) 
	byte mul2(byte a);
	//rekurencyjne wywolywanie mul2()
	byte recursiveMul2(byte a, int flag);
	//mnozenie a*b mod m(x)
	byte mul(byte a, byte b);

	//ustalanie kluczy rundy
	void keyExpansion(byte *key, byte **word, unsigned int wordsNo);
	//pobieranie klucza rundy round
	void getRoundKey(byte **word, int round, byte **roundKey);

	//podstawienie bajtu c odpowiednikiem z tablicy sBoxEn
	byte subByte(byte c);
	//subByte() na ka¿dym bajcie slowa
	void subWord(byte *word);
	//podstawienie bajtu c odpowiednikiem z tablicy sBoxDe
	byte invSubByte(byte c);
	//invSubByte() na ka¿dym bajcie slowa
	void invSubWord(byte *word);

	//operacja AddRoundKey
	void addRoundKey(byte **state, byte **roundKey);

	//operacja SubBytes
	void subBytes(byte **state);
	//operacja ShiftRows
	void shiftRows(byte **state);
	//operacja MixColumns
	void mixColumns(byte **state);
	//pelna runda szyfrowania
	void rnd(byte **state, byte **roundKey);

	//operacja InvSubBytes
	void invSubBytes(byte **state);
	//operacja InvShiftRows
	void invShiftRows(byte **state);
	//operacja InvMixColumns
	void invMixColumns(byte **state);
	//pelna runda deszyfrowania
	void rndDe(byte **state, byte **roundKey);

	//szyfrowanie pojedynczego bloku
	void aesEn(byte* input, unsigned int inputLength, byte **word, byte *output);
	//deszyfrowanie pojedynczego bloku
	void aesDe(byte* input, unsigned int inputLength, byte **word, byte *output);
};

#endif
