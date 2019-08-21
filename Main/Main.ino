#pragma region Includes

#include "HMAC_SHA_256.h"
#include "ESP8266.h"
#include "AES.h"
#include <PN532_HSU.h>
#include <PN532.h>
#include <EEPROM.h>
#include <avr/wdt.h>

#pragma endregion

#pragma region Defines

#define eepromAddress_authorizationFlag		0 //length = 1
#define eepromAddress_apSSIDLength			1
#define eepromAddress_apPasswordLength		2
#define eepromAddress_apSSID				3 //length = 32
#define eepromAddress_apPassword			35 //length = 32
#define eepromAddress_tcpServerIP			67 //length = 4
#define eepromAddress_tcpServerPort			71 //length = 2 - sizeof(short uint)
#define eepromAddress_centralMAC			73 //length = 6
#define eepromAddress_aesKey				79 //length = 32

#pragma endregion

#pragma region Globals

PN532_HSU		pn532hsu(Serial1);
PN532			nfc(pn532hsu);
ESP8266			esp;
AES				aes;
HMAC_SHA_256	hmac;

String			espResponse = "";

int				bluePin = 37,
				greenPin = 39,
				redPin = 41,
				switchControlPin = 45;
unsigned long	controlTimeout = 2000;

#pragma endregion

#pragma region Main Functions

void setup() {
	begin();
	if (checkUsbConnection()) {
		if (EEPROM.read(eepromAddress_authorizationFlag) == 1) {
			runAsCentralComp();
		}
		else authorize();
	}
	initComps();
	initConnection();
}
void loop() {
	keyExchange();
	checkConnection();
	control();
}

#pragma endregion

#pragma region Ancillary Functions

//inicjalizacja podzespolow czytnika
void begin() {
	pinMode(switchControlPin, OUTPUT);
	digitalWrite(switchControlPin, LOW);

	pinMode(bluePin, OUTPUT);
	pinMode(greenPin, OUTPUT);
	pinMode(redPin, OUTPUT);
	digitalWrite(bluePin, HIGH);
	digitalWrite(greenPin, HIGH);
	digitalWrite(redPin, HIGH);

	Serial.begin(115200);
	Serial2.begin(115200);

	randomSeed(analogRead(0));

	aes = AES();
	esp = ESP8266();
	hmac = HMAC_SHA_256();
	setUpPN532();
	Serial2.println("PN532 OK");
}
//sprawdzenie, czy czytnik jest podlaczony do centrali
bool checkUsbConnection() {
	unsigned long timeout = 10000;
	unsigned long t = 0;
	Serial2.flush();
	t = millis();
	while (millis() - t < timeout) {
		Serial2.println("Hello");
		delay(1000);
		if (Serial2.available() > 0) {
			String resp = Serial2.readString();
			if (resp.equals("Hello")) {
				Serial2.end();
				Serial2.begin(115200);
				return true;
			}
		}
	}
	return false;
}
//rejestracja czytnika
void authorize() {
	String data;
	String mac = esp.getMACAddress();
	Serial2.println(mac.c_str());
	while (Serial2.available() <= 0);
	data = Serial2.readStringUntil('~');
	byte *centralMac = new byte[6];
	hexStringToBytesArray(data, centralMac, 6);
	for (int i = 0; i < 6; i++) EEPROM.update(eepromAddress_centralMAC + i, centralMac[i]);
	free(centralMac);
	Serial2.println("OK");
	while (Serial2.available() <= 0);
	data = Serial2.readStringUntil('~');
	EEPROM.update(eepromAddress_apSSIDLength, data.length());
	for (int i = 0; i < data.length(); i++) EEPROM.update(eepromAddress_apSSID + i, data[i]);
	Serial2.println("OK");
	while (Serial2.available() <= 0);
	data = Serial2.readStringUntil('~');
	EEPROM.update(eepromAddress_apPasswordLength, data.length());
	for (int i = 0; i < data.length(); i++) EEPROM.update(eepromAddress_apPassword + i, data[i]);
	Serial2.println("OK");
	while (Serial2.available() <= 0);
	data = Serial2.readStringUntil('~');
	byte *ipAddress = new byte[4];
	ipAddressToByteArray(data, ipAddress);
	for (int i = 0; i < 4; i++) EEPROM.write(eepromAddress_tcpServerIP + i, ipAddress[i]);
	free(ipAddress);
	Serial2.println("OK");
	while (Serial2.available() <= 0);
	data = Serial2.readStringUntil('~');
	uint16_t port = (uint16_t)toShort(data);
	EEPROM.update(eepromAddress_tcpServerPort + 1, (byte)port);
	EEPROM.update(eepromAddress_tcpServerPort, (byte)(port >> 8));
	Serial2.println("OK");
	while (Serial2.available() <= 0);
	data = Serial2.readStringUntil('~');
	byte *key = new byte[32];
	hexStringToBytesArray(data, key, 32);
	for (int i = 0; i < 32; i++) EEPROM.update(eepromAddress_aesKey + i, key[i]);
	free(key);
	EEPROM.update(eepromAddress_authorizationFlag, 1);
	Serial2.println("Done");
	digitalWrite(greenPin, LOW);
	while (true);
}
//rejestracja znacznikow
void runAsCentralComp() {
	Serial2.println("Ready to be central's reader");
	while (Serial2.available() > 0);
	String response = Serial2.readString();
	Serial.println(response);
	digitalWrite(bluePin, LOW);
	digitalWrite(greenPin, LOW);
	digitalWrite(redPin, LOW);
	while (true) {
		bool success;
		byte uid[] = { 0, 0, 0, 0, 0, 0, 0 };
		byte uidLength;

		success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

		if (success) {
			for (int i = 0; i < uidLength; i++) Serial2.write(uid[i]);
			while (Serial2.available() <= 0);
			String response = Serial2.readString();
			if (response.equals("OK")) {
				digitalWrite(bluePin, HIGH);
				digitalWrite(redPin, HIGH);
				delay(3000);
				digitalWrite(bluePin, LOW);
				digitalWrite(redPin, LOW);
			}
			else {
				digitalWrite(bluePin, HIGH);
				digitalWrite(greenPin, HIGH);
				delay(1000);
				digitalWrite(bluePin, LOW);
				digitalWrite(greenPin, LOW);
			}
			Serial2.end();
			Serial2.begin(115200);
		}
	}
}
//weryfikacja polaczenia
bool authenticate() {
	digitalWrite(bluePin, LOW);
	digitalWrite(greenPin, HIGH);
	digitalWrite(redPin, HIGH);

	byte msg[2];
	String tmp = "ERROR";
	while (tmp.equals("ERROR")) {
		espResponse += esp.readResponse();
		if (espResponse.indexOf("+IPD,18") > 0) {
			String tmp = esp.getMessage(espResponse);
			espResponse = "";
			if (tmp.equals("ERROR")) {
				msg[0] = 'N';
				msg[1] = 'O';
				esp.sendMessage(msg, 2, espResponse);
			}
			else {
				msg[0] = 'O';
				msg[1] = 'K';
				esp.sendMessage(msg, 2, espResponse);
				byte	*randA = new byte[16],
						*randB = new byte[16],
						*key = new byte[32];
				for (int i = 0; i < 16; i++) randA[i] = tmp[i];
				String mac = esp.getMACAddress();
				for (int i = 0; i < 16; i++) randB[i] = (byte)random(256);
				byte *toHMAC = new byte[32 + mac.length()];
				for (int i = 0; i < 16; i++) toHMAC[i] = randA[i];
				free(randA);
				for (int i = 0; i < 16; i++) toHMAC[16 + i] = randB[i];
				for (int i = 0; i < mac.length(); i++) toHMAC[32 + i] = mac[i];
				for (int i = 0; i < 32; i++) key[i] = EEPROM.read(eepromAddress_aesKey + i);
				Serial2.println();
				byte *hash = new byte[32];
				hmac.hmac(key, 32, toHMAC, 32 + mac.length(), hash);
				byte *toSend = new byte[48];
				for (int i = 0; i < 16; i++) toSend[i] = randB[i];
				for (int i = 0; i < 32; i++) toSend[16 + i] = hash[i];
				free(hash);
				esp.sendMessage(toSend, 48, espResponse);
				free(toHMAC);
				free(toSend);

				tmp = "ERROR";
				while (tmp.equals("ERROR")) {
					checkConnection();
					espResponse += esp.readResponse();
					if (espResponse.indexOf("+IPD,34") > 0) {
						tmp = esp.getMessage(espResponse);
						if (tmp.equals("ERROR")) {
							msg[0] = 'N';
							msg[1] = 'O';
							esp.sendMessage(msg, 2, espResponse);
						}
						else {
							msg[0] = 'O';
							msg[1] = 'K';
							esp.sendMessage(msg, 2, espResponse);
							byte	*centralHash = new byte[32],
								*centralMAC = new byte[6];
							for (int i = 0; i < 32; i++) centralHash[i] = tmp[i];
							for (int i = 0; i < 6; i++) centralMAC[i] = EEPROM.read(eepromAddress_centralMAC + i);
							toHMAC = new byte[22];
							for (int i = 0; i < 16; i++) toHMAC[i] = randB[i];
							free(randB);
							for (int i = 0; i < 6; i++) {
								toHMAC[16 + i] = centralMAC[i];
							}
							free(centralMAC);
							hash = new byte[32];
							hmac.hmac(key, 32, toHMAC, 22, hash);
							free(key);
							free(toHMAC);
							for (int i = 0; i < 32; i++) {
								if (centralHash[i] != hash[i]) {
									free(centralHash);
									free(hash);
									return false;
								}
							}
							free(centralHash);
							free(hash);
							digitalWrite(bluePin, HIGH);
							digitalWrite(greenPin, LOW);
							digitalWrite(redPin, LOW);
							return true;
						}
					}
					else {
						espResponse = "";
						msg[0] = 'N';
						msg[1] = 'O';
						esp.sendMessage(msg, 2, espResponse);
					}
				}
			}
		}
	}
}
//konfiguracja podzespolow czytnika
void initComps() {
	Serial2.println("Initializing...");
	esp.checkESP();
	Serial2.println("ESP OK");
	esp.setUpESP();
	Serial2.println("SETUP OK");
}
//konfiguracja ukladu PN532
void setUpPN532() {
	nfc.begin();
	uint32_t versiondata = nfc.getFirmwareVersion();
	if (!versiondata) {
		wdt_enable(WDTO_15MS);
		while (true);
	}
	nfc.setPassiveActivationRetries(0xFF);
	nfc.SAMConfig();
}
//inicjowanie polaczenia z centrala
void initConnection() {
	initApConnection();
	initTcpConnection();
}
//proba polaczenia z siecia udostepniana przez centrale
void initApConnection() {
	String	ssid = "",
		password = "";
	char tmp;

	for (int i = 0; i < EEPROM.read(eepromAddress_apSSIDLength); i++) {
		tmp = (char)EEPROM.read(eepromAddress_apSSID + i);
		ssid += tmp;
	}
	for (int i = 0; i < EEPROM.read(eepromAddress_apPasswordLength); i++) {
		tmp = (char)EEPROM.read(eepromAddress_apPassword + i);
		password += tmp;
	}
	while (!esp.connectedToAP(ssid, password));
	Serial2.println("AP: CONNECTED");
}
//proba polaczenia z serwerem TCP udostepnianym przez centrale
void initTcpConnection() {
	String	serverIP = "",
		serverPort = "";

	for (int i = 0; i < 4; i++) {
		serverIP += EEPROM.read(eepromAddress_tcpServerIP + i);
		if (i != 3) serverIP += ".";
	}
	uint16_t tmp;
	tmp = ((EEPROM.read(eepromAddress_tcpServerPort) << 8) ^ EEPROM.read(eepromAddress_tcpServerPort + 1));
	serverPort = tmp;
	while (!esp.connectedToSingleTcpServer(serverIP, serverPort, espResponse));
	Serial2.println("TCP: CONNECTED");
	if (!authenticate()) {
		esp.quitAP();
		initConnection();
	};
}
//sprawdzenie stanu polaczenia
bool checkConnection() {
	char status = esp.checkConnection(espResponse);
	if (status == '4') {
		initTcpConnection();
		return false;
	}
	else if (status == '5') {
		initConnection();
		return false;
	}
	return true;
}
//weryfikacja dostepu
void control() {
	bool success;
	byte uid[] = { 0, 0, 0, 0, 0, 0, 0 };
	byte uidLength;

	success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

	if (success) {
		byte	tempBuf[16],
				aesBuf[16],
				key[32];

		for (int i = 0; i < uidLength; i++) tempBuf[i] = uid[i];
		for (int i = uidLength; i < 16; i++) tempBuf[i] = (byte)random(256);
		for (int i = 0; i < 32; i++) key[i] = EEPROM.read(eepromAddress_aesKey + i);
		aes.encrypt(tempBuf, 16, key, aesBuf);
		for (int i = 0; i < 16; i++) tempBuf[i] = 0;
		String tmp = "ERROR";
		while (tmp.equals("ERROR")) {
			unsigned long t = millis();
			while ((millis() - t < controlTimeout) && !esp.sendMessage(aesBuf, 16, espResponse));
			if (!checkConnection()) return;
			t = millis();
			while ((millis() - t < controlTimeout) && (espResponse.indexOf("+IPD,18") <= 0)) espResponse += esp.readMsgResponse();
			if (!checkConnection()) return;
			tmp = esp.getMessage(espResponse);
		}
		for (int i = 0; i < 16; i++) tempBuf[i] = (byte)tmp[i];
		aes.decrypt(tempBuf, 16, key, aesBuf);
		if (aesBuf[0] == 1) {
			digitalWrite(redPin, HIGH);
			digitalWrite(switchControlPin, HIGH);
			delay(3000);
			digitalWrite(switchControlPin, LOW);
			digitalWrite(redPin, LOW);
		}
		else {
			digitalWrite(greenPin, HIGH);
			delay(1000);
			digitalWrite(greenPin, LOW);
		}
		espResponse = "";
	}
}
//aktualizacja klucza kryptograficznego
void keyExchange() {
	espResponse += esp.readResponse();
	if (espResponse.indexOf("+IPD,3") > 0) {
		espResponse = "";
		byte msg[] = { 'O', 'K' };
		unsigned long t = millis();
		while ((millis() - t < controlTimeout) && !esp.sendMessage(msg, 2, espResponse));
		if (!checkConnection()) return;
		t = millis();
		while ((millis() - t < controlTimeout) && (espResponse.indexOf("+IPD,34") <= 0)) espResponse += esp.readMsgResponse();
		if (!checkConnection()) return;
		String tmp = esp.getMessage(espResponse);
		if (tmp.equals("ERROR")) {
			msg[0] = 'N'; msg[1] = 'O';
			esp.sendMessage(msg, 2, espResponse);
			return;
		}
		byte buffer[32];
		for (int i = 0; i < 32; i++) buffer[i] = tmp[i];
		byte newKey[32], key[32];
		for (int i = 0; i < 32; i++) key[i] = EEPROM.read(eepromAddress_aesKey + i);
		aes.decrypt(buffer, 32, key, newKey);
		for (int i = 0; i < 32; i++) EEPROM.update(eepromAddress_aesKey + i, newKey[i]);
		esp.sendMessage(msg, 2, espResponse);
		wdt_enable(WDTO_15MS);
		while (true);
	}
	else espResponse = "";
}

//zwraca wartosc calkowita znaku x - liczba hex (nie wartosc w ASCII) 
byte byteValueOf(char x) {
	switch (x)
	{
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': return 10;
	case 'b': return 11;
	case 'c': return 12;
	case 'd': return 13;
	case 'e': return 14;
	case 'f': return 15;
	case 'A': return 10;
	case 'B': return 11;
	case 'C': return 12;
	case 'D': return 13;
	case 'E': return 14;
	case 'F': return 15;
	default: return 0;
	}
}
//konwersja ciagu znakow zawierajacego znaki odpowiadajace wartosciom hex na tablice bajtow
void hexStringToBytesArray(String &msg, byte *converted, int tabLen) {
	for (int i = 0; i < tabLen; i++) {
		converted[i] = byteValueOf(msg[2 * i]);
		converted[i] = converted[i] << 4;
		converted[i] ^= byteValueOf(msg[2 * i + 1]);
	}
}
//konwersja ci¹gu znaków zawieraj¹cego wartoœæ liczby ca³kowitej na bajt
byte toByte(String &msg) {
	byte result = 0;
	int index = msg.length() - 1;
	for (int i = 0; i <= index; i++) result += (byteValueOf(msg[i])*power(10, index - i));
	return result;
}
//konwersja ci¹gu znaków zawieraj¹cego wartoœæ liczby ca³kowitej na liczbe 2-bajtowa
uint16_t toShort(String &msg) {
	uint16_t result = 0;
	int index = msg.length() - 1;
	for (int i = 0; i <= index; i++) result += (byteValueOf(msg[i])*power(10, index - i));
	return result;
}
//konwersja adresu ip na tablice bajtow
void ipAddressToByteArray(String &msg, byte *converted) {
	int beginIndex = 0,
		dotIndex = msg.indexOf(".");
	int nextDotIndex = msg.indexOf(".", dotIndex + 1);
	String tmp;

	tmp = msg.substring(0, dotIndex);
	converted[0] = toByte(tmp);
	dotIndex++;
	tmp = msg.substring(dotIndex, nextDotIndex);
	converted[1] = toByte(tmp);
	dotIndex = nextDotIndex + 1;
	nextDotIndex = msg.indexOf(".", dotIndex);
	tmp = msg.substring(dotIndex, nextDotIndex);
	converted[2] = toByte(tmp);
	dotIndex = nextDotIndex + 1;
	nextDotIndex = msg.length();
	tmp = msg.substring(dotIndex, nextDotIndex);
	converted[3] = toByte(tmp);
}
//potegowanie: base - podstawa, exp - wykladnik
int power(int base, int exp) {
	int result = 1;
	for (int i = 0; i < exp; i++) result *= base;
	return result;
}

#pragma endregion

