#ifndef _ESP8266_h
#define _ESP8266_h

#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

class ESP8266
{
public:
	ESP8266();

	//sprawdzenie komunikacji z modulem
	void checkESP();
	//konfiguracja parametrow modulu
	void setUpESP();
	//zwraca adres MAC modulu
	String getMACAddress();
	//proba polaczenia z siecia networkSSID
	bool connectedToAP(String networkSSID, String networkPassword);
	//proba polaczenia z serwerem TCP
	bool connectedToSingleTcpServer(String tcpServerIP, String tcpServerPort, String &response);
	//zerwanie polaczenia z siecia
	void quitAP();
	//wyodrebnienie wiadomosci z komendy "+IPD"
	String getMessage(String &message);
	//wyslanie wiadomosci
	bool sendMessage(byte *message, byte messageLength, String &response);
	//odczytanie odpowiedzi modulu
	String readResponse();
	String readMsgResponse();
	//sprawdzenie stanu polaczenia
	char checkConnection(String &espResponse);
	//ponowne uruchomienie modulu
	void resetESP();
	//oproznienie zawartosci bufora portu szeregowego Serial
	void flushSerial();
	//while(true);
	void stop();
};

#endif
