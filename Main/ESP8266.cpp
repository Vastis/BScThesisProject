#include "ESP8266.h"
#include <avr/wdt.h>

ESP8266::ESP8266() {

}

void ESP8266::checkESP() {
	String message = "";
	Serial2.print("Checking ESP...");
	flushSerial();
	Serial.println("AT");
	delay(200);
	message = readResponse();
	if (message.indexOf("OK") <= 0) {
		Serial2.println("No ESP found.");
		wdt_enable(WDTO_15MS);
		stop();
	}
}
void ESP8266::setUpESP() {
	String message = "";
	Serial2.print("Setting up...");
	flushSerial();
	while (message.indexOf("OK") <= 0) {
		Serial.println("AT+CWMODE=3");
		delay(200);
		message = readResponse();
	}
	message = "";
	while (message.indexOf("OK") <= 0) {
		Serial.println("AT+IPR=115200");
		delay(200);
		message = readResponse();
	}
	resetESP();
}
String ESP8266::getMACAddress() {
	String result = "";
	Serial.println("AT+CIPSTAMAC?");
	String response = readResponse();
	int index = response.indexOf("CIPSTAMAC:");
	index += 11;
	for (int i = 0; i < 6; i++) {
		result += response.substring(index, index + 2);
		index += 3;
	}
	return result;
}
bool ESP8266::connectedToAP(String networkSSID, String networkPassword) {
	Serial2.print("Trying to connect to the network...");
	unsigned long timeout = 5000;
	unsigned long t = 0;

	flushSerial();
	Serial.println("AT+CWJAP=\"" + networkSSID + "\",\"" + networkPassword + "\"");
	t = millis();
	while (millis() - t < timeout) {
		while (Serial.available() > 0) {
			String message = readResponse();
			if (message.indexOf("OK") > 0) return true;

		}
	}
	Serial2.println();
	return false;
}
bool ESP8266::connectedToSingleTcpServer(String tcpServerIP, String tcpServerPort, String &response) {
	unsigned long timeout = 5000;
	unsigned long t = 0;

	flushSerial();
	Serial2.print("Trying to connect to TCP server (IP: " + tcpServerIP + ", port: " + tcpServerPort + ")...");
	Serial.println("AT+CIPMUX=0");
	delay(200);
	String message = readResponse();
	if (!message.indexOf("OK") > 0 && !message.indexOf("link is builded") > 0) {
		Serial2.println("Error occured. Trying again...");
		return false;
	}
	flushSerial();
	Serial.println("AT+CIPSTART=\"TCP\",\"" + tcpServerIP + "\"," + tcpServerPort);
	t = millis();
	while (millis() - t < timeout) {
		if (Serial.available() > 0) {
			message = readResponse();
			if (message.indexOf("CONNECT") >= 0) {
				delay(100);
				if (message.indexOf("+IPD") > 0) response += message;
				return true;
			}
			flushSerial();
		}
	}
	Serial2.println();
	return false;
}
void ESP8266::quitAP()
{
	String response = "";
	while (response.indexOf("OK") <= 0) {
		Serial.println("AT+CWQAP");
		response = readResponse();
	}
}
String ESP8266::getMessage(String &message) {
	int index1 = message.indexOf("+IPD") + 5;
	int index2 = message.indexOf(":", index1);
	int length = message.substring(index1, index2).toInt();
	index1 = index2 + 1;
	index2 = index1 + length;
	String result = message.substring(index1, index2);
	if (result.length() >= 32) {
		if ((result[31] != 0) && (result[30] != 0)) return result;
	}
	if ((result[result.length() - 1] != 110) && (result[result.length() - 2] != 110)) return "ERROR";
	else return result;
}
bool ESP8266::sendMessage(byte *message, byte messageLength, String &response) {
	unsigned long timeout = 1000;
	String debug;

	String command = "AT+CIPSEND=";
	command += messageLength;

	unsigned long t = millis();
	while (millis() - t < timeout) {
		Serial.println(command);
		debug = readResponse();
		if (debug.indexOf('>') > 0) {
			for (int i = 0; i < messageLength; i++) Serial.write(message[i]);
			Serial.println();
			delay(50);
			response = readMsgResponse();
			if (response.indexOf("SEND OK") > 0) {
				return true;
			}
			else return false;
		}
	}
	return false;
}
String ESP8266::readMsgResponse() {
	unsigned long timeout = 100;
	unsigned long t = millis();
	String data = "";

	Serial.setTimeout(100);
	while (millis() - t < timeout) {
		if (Serial.available() > 0) {
			String r = Serial.readStringUntil(110);
			data += r;
			char next = Serial.read();
			if (next == 110) {
				data += next;
				next = Serial.read();
				if (next == 110) {
					data += next;
					return data;
				}
				else return data;
			}
			else data += next;
			t = millis();
		}
	}
	return data;
}
String ESP8266::readResponse() {
	unsigned long timeout = 100;
	unsigned long t = millis();
	String data = "";

	while (millis() - t < timeout) {
		if (Serial.available() > 0) {
			char r = Serial.read();
			data += r;
			t = millis();
		}
	}
	return data;
}
char ESP8266::checkConnection(String &espResponse) {
	unsigned long timeout = 1000;
	Serial.println("AT+CIPSTATUS");
	unsigned long t = millis();
	while (millis() - t < timeout) {
		String response = readMsgResponse();
		if (response.indexOf("+IPD") > 0) {
			espResponse += response;
			return '3';
		}
		if (response.indexOf("STATUS:5") > 0) return '5';
		if (response.indexOf("STATUS:4") > 0) return '4';
		if (response.indexOf("STATUS:3") > 0) return '3';
	}
	return '5';
}
void ESP8266::resetESP() {
	unsigned long timeout = 7000;
	unsigned long t = millis();
	bool ready = false;

	flushSerial();
	Serial.println("AT+RST");
	String message = "";
	while (millis() - t < timeout && !ready) {
		if (Serial.available() > 0) {
			message += readResponse();
			if (message.indexOf("ready") > 0) ready = true;
			delay(50);
		}
	}
	if (!ready) {
		Serial2.println("Error occured. Shutting down...");
		stop();
	}
}

void ESP8266::flushSerial() {
	while (Serial.available() > 0) Serial.read();
}
void ESP8266::stop() {
	while (true);
}