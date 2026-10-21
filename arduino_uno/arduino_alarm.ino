/*
 * Kiarash Security System - Arduino Uno 8-Channel Optocoupler Relay Controller
 * Note: Optocoupler relays are usually Active LOW (LOW = ON, HIGH = OFF)
 */

const int RELAY_SIREN = 2;       // Channel 1: Main Siren
const int RELAY_STROBE = 3;      // Channel 2: Strobe Light
const int RELAY_AUX1 = 4;        // Channel 3: Aux 1
const int RELAY_AUX2 = 5;        // Channel 4: Aux 2
const int RELAY_PINS[8] = {2, 3, 4, 5, 6, 7, 8, 9};

bool alarmLatched = false;
unsigned long lastHeartbeat = 0;

void setup() {
  Serial.begin(9600);
  for (int i = 0; i < 8; i++) {
    pinMode(RELAY_PINS[i], OUTPUT);
    digitalWrite(RELAY_PINS[i], HIGH); // OFF by default (Active LOW)
  }
  Serial.println("READY:ARDUINO_UNO_SECURITY");
}

void triggerAlarm() {
  alarmLatched = true;
  digitalWrite(RELAY_SIREN, LOW);  // Turn ON Siren
  digitalWrite(RELAY_STROBE, LOW); // Turn ON Strobe
  Serial.println("STATUS:ALARM_ON");
}

void stopAlarm() {
  alarmLatched = false;
  for (int i = 0; i < 8; i++) {
    digitalWrite(RELAY_PINS[i], HIGH); // Turn OFF all relays
  }
  Serial.println("STATUS:ALARM_OFF");
}

void loop() {
  if (Serial.available() > 0) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    if (cmd == "ALARM_ON") {
      triggerAlarm();
    } 
    else if (cmd == "ALARM_OFF") {
      stopAlarm();
    } 
    else if (cmd == "PING") {
      lastHeartbeat = millis();
      Serial.println("PONG");
    } 
    else if (cmd == "TEST_SIREN") {
      digitalWrite(RELAY_SIREN, LOW);
      delay(1500);
      if (!alarmLatched) {
        digitalWrite(RELAY_SIREN, HIGH);
      }
      Serial.println("TEST:SIREN_OK");
    }
  }
}
