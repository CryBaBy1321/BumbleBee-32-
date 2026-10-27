/*
  BumbleBee32 — Unified Honeypot, PMF Protection & IDS Firmware
  --------------------------------------------------------------
  - Hosts a PMF-Protected Access Point (PMF customizable via REQUIRE_PMF).
  - Listens in Promiscuous Mode for Deauthentication/Disassociation bursts.
  - Hosts HTTP & Telnet Honeypot service stubs.
  - Reports all events in real-time to the Flask backend server.
*/

#include <WiFi.h>
#include <HTTPClient.h>
extern "C" {
  #include "esp_wifi.h"
}

// Set to true for 802.11w PMF Protection, false for Vulnerable Baseline
#define REQUIRE_PMF false 

const char* ap_ssid      = "BumbleBee32_Secure";
const char* ap_password  = "testpass123";

// Server details for backend logging
const char* backend_url  = "http://10.137.49.100:5000/api/log"; 

// Honeypot Services
WiFiServer telnetServer(23);
WiFiServer httpServer(80);

// Deauth attack detection variables
volatile uint32_t deauth_count = 0;
uint32_t last_deauth_time = 0;
const uint32_t DEAUTH_THRESHOLD = 5; // Bursts >= 5 frames trigger an IDS event

// Wi-Fi Promiscuous Packet Sniffer Callback
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t *payload = pkt->payload;
  
  // Frame control byte check: 0xC0 = Deauth, 0xA0 = Disassociate
  uint8_t frame_type = payload[0];
  if (frame_type == 0xC0 || frame_type == 0xA0) {
    deauth_count++;
  }
}

esp_err_t applyPmfSetting() {
  wifi_config_t conf;
  memset(&conf, 0, sizeof(conf));
  esp_wifi_get_config(WIFI_IF_AP, &conf);
  conf.ap.pmf_cfg.required = REQUIRE_PMF;
  conf.ap.pmf_cfg.capable = true;
  return esp_wifi_set_config(WIFI_IF_AP, &conf);
}

void logEventToBackend(String attackType, String srcIp, String details) {
  if (WiFi.status() == WL_CONNECTED || WiFi.softAPgetStationNum() > 0) {
    HTTPClient http;
    http.begin(backend_url);
    http.addHeader("Content-Type", "application/json");
    
    String jsonPayload = "{\"attack_type\":\"" + attackType + 
                         "\",\"src_ip\":\"" + srcIp + 
                         "\",\"details\":\"" + details + 
                         "\",\"pmf_status\":\"" + (REQUIRE_PMF ? "PROTECTED" : "VULNERABLE") + "\"}";
                         
    http.POST(jsonPayload);
    http.end();
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Configure Access Point Mode with PMF
  WiFi.mode(WIFI_AP);
  WiFi.softAPdisconnect(true);
  delay(500);
  WiFi.softAP(ap_ssid, ap_password);
  delay(200);
  
  esp_err_t err = applyPmfSetting();
  
  Serial.println("\n--- BumbleBee32 IDS & Protection System ---");
  Serial.print("AP SSID: "); Serial.println(ap_ssid);
  Serial.print("PMF Required: "); Serial.println(REQUIRE_PMF ? "YES (Protected)" : "NO (Vulnerable Baseline)");
  Serial.print("PMF Config Status: "); Serial.println(err == ESP_OK ? "SUCCESS" : "FAILED");
  Serial.print("AP IP Address: "); Serial.println(WiFi.softAPIP());
  Serial.print("AP MAC Address (BSSID): "); Serial.println(WiFi.softAPmacAddress());

  // Start Promiscuous Sniffer for Deauth Detection
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

  // Start Honeypot Services
  telnetServer.begin();
  httpServer.begin();
}

void loop() {
  // 1. Process Deauth Bursts
  if (deauth_count >= DEAUTH_THRESHOLD) {
    uint32_t now = millis();
    if (now - last_deauth_time > 2000) { // Rate limit logging to every 2 seconds
      Serial.println("[ALERT] Deauth Attack Burst Detected!");
      logEventToBackend("WIFI_DEAUTH_FLOOD", "AIR_INTERFACE", "Detected " + String(deauth_count) + " management frames.");
      deauth_count = 0;
      last_deauth_time = now;
    }
  }

  // 2. HTTP Honeypot Trap
  WiFiClient httpClient = httpServer.available();
  if (httpClient) {
    String clientIP = httpClient.remoteIP().toString();
    String req = httpClient.readStringUntil('\r');
    Serial.println("[HONEYPOT] HTTP Probe from: " + clientIP);
    logEventToBackend("HTTP_HONEYPOT_PROBE", clientIP, req);
    
    httpClient.println("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>BumbleBee32 Management Gateway</h1>");
    httpClient.stop();
  }

  // 3. Telnet Honeypot Trap
  WiFiClient telnetClient = telnetServer.available();
  if (telnetClient) {
    String clientIP = telnetClient.remoteIP().toString();
    Serial.println("[HONEYPOT] Telnet Connection Attempt from: " + clientIP);
    logEventToBackend("TELNET_UNAUTHORIZED_ACCESS", clientIP, "Attempted root shell login");
    
    telnetClient.println("BumbleBee32 Embedded OS v1.02");
    telnetClient.print("login: ");
    delay(1000);
    telnetClient.stop();
  }
}