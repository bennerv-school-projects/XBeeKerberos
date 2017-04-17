#include <Printers.h>
#include <XBee.h>
#include "kerberos.h"
#include <AES.h>
#include <SoftwareSerial.h>
#include <assert.h>

XBee xbee= XBee();
SoftwareSerial mySerial(10, 11); // RX, TX
uint8_t* rxPayload;
uint8_t txPayload[3+4*N_BLOCK];
byte currentNode;
uint16_t address;
ZBRxResponse pck = ZBRxResponse();
ZBTxStatusResponse txStat = ZBTxStatusResponse();
AES aes;
String inputString = "";
bool stringComplete = false;

void setup() {

  inputString.reserve(60);
  Serial.begin(9600); //for uno test
  mySerial.begin(9600);
  xbee.setSerial(mySerial);
}

void loop() {
  byte opcode;
  
  xbee.readPacket();
  
  if (xbee.getResponse().isAvailable()) {
     
     if (xbee.getResponse().getApiId() == ZB_RX_RESPONSE){
       
       xbee.getResponse().getZBRxResponse(pck);
       address = pck.getRemoteAddress16();
       rxPayload = pck.getData();
       opcode = rxPayload[0];

       switch (opcode){
          case 0: {
            Serial.println("Processing opcode 0: KRB_AS_REQ");
            //Client login. 
            //Invent a 128' session key 
            //loopup clients master key using rxPayload[2]
            assert(rxPayload[1] == KRB_AS_REQ);

            //establish session key
            byte sessionKey[N_BLOCK];
            int i;
            for (i = 0; i < N_BLOCK; i ++){
              sessionKey[i] = (byte)random(0, 255);
            }
            
            //encrypt session key with clients master key
            byte cipherTxt[N_BLOCK];
            aes.set_key(masterKeys[rxPayload[2]], 128);
            aes.encrypt(sessionKey, cipherTxt);
            //form a TGT and prepare response payload
            memset(txPayload, 0, sizeof(txPayload));
            txPayload[0] = (byte)1; //set opcode to KRB_AS_REP
            txPayload[1] = KRB_AS_REP;
            memcpy(&txPayload[2], cipherTxt, sizeof(cipherTxt));
            
            TGT tgt;
            tgt.clientName[0] = rxPayload[2];
            memcpy(tgt.sessionKey, sessionKey, sizeof(sessionKey));
            aes.set_key(masterKeys[0], 128);
            aes.encrypt(tgt.clientName, cipherTxt);
            memcpy(&txPayload[2+N_BLOCK], cipherTxt, sizeof(cipherTxt));
            aes.encrypt(tgt.sessionKey, cipherTxt);
            memcpy(&txPayload[2+2*N_BLOCK], cipherTxt, sizeof(cipherTxt));

            /*debug*/ //Serial.println(rxPayload[2]);
            XBeeAddress64 addr64 = XBeeAddress64(highAddress[rxPayload[2]],lowAddress[rxPayload[2]]);
            ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
            tx.setAddress16(0xfffe);
            xbee.send(tx);
            Serial.println("  KRB_AS_REP sent");
            break;
          }
          case 2 : {
            //extract desired resource and nonce
            //extract tgt
            //build TGS_REP for client
            //generate a random session key
            //create ticket for requested resource. This conisists of the client initiating contact and the session key both encrypted with the resources master key

            Serial.println("Processing Opcode 2: KRB_TGS_REQ");
            assert(rxPayload[1] == KRB_TGS_REQ);
            /*debug*/ //Serial.println((int)rxPayload[1]);
            //establish session key
            byte sessionKey[N_BLOCK]; //= {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
            int i;
            for (i = 0; i < N_BLOCK; i ++){
              sessionKey[i] = (byte)random(0, 255);
            }

            //grag the tgt
            TGT tgt;
            
            aes.set_key(masterKeys[0], 128);
            aes.decrypt(&rxPayload[2], tgt.clientName);
            aes.decrypt(&rxPayload[2 + N_BLOCK], tgt.sessionKey);

            byte resourceInfo[N_BLOCK];
            aes.set_key(tgt.sessionKey, 128);
            aes.decrypt(&rxPayload[2+2*N_BLOCK], resourceInfo);

            //Construct response
            memset(txPayload, 0, sizeof(txPayload));
            txPayload[0] = (byte)3; //set opcode to KRB_AS_REP
            txPayload[1] = KRB_TGS_REP;
            byte cipherTxtA[4*N_BLOCK];
            byte cipherTxtB[2*N_BLOCK];
            aes.set_key(masterKeys[resourceInfo[0]], 128);//set to bob's key
            aes.encrypt(tgt.clientName, &cipherTxtB[0]);
            aes.encrypt(sessionKey, &cipherTxtB[N_BLOCK]);
            
            aes.set_key(tgt.sessionKey, 128); //set to alice's key
            aes.encrypt(resourceInfo, &cipherTxtA[0]);
            aes.encrypt(sessionKey, &cipherTxtA[N_BLOCK]);
            aes.encrypt(&cipherTxtB[0], &cipherTxtA[2*N_BLOCK]);
            aes.encrypt(&cipherTxtB[N_BLOCK], &cipherTxtA[3*N_BLOCK]);

            //build tx packet and send to alice
            memcpy(&txPayload[2], cipherTxtA, sizeof(cipherTxtA));
            XBeeAddress64 addr64 = XBeeAddress64(highAddress[tgt.clientName[0]],lowAddress[tgt.clientName[0]]);
            ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
            tx.setAddress16(0xfffe);
            xbee.send(tx);
            Serial.println("  KRB_TGS_REP sent");
            //Serial.println(highAddress[rxPayload[2]]);
            //Serial.println(lowAddress[rxPayload[2]]);
            //Serial.print("K_AB = "); Serial.println(sessionKey);
            
            break;
          }
          case 7: {
            byte messageLength = rxPayload[1];
            Serial.println("Opcode 7: Control layer - Received a message");
            char message[messageLength+1] = {0};

            // Print out the message over serial
            memcpy(message, &rxPayload[2], messageLength);
            Serial.println(message);
            break;
         
          }
          default : {
            break;
          }


        
       }

     }else if (xbee.getResponse().getApiId() == ZB_TX_STATUS_RESPONSE){
        xbee.getResponse().getZBTxStatusResponse(txStat);
        if (txStat.getDeliveryStatus() == SUCCESS){
          Serial.println("    XBEE TX Success");
        } else {
          Serial.println("    XBEE TX failed");
        }
     }
   }else if(xbee.getResponse().isError()){
    Serial.println("error ");
    Serial.println(xbee.getResponse().getErrorCode());
    }
  
  if (stringComplete) {
    //Serial.println(inputString);
    byte initiator = inputString[0] - 48;
    byte receiver = inputString[2] - 48;
    char messageLength[3];
    messageLength[0] = inputString[4];
    messageLength[1] = inputString[5];
    messageLength[2] = '\0';
    byte len = (byte)atoi(messageLength);

    //debug
    Serial.println("Command layer - revieved input from user. Simulating command.");
    Serial.print("  Initiator "); Serial.println(initiator, DEC);
    Serial.print("  Reciever "); Serial.println(receiver, DEC);
    Serial.print("  Message length "); Serial.println(len, DEC);
    Serial.print("  CMD Message = "); Serial.println(inputString);
    
    memset(txPayload, 0, sizeof(txPayload));
    txPayload[0] = 8;
    txPayload[1] = receiver;
    txPayload[2] = len;
    memcpy(&txPayload[3], &inputString[7], len);

    // Send the data over to the correct xbee
    XBeeAddress64 addr64 = XBeeAddress64(highAddress[initiator], lowAddress[initiator]);
    ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
    tx.setAddress16(0xfffe);
    xbee.send(tx);    

    Serial.println("    CMD sent.");
    // clear the string:
    inputString = "";
    stringComplete = false;
  }
}

void serialEvent() {
  while (Serial.available()) {
    // get the new byte:
    char inChar = (char)Serial.read();
    // add it to the inputString:
    inputString += inChar;
    // if the incoming character is a newline, set a flag
    // so the main loop can do something about it:
    if (inChar == '\n') {
      stringComplete = true; 
    }
  }
    
}
