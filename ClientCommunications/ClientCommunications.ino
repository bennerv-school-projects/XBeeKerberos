#include <Printers.h>
#include <XBee.h>
#include <AES.h>
#include <assert.h>
#include <SoftwareSerial.h>

#include "kerberos.h"

/* CHANGE LOG
 * Date       Name       Changes
 * -----------------------------------------------------------------------------
 * 04/01/17   Ben        File creation
 * 04/12/17   Ben        Kerberos commands and processing opcode 1
 * -----------------------------------------------------------------------------
 * Kerberos client on arduino
 * ----------------------------------------------------------------------------- 
 */

AES aes;
uint8_t myIndex = 1;

SoftwareSerial mySerial(10, 11);
XBee xbee = XBee();
ZBRxResponse rx = ZBRxResponse();
ZBTxStatusResponse txStatus = ZBTxStatusResponse();

byte session_key[5][N_BLOCK] = {0};
byte txPayload[3+(3*N_BLOCK)];
uint8_t * rxPayload;

bool isConnected = false;
TGT tgt; // TGT between myself and the KDC
byte nonce[5] = {0};



void setup() {
  
  // Start the serial with a baud rate of 9600
  Serial.begin(9600);
  mySerial.begin(9600);
  xbee.setSerial(mySerial);
  
  
  // Set the key in the AES object (128 bit key)
  aes.set_key(masterKeys[myIndex], 128);

  // Send the opcode 0 to connect to the KDC
  isConnected = false;
  announceLogin();

}

void loop() {
  
  // Read a packet from the KDC
  xbee.readPacket();

  // Make sure that the xbee is available to receive
  if(xbee.getResponse().isAvailable()) {
    Serial.println("Saw a packet");
    
    // Check if we have received a response
    if(xbee.getResponse().getApiId() == ZB_RX_RESPONSE) {
      Serial.println("Received a ZB_RX Packet");
      
      // get the response and store it in a txPayload pointer
      xbee.getResponse().getZBRxResponse(rx);
      rxPayload = rx.getData();
      
      uint8_t command = rxPayload[0];
    
      // Switch on each of the opcodes read, then read the rest of the data
      switch(command) {
        
        // Shouldn't ever receive this, only send it out 
        case 0: {
          assert(0);
        }
          break;
  
        // Receiving a TGT and session key back from the KDC
        case 1: {
          byte kerb_command = rxPayload[1];
          assert(kerb_command == KRB_AS_REP);
  
          // Read two blocks.  The first containing ciphertext with the client (my) name in it
          byte cipherFirstBlock[N_BLOCK] = {0};
          byte cipherSecondBlock[N_BLOCK] = {0};
          byte cipherThirdBlock[N_BLOCK] = {0};
          memcpy(cipherFirstBlock, &rxPayload[2], N_BLOCK);
          memcpy(cipherSecondBlock, &rxPayload[2+N_BLOCK], N_BLOCK);
          memcpy(cipherThirdBlock, &rxPayload[2+(2*N_BLOCK)], N_BLOCK);
  
          byte plainFirstBlock[N_BLOCK] = {0};

          // Decrypt the session key encrypted by my master key
          aes.set_key(masterKeys[myIndex], 128);
          aes.decrypt(cipherFirstBlock, plainFirstBlock);
  
          // Copy the session key for further communication
          memcpy(&session_key[myIndex], plainFirstBlock, sizeof(byte) * N_BLOCK);
  
          // Copy the TGT for further communication
          memcpy(tgt.clientName, cipherSecondBlock, sizeof(byte) * N_BLOCK);
          memcpy(tgt.sessionKey, cipherThirdBlock, sizeof(byte) * N_BLOCK);
          
          isConnected = true;

          // Print out the session key to make sure everything is working correctly at this point
          Serial.print((char *)session_key[myIndex]);
          
          Serial.println();
        }
          break;
  
        // Logging into a resource.  Shouldn't ever receive this, only send it out
        case 2: {
          assert(0);
        }
          break;
  
        // Receiving a login token for another resource.
        case 3: {
          byte kerb_command = Serial.read();
          assert(kerb_command == KRB_TGS_REP);
  
          // Make sure we are connected
          assert(isConnected);
  
          // Storage for cipher/plaintext blocks being read
          byte cipherFirstBlock[N_BLOCK] = {0};
          byte cipherSecondBlock[N_BLOCK] = {0};
          byte cipherThirdBlock[N_BLOCK] = {0};
          byte cipherFourthBlock[N_BLOCK] = {0};
  
          byte plainFirstBlock[N_BLOCK] = {0};
          byte plainSecondBlock[N_BLOCK] = {0};
          byte plainThirdBlock[N_BLOCK] = {0};
          byte plainFourthBlock[N_BLOCK] = {0};
  
          // Read from the serial port
          Serial.readBytes(cipherFirstBlock, N_BLOCK); 
          Serial.readBytes(cipherSecondBlock, N_BLOCK); 
          Serial.readBytes(cipherThirdBlock, N_BLOCK); 
          Serial.readBytes(cipherFourthBlock, N_BLOCK); 
  
          // Decrypt the response from the KDC
          aes.set_key(session_key[myIndex], 128);
          aes.decrypt(cipherFirstBlock, plainFirstBlock); // Name of person to send to 
          aes.decrypt(cipherSecondBlock, plainSecondBlock); // Session key between myself and other 
          aes.decrypt(cipherThirdBlock, plainThirdBlock);  // Name of me (encrypted in TGT
          aes.decrypt(cipherFourthBlock, plainFourthBlock); // Session key between myself and other (encrypted by Bob's master key)
  
          // Save the session key between the other party
          byte readClientName = plainFirstBlock[0];
          memcpy(&session_key[readClientName], plainSecondBlock, N_BLOCK);
  
          // Save the TGT for the other party for further communication
          memcpy(tgt.clientName, plainThirdBlock, N_BLOCK);
          memcpy(tgt.sessionKey, plainFourthBlock, N_BLOCK); 
        }
          break;
  
        // Receiving a authentication from a client
        case 4: {
          byte kerb_command = Serial.read();
          assert(kerb_command == KRB_AP_REQ);
  
          // Storage for cipher/plaintext blocks being read
          byte cipherFirstBlock[N_BLOCK] = {0};
          byte cipherSecondBlock[N_BLOCK] = {0};
          byte cipherThirdBlock[N_BLOCK] = {0};
          byte data[N_BLOCK + 2] = {0};
  
          byte plainFirstBlock[N_BLOCK] = {0};
          byte plainSecondBlock[N_BLOCK] = {0};
          byte plainThirdBlock[N_BLOCK] = {0};
  
          // Grab the ticket and get the session key out of it
          Serial.readBytes(cipherSecondBlock, N_BLOCK);
          Serial.readBytes(cipherSecondBlock, N_BLOCK);
          Serial.readBytes(cipherThirdBlock, N_BLOCK);
  
          // Decrypt the ticket
          aes.set_key(masterKeys[myIndex], 128);
          aes.decrypt(cipherFirstBlock, plainFirstBlock);
          aes.decrypt(cipherSecondBlock, plainSecondBlock);
  
          // Save the session key of the person for further communication
          byte sender = plainFirstBlock[0];
          memcpy(&session_key[sender], plainSecondBlock, N_BLOCK);
  
          // Decrypt the timestamp
          aes.set_key(session_key[sender], 128);
          aes.decrypt(cipherThirdBlock, plainThirdBlock);
  
          // Add one from the timestamp first byte
          plainThirdBlock[0] += 1;
          aes.encrypt(plainThirdBlock, cipherThirdBlock);
  
          // Send back the authentication
          data[0] = 5;
          data[1] = KRB_AP_REP;
          memcpy(&data[2], cipherThirdBlock, N_BLOCK);
          Serial.write(data, sizeof(data));
        }
          break;
  
        // Authenticating oneself to a client
        case 5: {
          
        }
          break;
  
        // Sending a message/command to a client
        case 6: {
          
        }
          break;
  
        // Send a message to print out - shouldn't ever receive this only send it out
        case 7:  {
          assert(0);
        }
          break;
  
        // Keep alive message, shoudln't ever receive this only send it out
        case 8: {
          assert(0);
        }
          break;
          
        default: {
          
        }
          break;
      }
    } else if(xbee.getResponse().getApiId() == ZB_TX_STATUS_RESPONSE) {
      xbee.getResponse().getZBTxStatusResponse(txStatus);

      if(txStatus.getDeliveryStatus() == SUCCESS) {
        Serial.println("Transmit successful");
      } else {
        Serial.println("Transmit failed");
        if(!isConnected) {
          Serial.println("Reannouncing login");
          announceLogin();
        }
      }
    }
  } else if(xbee.getResponse().isError()){
    Serial.println("Error: " + xbee.getResponse().getErrorCode());
  }

}

/* 
 * Announces the login to the server and establishes a TGT between the KDC and the client
 * Happens on xbee power on - OPCODE 0
 * 
 * Sends the folllowing information over serial:
 *  byte - The opcode of the operation to perform (0 in this case)
 *  byte - The KRB_AS_REQ command
 *  byte - The clientName to identify itself
 */
void announceLogin() {
  memset(txPayload, 0, sizeof(txPayload));
  txPayload[0] = 0; // The opcode number 
  txPayload[1] = KRB_AS_REQ; // the command being sent
  txPayload[2] = myIndex; // the client announcing themselves

  // Grab the address of the server and form a new address
  XBeeAddress64 addr64 = XBeeAddress64(highAddress[0], lowAddress[0]);
  
  // Send out the data
  ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
  tx.setAddress16(0xfffe);
  xbee.send(tx);
  Serial.println("Announcing login");
}

/* 
 * Announces to the KDC that it wants to log into the resource (resourceId)
 * 
 * Args: 
 *   byte - the resource attempting to log into
 * 
 * Sends the folllowing information over serial:
 *  byte            - The opcode of the operation to perform (2 in this case)
 *  byte            - The KRB_TGS_REQ command
 *  byte[2*N_BLOCK] - TGT
 *  byte[N_BLOCK]   - Requested resource and authenticator nonce 
 */
void loginToResource(byte resourceId) {
  byte timestamp[N_BLOCK] = {0};
  byte cipherTimestamp[N_BLOCK] = {0};

  // Make sure we are connected first
  if(!isConnected) {
    return;
  }

  // Opcodes
  txPayload[0] = 2; // the opcode number
  txPayload[1] = KRB_TGS_REQ; // the command being sent

  // TGT
  memcpy(&txPayload[2], tgt.clientName, N_BLOCK);
  memcpy(&txPayload[2+N_BLOCK], tgt.sessionKey, N_BLOCK);

  // Generate "nonce" for timestamp and who I want to talk to 
  timestamp[0] = resourceId;
  timestamp[1] = (byte)random(0, 255);

  // Encrypt the timestamp
  aes.set_key(session_key[myIndex], 128);
  aes.encrypt(timestamp, cipherTimestamp);

  // Authenticator and who to talk to
  memcpy(&txPayload[2+(2*N_BLOCK)], cipherTimestamp, N_BLOCK);

  // Write out the data to the KDC
  Serial.write(txPayload, sizeof(txPayload));
}

/* 
 * Have this client connect to the desired other client (no KDC middleman)
 * 
 * Args: 
 *   byte - the resource attempting to authenticate
 * 
 * Sends the folllowing information over serial:
 *  byte            - The opcode of the operation to perform (2 in this case)
 *  byte            - The KRB_AP_REQ command
 *  byte[2*N_BLOCK] - TGT of the other person
 *  byte[N_BLOCK]   - Authenticator nonce 
 */
void connectToResource(byte resourceId) {
  byte timestamp[N_BLOCK] = {0};
  byte cipherTimestamp[N_BLOCK] = {0};

  // Opcodes
  txPayload[0] = 4;
  txPayload[1] = KRB_AP_REQ;

  // TGT copying (encrypted with other party's master key)
  memcpy(&txPayload[2], tgt.clientName, N_BLOCK);
  memcpy(&txPayload[2], tgt.sessionKey, N_BLOCK);

  // Generate "nonce" for timestamp and who I want to talk to 
  timestamp[0] = (byte)random(0, 255);
  nonce[resourceId] = timestamp[0];

  // Encrypt the timestamp
  aes.set_key(session_key[myIndex], 128);
  aes.encrypt(timestamp, cipherTimestamp);

  // Authenticator and who to talk to
  memcpy(&txPayload[2+(2*N_BLOCK)], cipherTimestamp, N_BLOCK);

  // Write out the data to the corresponding node
  Serial.write(txPayload, sizeof(txPayload));
}

