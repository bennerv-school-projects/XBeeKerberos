#include <AES.h>

#include <Printers.h>
#include <XBee.h>
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
bool connectedPeers[5] = {false, false, false, false, false};
byte txPayload[3+(4*N_BLOCK)];
uint8_t * rxPayload;

TGT tgt; // TGT between myself and the KDC
byte nonce[5] = {0};



void setup() {
  
  // Start the serial with a baud rate of 9600
  Serial.begin(9600);
  mySerial.begin(9600);
  xbee.setSerial(mySerial);
  announceLogin();
}

void loop() {
  
  // Read a packet from the KDC
  xbee.readPacket();

  // Make sure that the xbee is available to receive
  if(xbee.getResponse().isAvailable()) {
    //Serial.println("Saw a packet");
    
    // Check if we have received a response
    if(xbee.getResponse().getApiId() == ZB_RX_RESPONSE) {
      //Serial.println("Received a ZB_RX Packet");
      
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
          Serial.println("Opcode 1: Getting TGT from KDC");
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
          
          connectedPeers[0] = true;

          // Log into the desired resource
          loginToResource(2);
        }
          break;
  
        // Logging into a resource.  Shouldn't ever receive this, only send it out
        case 2: {
          assert(0);
        }
          break;
  
        // Receiving a login token for another resource.
        case 3: {
          Serial.println("Opcode 3: Receiving a token from KDC to login to someone");
          byte kerb_command = rxPayload[1];
          assert(kerb_command == KRB_TGS_REP);
  
          // Make sure we are connected to the KDC
          assert(connectedPeers[0]);
  
          // Storage for cipher/plaintext blocks being read
          byte plainFirstBlock[N_BLOCK] = {0};
          byte plainSecondBlock[N_BLOCK] = {0};
          byte plainThirdBlock[N_BLOCK] = {0};
          byte plainFourthBlock[N_BLOCK] = {0};
  
          // Decrypt the response from the KDC
          aes.set_key(session_key[myIndex], 128);
          aes.decrypt(&rxPayload[2], plainFirstBlock); // Name of resource requested (index) 
          aes.decrypt(&rxPayload[2+N_BLOCK], plainSecondBlock); // Session key between myself and other 
          aes.decrypt(&rxPayload[2+(2*N_BLOCK)], plainThirdBlock);  // Name of me (encrypted by other's master key)
          aes.decrypt(&rxPayload[2+(3*N_BLOCK)], plainFourthBlock); // Session key between myself and other (encrypted by Bob's master key)
  
          // Save the session key between the other party
          byte readClientName = plainFirstBlock[0];
          memcpy(&session_key[readClientName], plainSecondBlock, N_BLOCK);

          switch(readClientName) {
            case 0: {
              Serial.println("Connecting to resource id 0");
              break;
            }
            case 1: {
              Serial.println("Connecting to resource id 1");
              break;
            }
            case 2: {
              Serial.println("Connecting to resource id 2");
              break;
            }
            case 3: {
              Serial.println("Connecting to resource id 3");
              break;
            }
            case 4: {
              Serial.println("Connecting to resource id 4");
              break;
            }
            default: {
              Serial.println("Trying to connect to an invalid resource id");
            }
          }
 
          // Initialize an authentication operation between myself and the other party
          authenticateResource(plainThirdBlock, plainFourthBlock, readClientName);
          
        }
          break;
  
        // Receiving a authentication from a client
        case 4: {
          Serial.println("Opcode 4: Receive authentication message from a client");
          byte kerb_command = rxPayload[1];
          assert(kerb_command == KRB_AP_REQ);
          memset(txPayload, 0, sizeof(txPayload));

          // Storage for plaintext information  
          byte plainTicketName[N_BLOCK] = {0};
          byte plainTicketKey[N_BLOCK] = {0};
          byte plainThirdBlock[N_BLOCK] = {0};
  
          // Decrypt the ticket
          aes.set_key(masterKeys[myIndex], 128);
          aes.decrypt(&rxPayload[2], plainTicketName);
          aes.decrypt(&rxPayload[2+N_BLOCK], plainTicketKey);
  
          // Save the session key of the person for further communication
          byte sender = plainTicketName[0];
          memcpy(&session_key[sender], plainTicketKey, N_BLOCK);
  
          // Decrypt the timestamp
          aes.set_key(session_key[sender], 128);
          aes.decrypt(&rxPayload[2+(2*N_BLOCK)], plainThirdBlock);
  
          // Add one from the timestamp first byte
          plainThirdBlock[0] += 1;
          aes.encrypt(plainThirdBlock, &txPayload[3]);
  
          // Build the authentication packet
          txPayload[0] = 5;
          txPayload[1] = KRB_AP_REP;
          txPayload[2] = myIndex; // Make sure the person I'm communicating with knows who I am

          // Send out the authentication packet
          XBeeAddress64 addr64 = XBeeAddress64(highAddress[sender], lowAddress[sender]);
          ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
          tx.setAddress16(0xfffe);
          xbee.send(tx);
          
          // Set the corresponding connection as true with this peer
          connectedPeers[sender] = true;
        }
          break;
  
        // Authenticating oneself to a client
        case 5: {

          Serial.println("Opcode 5: Final authentication with another client");
          
          byte kerb_command = rxPayload[1];
          assert(kerb_command == KRB_AP_REP);

          // Who sent me this packet
          byte sender = rxPayload[2];

          // Set the key and decrypt the response, making sure the nonce is 1+nonce before
          byte plaintextNonce[N_BLOCK] = {0};
          aes.set_key(session_key[sender], 128);
          aes.decrypt(&rxPayload[3], plaintextNonce);

          // Check the nonce is correct
          if(plaintextNonce[0] == (nonce[sender]+1) ) {
            connectedPeers[sender] = true;
            Serial.println("Successfully authenticated with client");
          }
        }
          break;
  
        // Sending a message/command to a client
        case 6: {
          byte senderIndex = rxPayload[1];
          byte messageLength = rxPayload[2];

          Serial.println("Opcode 6: Received a command");
          memset(txPayload, 0, sizeof(txPayload));

          // Place to store the message
          txPayload[0] = 7;
          txPayload[1] = messageLength;

          // Set the encryption key
          aes.set_key(session_key[senderIndex], 128);

          // Decrypt the message
          for(int i = 0; i < messageLength; i+= N_BLOCK) {
            aes.decrypt(rxPayload[3+i], txPayload[2+i]);
          }

          // Print command to the KDC 
          XBeeAddress64 addr64 = XBeeAddress64(highAddress[0], lowAddress[0]);
          ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
          tx.setAddress16(0xfffe);
          xbee.send(tx);
        }
          break;
  
        // Send a message to print out - shouldn't ever receive this only send it out
        case 7:  {
          assert(0);
        }
          break;
  
        // Command to do something from the server
        case 8: {
          
        }
          break;
          
        default: {
          
        }
          break;
      }
    } else if(xbee.getResponse().getApiId() == ZB_TX_STATUS_RESPONSE) {
      xbee.getResponse().getZBTxStatusResponse(txStatus);

      if(txStatus.getDeliveryStatus() == SUCCESS) {
        Serial.println("Transmit Success");
      } else {
        Serial.println("Transmit failed");
        if(!connectedPeers[0]) {
          Serial.println("Reannouncing login");
          announceLogin();
        }
      }
    }
  } else if(xbee.getResponse().isError()){
    Serial.println("Error: ");
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
  Serial.println("Opcode 0: Announcing login");
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
  if(!connectedPeers[0]) {
    return;
  }

  memset(txPayload, 0, sizeof(txPayload));

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

  // Grab the address of the server and form a new address
  XBeeAddress64 addr64 = XBeeAddress64(highAddress[0], lowAddress[0]);
  
  // Send out the data
  ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
  tx.setAddress16(0xfffe);
  xbee.send(tx);
  Serial.println("Opcode 2: Requesting access to resouce");
}

/* 
 * Have this client connect to the desired other client (no KDC middleman)
 * 
 * Args: 
 *   byte - the encrypted name of the myself 
 *   byte - the encrypted session key of the resource attempting to communicate with
 *   byte - the resource attempting to authenticate
 * 
 * Sends the folllowing information over serial:
 *  byte            - The opcode of the operation to perform (2 in this case)
 *  byte            - The KRB_AP_REQ command
 *  byte[2*N_BLOCK] - TGT of the other person
 *  byte[N_BLOCK]   - Authenticator nonce 
 */
void authenticateResource(byte ticketName[], byte ticketKey[], byte resourceId) {
  Serial.println("Opcode 4: Authenticating myself with resource");
  memset(txPayload, 0, sizeof(txPayload));
  byte timestamp[N_BLOCK] = {0};

  // Opcodes
  txPayload[0] = 4;
  txPayload[1] = KRB_AP_REQ;

  // TGT copying (encrypted with other party's master key)
  memcpy(&txPayload[2], ticketName, N_BLOCK);
  memcpy(&txPayload[2 + N_BLOCK], ticketKey, N_BLOCK);

  // Generate "nonce" for timestamp and who I want to talk to 
  timestamp[0] = (byte)random(0, 255);
  nonce[resourceId] = timestamp[0];

  // Encrypt the timestamp
  aes.set_key(session_key[resourceId], 128);
  aes.encrypt(timestamp, &txPayload[2+(2*N_BLOCK)]);

  // Send the data over xbee
  XBeeAddress64 addr64 = XBeeAddress64(highAddress[resourceId], lowAddress[resourceId]);
  ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
  tx.setAddress16(0xfffe);
  xbee.send(tx);
}

/* 
 * Sends a message to another node encrypted by the shared session key between them
 * 
 * Args: 
 *   byte   - the node id I'm sending a message to
 *   byte   - message length in bytes
 *   byte[] - the message being sent (max is 64 characters)
 */
void sendMessageToNode(byte nodeId, byte messageLength, char message[]) {
  byte plainText[N_BLOCK] = {0};

  if(!connectedPeers[nodeId]) {
    Serial.println("Not connected to the required node");
    return;
  }
  memset(txPayload, 0, sizeof(txPayload));

  // Set the opcode and message length
  txPayload[0] = 6;
  txPayload[1] = myIndex;
  txPayload[2] = messageLength;

  // Set the encryption key
  aes.set_key(session_key[nodeId], 128);

  // Encrypt the message
  for(int i = 0; i < messageLength; i+= N_BLOCK) {
    memcpy(&message[i], plainText, N_BLOCK);
    aes.encrypt(plainText, txPayload[3+i]);
  }
  Serial.println("Opcode 6: Sending a message to a node");
  XBeeAddress64 addr64 = XBeeAddress64(highAddress[nodeId], lowAddress[nodeId]);
  ZBTxRequest tx = ZBTxRequest(addr64, txPayload, sizeof(txPayload));
  tx.setAddress16(0xfffe);
  xbee.send(tx);
}

