#include <Printers.h>
#include <XBee.h>
#include <AES.h>
#include <assert.h>

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
byte master_key[N_BLOCK] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
const byte clientName = 0; // Value 0-4

byte session_key[5][N_BLOCK] = {0};

bool isConnected = false;
TGT tgt[5]; // tgt[clienName] is my own TGT with the KDC
byte nonce[5] = {0};


void setup() {
  
  // Start the serial with a baud rate of 9600
  Serial.begin(9600);
  while(!Serial);
  
  // Set the key in the AES object (128 bit key)
  aes.set_key(master_key, 128);

  // Send the opcode 0 to connect to the KDC
  announceLogin();
  isConnected = false;

}

void loop() {

  // Read from the serial port if something is available to be read
  if(Serial.available()) {
    byte command = Serial.read();

    // Switch on each of the opcodes read, then read the rest of the data
    switch(command) {
      
      // Shouldn't ever receive this, only send it out 
      case 0: {
        assert(0);
      }
        break;

      // Receiving a TGT and session key back from the KDC
      case 1: {
        byte kerb_command = Serial.read();
        assert(kerb_command == KRB_AS_REP);

        // Read two blocks.  The first containing ciphertext with the client (my) name in it
        byte cipherFirstBlock[N_BLOCK] = {0};
        byte cipherSecondBlock[N_BLOCK] = {0};
        Serial.readBytes(cipherFirstBlock, N_BLOCK);
        Serial.readBytes(cipherSecondBlock, N_BLOCK);

        byte plainFirstBlock[N_BLOCK] = {0};
        byte plainSecondBlock[N_BLOCK] = {0};
        aes.set_key(master_key);
        aes.decrypt(cipherFirstBlock, plainFirstBlock);
        aes.decrypt(cipherSecondBlock, plainSecondBlock);

        // Read the client name it's being sent to and make sure it is me
        byte readClientName = plainFirstBlock[0];
        assert(clientName == readClientName);

        // Copy the session key for further communication
        memcpy(&session_key[clientName], plainSecondBlock, sizeof(byte) * N_BLOCK);

        // Copy the TGT for further communication
        memcpy(tgt[clientName].clientName, cipherFirstBlock, sizeof(byte) * N_BLOCK);
        memcpy(tgt[clientName].sessionKey, cipherSecondBlock, sizeof(byte) * N_BLOCK);
        
        isConnected = true;
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
        aes.set_key(session_key[clientName], 128);
        aes.decrypt(cipherFirstBlock, plainFirstBlock); // Name of person to send to 
        aes.decrypt(cipherSecondBlock, plainSecondBlock); // Session key between myself and other 
        aes.decrypt(cipherThirdBlock, plainThirdBlock);  // Name of me (encrypted in TGT
        aes.decrypt(cipherFourthBlock, plainFourthBlock); // Session key between myself and other (encrypted by Bob's master key)

        // Save the session key between the other party
        byte readClientName = plainFirstBlock[0];
        memcpy(&session_key[readClientName], plainSecondBlock, N_BLOCK);

        // Save the TGT for the other party for further communication
        memcpy(&tgt[readClientName].clientName, plainThirdBlock, N_BLOCK);
        memcpy(&tgt[readClientName].sessionKey, plainFourthBlock, N_BLOCK); 
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
        aes.set_key(master_key, 128);
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
  }
}

/* 
 * Announces the login to the Node.js server and establishes a TGT between the KDC and the client
 * Happens on xbee power on - OPCODE 0
 * 
 * Sends the folllowing information over serial:
 *  byte - The opcode of the operation to perform (0 in this case)
 *  byte - The KRB_AS_REQ command
 *  byte - The clientName to identify itself
 */
void announceLogin() {
  byte data[3];
  data[0] = 0; // The opcode number 
  data[1] = KRB_AS_REQ; // the command being sent
  data[2] = clientName; // the name of the client announcing themself

  Serial.write(data, sizeof(data));
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
  byte data[2 + 3*N_BLOCK] = {0};
  byte timestamp[N_BLOCK] = {0};
  byte cipherTimestamp[N_BLOCK] = {0};

  // Make sure we are connected first
  if(!isConnected) {
    return;
  }

  // Opcodes
  data[0] = 2; // the opcode number
  data[1] = KRB_TGS_REQ; // the command being sent

  // TGT
  memcpy(&data[2], tgt[clientName].clientName, N_BLOCK);
  memcpy(&data[2+N_BLOCK], tgt[clientName].sessionKey, N_BLOCK);

  // Generate "nonce" for timestamp and who I want to talk to 
  timestamp[0] = resourceId;
  timestamp[1] = (byte)random(0, 255);

  // Encrypt the timestamp
  aes.set_key(session_key[clientName], 128);
  aes.encrypt(timestamp, cipherTimestamp);

  // Authenticator and who to talk to
  memcpy(&data[2+(2*N_BLOCK)], cipherTimestamp, N_BLOCK);

  // Write out the data to the KDC
  Serial.write(data, sizeof(data));
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
  byte data[2+ 3*N_BLOCK] = {0};
  byte timestamp[N_BLOCK] = {0};
  byte cipherTimestamp[N_BLOCK] = {0};

  // Opcodes
  data[0] = 4;
  data[1] = KRB_AP_REQ;

  // TGT copying (encrypted with other party's master key)
  memcpy(&data[2], tgt[resourceId].clientName, N_BLOCK);
  memcpy(&data[2], tgt[resourceId].sessionKey, N_BLOCK);


  // Generate "nonce" for timestamp and who I want to talk to 
  timestamp[0] = (byte)random(0, 255);
  nonce[resourceId] = timestamp[0];

  // Encrypt the timestamp
  aes.set_key(session_key[clientName], 128);
  aes.encrypt(timestamp, cipherTimestamp);

  // Authenticator and who to talk to
  memcpy(&data[2+(2*N_BLOCK)], cipherTimestamp, N_BLOCK);

  // Write out the data to the corresponding node
  Serial.write(data, sizeof(data));
}

