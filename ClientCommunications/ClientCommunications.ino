/* CHANGE LOG
 * Date       Name       Changes
 * -----------------------------------------------------------------------------
 * 04/01/17   Ben        File creation
 * 04/12/17   Ben        Kerberos commands and processing
 * -----------------------------------------------------------------------------
 * Kerberos client on arduino
 * ----------------------------------------------------------------------------- 
 */

#include <AES.h>
#include <assert.h>

AES aes;
byte key[N_BLOCK] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
const char clientName = 'A';

byte session_key[N_BLOCK] = {0};

bool isConnected = false;

// Define a TGT and kerberos_commands as well.  Should put in a separate file
enum kerberos_command {
  KRB_AS_REQ = 0,
  KRB_AS_REP = KRB_AS_REQ+1,
  KRB_TGS_REQ = KRB_AS_REP+1,
  KRB_TGS_REP = KRB_TGS_REQ+1,
  KRB_AP_REQ = KRB_TGS_REP+1,
  KRB_AP_REP = KRB_AP_REQ+1
};

typedef struct {
  byte clientName[N_BLOCK];
  byte sessionKey[N_BLOCK];
} TGT;

void setup() {
  
  // Start the serial with a baud rate of 9600
  Serial.begin(9600);
  while(!Serial);
  
  // Set the key in the AES object (128 bit key)
  aes.set_key(key, 128);

  // Send the opcode 0 to connect to the KDC
  announceLogin();
  isConnected = false;

}

void loop() {

  TGT tgt;
  
  if(Serial.available()) {
    byte command = Serial.read();

    // Switch on each of the opcodes read, then read the rest of the data
    switch(command) {
      
      // Shouldn't ever receive this, only send it out 
      case 0:
        break;

      // Receiving a TGT and session key back from the KDC
      case 1: {
        byte kerb_command = Serial.read();
        assert(kerb_command == KRB_AS_REP);

        // Read two blocks.  The first containing ciphertext with the client (my) name in it
        byte firstBlock[N_BLOCK] = {0};
        byte secondBlock[N_BLOCK] = {0};
        Serial.readBytes(firstBlock, N_BLOCK);
        Serial.readBytes(secondBlock, N_BLOCK);

        byte plainFirstBlock[N_BLOCK] = {0};
        byte plainSecondBlock[N_BLOCK] = {0};
        aes.decrypt(firstBlock, plainFirstBlock);
        aes.decrypt(secondBlock, plainSecondBlock);

        // Read the client name it's being sent to and make sure it is me
        char readClientName = plainFirstBlock[0];
        assert(clientName == readClientName);

        // Copy the session key for further communication
        memcpy(session_key, plainSecondBlock, sizeof(byte) * N_BLOCK);

        // Copy the TGT for further communication
        memcpy(tgt.clientName, firstBlock, sizeof(byte) * N_BLOCK);
        memcpy(tgt.sessionKey, secondBlock, sizeof(byte) * N_BLOCK);
        
        isConnected = true;
      }
        break;

      // Logging into a resource.  Shouldn't ever receive this, only send it out
      case 2: {
        
      }
        break;

      // Receiving a login token for another resource.
      case 3: {
        
      }
        break;

      // Receiving a authentication from a client
      case 4: {
        
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
        
      }
        break;

      // Keep alive message, shoudln't ever receive this only send it out
      case 8: {
        
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

