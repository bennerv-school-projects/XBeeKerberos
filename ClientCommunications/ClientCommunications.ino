#include <AES.h>

AES aes;
byte key[N_BLOCK] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
const char clientName = 'A';
byte plain [N_BLOCK] = {0};
byte cipher [N_BLOCK] = {0};


// Define a TGT and kerberos_commands as well.  Should put in a separate file
enum kerberos_command {
  KRB_AS_REQ = 0,
  KRB_AS_REP = KRB_AS_REQ+1,
  KRB_TGS_REQ = KRB_AS_REP+1,
  KRB_TGS_REP = KRB_TGS_REQ+1,
  KRB_AP_REQ = KRB_TGS_REP+1,
  KRB_AP_REP = KRB_AP_REQ+1
};

typedef struct TGT {
  
}

void setup() {
  
  // Start the serial with a baud rate of 9600
  Serial.begin(9600);
  while(!Serial);

  // Memset the values for aes
  memset(plain, 0, sizeof(plain));
  memset(cipher, 0, sizeof(cipher));

  // Set the key in the AES object (128 bit key)
  aes.set_key(key, 128);

  announceLogin();
  

}

void loop() {

  if(Serial.available()) {
    byte command = Serial.read();

    // Switch on each of the opcodes read, then read the rest of the data
    switch(command) {
      
      // Shouldn't ever receive this, only send it out 
      case 0:
        break;

      // Receiving a TGT and session key back from the KDC
      case 1:
        break;

      // Logging into a resource.  Shouldn't ever receive this, only send it out
      case 2:
        break;

      // Receiving a login token for another resource.
      case 3:
        break;

      // Receiving a authentication from a client
      case 4:
        break;

      // Authenticating oneself to a client
      case 5:
        break;

      // Sending a message/command to a client
      case 6:
        break;

      // Send a message to print out - shouldn't ever receive this only send it out
      case 7: 
        break;

      // Keep alive message, shoudln't ever receive this only send it out
      case 8:
        break;
        
      default:
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
  data[0] = 0;
  data[1] = KRB_AS_REQ;
  data[2] = clientName;

  Serial.write(data, sizeof(data));
}

