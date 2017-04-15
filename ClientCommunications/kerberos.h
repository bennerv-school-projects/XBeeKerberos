#ifndef __KERB__
#define __KERB__

#include <AES.h>
	
// Define a TGT and kerberos_commands as well.  Should put in a separate file
enum kerberos_command {
  KRB_AS_REQ = 0,
  KRB_AS_REP = KRB_AS_REQ+1,
  KRB_TGS_REQ = KRB_AS_REP+1,
  KRB_TGS_REP = KRB_TGS_REQ+1,
  KRB_AP_REQ = KRB_TGS_REP+1,
  KRB_AP_REP = KRB_AP_REQ+1
};

// TGT structure
typedef struct {
  byte clientName[N_BLOCK];
  byte sessionKey[N_BLOCK];
} TGT;

// Address and payload information
uint64_t addresses[10] = {0x0013A200, 0x4065C409, 0x0013A200, 0x4065C4B6, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
uint8_t payload[3+(3*N_BLOCK)] = {0};



#endif
