#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>

#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "spines_lib.h"

#include "../common/openssl_rsa.h"
#include "../common/tc_wrapper.h"
#include "../prime/OpenTC-1.1/TC-lib-1.0/TC.h"


int main(int argc, char **argv)
{
	char conf_dir[100];
	char filename[200];
	int curr_N,i;
	TC_IND *tc_partial_key;
	TC_PK *tc_public_key;

	if(argc<3){
	Alarm(EXIT,"Usage:%s conf_dir N\n",argv[0]);
	}

	curr_N=0;
	memset(conf_dir,0,sizeof(conf_dir));

	sprintf(conf_dir,"%s",argv[1]);
	sscanf(argv[2],"%d",&curr_N);
	
	memset(filename,0,sizeof(filename));
	sprintf(filename,"./%s/keys/pubkey_1.key",conf_dir);
	printf("Public key file %s\n",filename);
	tc_public_key=(TC_PK *)TC_read_public_key(filename);
	for(i=0;i<curr_N;i++){
		memset(filename,0,sizeof(filename));
		sprintf(filename,"./%s/keys/share%d_1.key",conf_dir,i);
		tc_partial_key = (TC_IND *)TC_read_share(filename);		
		printf("Pubkey\n");
		TC_PK_Print(tc_public_key);
		printf("Read= %s\n",filename);
		TC_IND_Print(tc_partial_key);
	}	
return (0);	
}
