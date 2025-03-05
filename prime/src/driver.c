/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol 
 *   Sahiti Bommareddy    Reconfiguration 
 *   Maher Khan           Reconfiguration 
 *  	
 * Copyright (c) 2008-2025
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "net_types.h"
#include "objects.h"
#include "packets.h"
#include "data_structs.h"
#include "network.h"
#include "utility.h"
#include "net_wrapper.h"
#include "merkle.h"
#include "spines_lib.h"

/* The behavior of the client can be controlled with parameters that follow */

/* A single client process can be made to act like several clients by
 * having multiple requests outstanding at one time.  After sending
 * the specified number of requests, the client does not send a new
 * one until it receives a response to one of the previous ones. */
#define NUM_CLIENTS_TO_EMULATE 1

/* Adjust this to configure how often a client prints. */
/*#define PRINT_INTERVAL NUM_CLIENTS_TO_EMULATE*/
#define PRINT_INTERVAL 10

/* This sets the maximum number of updates a client can submit */
#define MAX_ACTIONS 100000 

/* This is the number of buckets used for the latency histogram */
#define NUM_BUCKETS 21

/* This is the size (in terms milliseconds of latency) of each bucket */
#define BUCKET_SIZE 5

/* This is the range of how long to randomly wait before submitting new updates */
#define DELAY_RANGE 80000

/* Local Functions */
void Usage(int argc, char **argv);
void Print_Usage (void);
void Init_Memory_Objects(void);
void Config_Recv(channel sk, int dummy, void *dummy_p); 
void Net_Cli_Recv(channel sk, int dummy, void *dummy_p); 
void Init_Client_Network(void); 
void Process_Message( signed_message *mess, int32u num_bytes );
void Run_Client(void);
void Send_Update(int dummy, void *dummyp);
void CLIENT_Cleanup(void);
int32u Validate_Message( signed_message *mess, int32u num_bytes ); 
double Compute_Average_Latency(void);
void clean_exit(int signum);

/* Client Variables */
extern network_variables NET;
extern server_variables  VAR;

int32u My_Client_ID;
int32u My_Server_ID;
int32u My_Server_Alive;
int32u my_global_configuration_number;
int32u my_incarnation;
int32u update_count;
int32u needed_count;
double total_time;
int32u time_stamp;
int ca_driver;
struct ip_mreq mreq;
sp_time t;

/* Local buffers for receiving the packet */
static sys_scatter srv_recv_scat;
/* static sys_scatter ses_recv_scat; */

int32u num_outstanding_updates;
int32u send_to_server;
int32u last_executed = 0;
int32u executed[MAX_ACTIONS];
int sd[MAX_NUM_SERVER_SLOTS];
util_stopwatch update_sw[MAX_ACTIONS];

util_stopwatch sw;
util_stopwatch latency_sw;
signed_message *pending_update;
double Latencies[MAX_ACTIONS];
int32u Histogram[NUM_BUCKETS];
double Min_PO_Time, Max_PO_Time;
/* FILE *fp; */
struct sockaddr_un Conn;

void clean_exit(int signum)
{
  Alarm(PRINT, "Received signal %d\n", signum);
  fflush(stdout);
  CLIENT_Cleanup();
}

int main(int argc, char** argv) 
{
  /* char buf[128]; */

  Usage(argc, argv);
  Alarm_set_types(PRINT);
  Alarm_set_types(STATUS);
  //Alarm_set_types(DEBUG);
  Alarm_enable_timestamp_high_res(NULL);

  NET.program_type = NET_CLIENT_PROGRAM_TYPE;  
  update_count     = 0;
  time_stamp       = 0;
  total_time       = 0;
  //MS2022
  VAR.Num_Servers=18;
  //UTIL_Client_Load_Addresses(); 
  UTIL_Load_Addresses(); 

  E_init(); 
  Init_Memory_Objects();
  Init_Client_Network();
  
  OPENSSL_RSA_Init();
  OPENSSL_RSA_Read_Keys( My_Client_ID, RSA_CLIENT,"./keys" ); 
  
  /* sprintf(buf, "latencies/client_%d.lat", My_Client_ID);
  fp = fopen(buf, "w"); */
    
  signal(SIGINT,  clean_exit);
  signal(SIGTERM, clean_exit);
  signal(SIGKILL, clean_exit);
  signal(SIGQUIT, clean_exit);
  signal(SIGHUP,  clean_exit);
  signal(SIGTSTP, clean_exit);
  signal(SIGTTOU, clean_exit);
  signal(SIGTTIN, clean_exit);
  signal(SIGPIPE, clean_exit);

  Run_Client();

  Alarm(PRINT, "%d entering event system.\n", My_Client_ID);
  fflush(stdout);
  E_handle_events();

  Alarm(PRINT, "%d finishing!!!\n", My_Client_ID);
  fflush(stdout);

  return 0;
}

void Init_Memory_Objects(void)
{
  /* Initialize memory object types  */
  Mem_init_object_abort(PACK_BODY_OBJ, "packet",        sizeof(packet),      100, 1);
  Mem_init_object_abort(SYS_SCATTER,   "sys_scatter",   sizeof(sys_scatter), 100, 1);
}

void Usage(int argc, char **argv)
{
  char ip_str[16];
  int i1, i2, i3, i4;
  int tmp;

  NET.My_Address = -1;
  My_Client_ID   =  0;
  My_Server_ID   =  0;
  VAR.Num_Servers=6;
  my_global_configuration_number = 0;
  My_Server_Alive =1; 
  while(--argc > 0) {
    argv++;
    
    /* [-l A.B.C.D] */
    if((argc > 1) && (!strncmp(*argv, "-l", 2))) {
      sscanf(argv[1], "%s", ip_str);
      sscanf( ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      NET.My_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
      argc--; argv++;
    }
    /* [-i client_id] */
    else if((argc > 1)&&(!strncmp(*argv, "-i", 2))) {
      sscanf(argv[1], "%d", &tmp);
      //My_Client_ID = tmp;
      My_Client_ID = MAX_NUM_SERVER_SLOTS + tmp;
      if(My_Client_ID > NUM_CLIENTS || My_Client_ID <= 0) {
	Alarm(PRINT, "Client ID must be between 1 and %d\n", NUM_CLIENTS);
	exit(0);
      }
      argc--; argv++;
    }
    /* [-s server_id] */
    else if((argc > 1)&&(!strncmp(*argv, "-s", 2))) {
      sscanf(argv[1], "%d", &tmp);
      My_Server_ID = tmp;
      if(My_Server_ID > MAX_NUM_SERVERS || My_Server_ID <= 0) {
	Alarm(PRINT, "Server ID must be between 1 and %d\n", MAX_NUM_SERVERS);
	exit(0);
      }
      argc--; argv++;
    }
  /* [-c count] */
    else if((argc > 1)&&(!strncmp(*argv, "-c", 2))) {
      sscanf(argv[1], "%d", &tmp);
      needed_count = tmp;
      argc--; argv++;
    } 
   else {
      Print_Usage();
    }
  }

  /* Both -l and -i arguments are mandatory */
  if(My_Client_ID == 0 || NET.My_Address == -1)
    Print_Usage();

  /* Port is computed as a function of the client id */
  NET.Client_Port = PRIME_CLIENT_BASE_PORT + My_Client_ID;

  Alarm(PRINT, "Client %d, IP = "IPF", Port = %d\n", 
	My_Client_ID, IP(NET.My_Address), NET.Client_Port);
  if(My_Server_ID == 0)
    Alarm(PRINT, "Rotating updates across all servers.\n");
  else
    Alarm(PRINT, "Sending updates to server %d only.\n", My_Server_ID);

  /* Seed the random number generator */
  srand(My_Client_ID);
}

void Print_Usage()
{
  Alarm(PRINT, "Usage: ./client\n"
	"\t -l IP (A.B.C.D) \n"
	"\t -c count_of_transactions_to_benchmark \n"
        "\t -i client_id, indexed base 1\n"
	"\t[-s server_id, indexed base 1]\n");

  exit(0);
}


/***********************************************************/
/* void Init_Client_Network(void)                          */
/*                                                         */
/* First thing that gets called. Initializes the network   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Init_Client_Network(void) 
{
  struct sockaddr_in server_addr;
  struct sockaddr_un my_addr;
  struct sockaddr_un my_addr2;
  int32u i;
  
  /* Initialize the receiving scatters */
  srv_recv_scat.num_elements    = 1;
  srv_recv_scat.elements[0].len = sizeof(packet);
  srv_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
  if(srv_recv_scat.elements[0].buf == NULL)
    Alarm(EXIT, "Init_Client_Network: Cannot allocate packet object\n");
  
  /* ses_recv_scat.num_elements    = 1;
  ses_recv_scat.elements[0].len = sizeof(packet);
  ses_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
  if(ses_recv_scat.elements[0].buf == NULL)
    Alarm(EXIT, "Init_Client_Network: Cannot allocate packet object\n"); */
 
  /* Initialize IPC socket, single one in this case */
  if (USE_IPC_CLIENT) {
   Alarm(DEBUG,"Using IPC Client \n");
    if (My_Server_ID == 0) {
        Alarm(PRINT, "My_Server_ID is 0, must set ID to use IPC\n");
        exit(0);
    }
    sd[My_Server_ID] = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sd[My_Server_ID] < 0) {
        perror("Client: Couldn't create an IPC socket");
        exit(0);
    }
    memset(&my_addr, 0, sizeof(struct sockaddr_un));
    my_addr.sun_family = AF_UNIX;
    snprintf(my_addr.sun_path, sizeof(my_addr.sun_path) - 1, "%s%d", 
                (char *)CLIENT_IPC_PATH, My_Server_ID);
    if (remove(my_addr.sun_path) == -1 && errno != ENOENT) {
        perror("client: error removing previous path binding");
        exit(EXIT_FAILURE);
    }   
    if (bind(sd[My_Server_ID], (struct sockaddr *)&my_addr, sizeof(struct sockaddr_un)) < 0) {
        perror("client: error binding to path");
        exit(EXIT_FAILURE);
    }   
    chmod(my_addr.sun_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        
    memset(&Conn, 0, sizeof(struct sockaddr_un));
    Conn.sun_family = AF_UNIX;
    sprintf(Conn.sun_path, "%s%d", (char *)REPLICA_IPC_PATH, My_Server_ID);

    /* if((connect(sd[My_Server_ID], (struct sockaddr *)&Conn, sizeof(Conn))) < 0) {
      perror("connect");
      Alarm(PRINT, "Client %d could not connect to server %d\n", 
          My_Client_ID, My_Server_ID);
      fflush(stdout);
      exit(0);
    } */
    Alarm(PRINT, "Client %d ready to send to server %d\n", My_Client_ID, My_Server_ID);

    /* Register the socket descriptor with the event system */
    E_attach_fd(sd[My_Server_ID], READ_FD, Net_Cli_Recv, 0, NULL, MEDIUM_PRIORITY);

    /* Maximize the size of the socket buffers */
    max_rcv_buff(sd[My_Server_ID]);
    max_snd_buff(sd[My_Server_ID]);
  }
  /* Initialize the TCP sockets, one per server in my site */
  else {
    for(i = 1; i <= MAX_NUM_SERVERS; i++) {

      /* If we're sending to a particular server, set up a connection
       * with that server only. */
      if(My_Server_ID != 0 && i != My_Server_ID)
        continue;

      if((sd[i] = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        fflush(stdout);
        exit(0);
      }

      assert(sd[i] != fileno(stderr));

      memset(&server_addr, 0, sizeof(server_addr));
      server_addr.sin_family      = AF_INET;
      server_addr.sin_port        = htons(PRIME_TCP_BASE_PORT + i);
      server_addr.sin_addr.s_addr = htonl(UTIL_Get_Server_Address(i));
        
      if((connect(sd[i], (struct sockaddr *)&server_addr, 
          sizeof(server_addr))) < 0) {
        perror("connect");
        Alarm(PRINT, "Client %d could not connect to server server %d\n", 
          My_Client_ID, i);
        fflush(stdout);
        exit(0);
      }
      Alarm(PRINT, "Client %d connected to server %d\n", My_Client_ID, i);

      /* Register the socket descriptor with the event system */
      E_attach_fd(sd[i], READ_FD, Net_Cli_Recv, 0, NULL, MEDIUM_PRIORITY);

      /* Maximize the size of the socket buffers */
      max_rcv_buff(sd[i]);
      max_snd_buff(sd[i]);
    }
  }
  /*CA Driver IPC path*/
    ca_driver = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (ca_driver < 0) {
        perror("Client: Couldn't create an CA->driver IPC socket");
        exit(0);
    }
    memset(&my_addr2, 0, sizeof(struct sockaddr_un));
    my_addr2.sun_family = AF_UNIX;
    snprintf(my_addr2.sun_path, sizeof(my_addr2.sun_path) - 1, "%s%d",
                (char *)CA_DRIVER_IPC_PATH, My_Server_ID);
    if (remove(my_addr2.sun_path) == -1 && errno != ENOENT) {
        perror("client: error removing previous ca driver path binding");
        exit(EXIT_FAILURE);
    }
    if (bind(ca_driver, (struct sockaddr *)&my_addr2, sizeof(struct sockaddr_un)) < 0) {
        perror("client: error binding to ca diver path");
        exit(EXIT_FAILURE);
    }
    chmod(my_addr2.sun_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    E_attach_fd(ca_driver,READ_FD, Config_Recv, 0, NULL, MEDIUM_PRIORITY);
    Alarm(PRINT, "CA Driver IPC  (path: %s)setup done\n",my_addr2.sun_path);
    fflush(stdout); 
}

/***********************************************************/
/* void Net_Cli_Recv(channel sk, int dummy, void *dummy_p) */
/*                                                         */
/* Called by the event system to receive data from socket  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:      socket                                         */
/* dummy:   not used                                       */
/* dummy_p: not used                                       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Net_Cli_Recv(channel sk, int dummy, void *dummy_p) 
{
  int32  received_bytes;
  int32u expected_total_size = 0, remaining_bytes;
  int    ret;
  struct sockaddr_un from;
  socklen_t from_len;

  if (USE_IPC_CLIENT) {
    from_len = sizeof(struct sockaddr_un);
    ret = recvfrom(sk, srv_recv_scat.elements[0].buf, sizeof(packet), 0,
                (struct sockaddr *)&from, &from_len);
    if(ret <= 0) {
      Alarm(PRINT, "%d read returned %d\n", My_Client_ID, ret);
      fflush(stdout);
      close(sk);
      E_detach_fd(sk, READ_FD);
      CLIENT_Cleanup();
    }
    received_bytes = ret;
  }
  else {
      /* First read the signed message part (header), which can be used
       * to determine the length of the rest of the message. */
      ret = NET_Read(sk, srv_recv_scat.elements[0].buf, sizeof(signed_message));
      if(ret <= 0) {
        Alarm(DEBUG, "%d read returned %d\n", My_Client_ID, ret);
        close(sk);
        E_detach_fd(sk, READ_FD);
        CLIENT_Cleanup();
      }

      expected_total_size = 
        UTIL_Message_Size((signed_message *)srv_recv_scat.elements[0].buf);

      remaining_bytes = expected_total_size - sizeof(signed_message);

      Alarm(DEBUG, "Read %d bytes so far, expecting total size of %d\n",
        ret, expected_total_size);

      ret = NET_Read(sk, &srv_recv_scat.elements[0].buf[sizeof(signed_message)], 
               remaining_bytes);
      if(ret <= 0) {
        Alarm(PRINT, "%d read returned %d\n", My_Client_ID, ret);
        fflush(stdout);
        close(sk);
        E_detach_fd(sk, READ_FD);
        CLIENT_Cleanup();
      }
      received_bytes = expected_total_size;
  }
    
  //Alarm(DEBUG, "Received %d bytes!\n", received_bytes);
  
  /* Validate the client response */
  if(!Validate_Message((signed_message*)srv_recv_scat.elements[0].buf, 
 	       received_bytes)) {
    Alarm(DEBUG,"CLIENT VALIDATION FAILURE\n");
    return;
  } 

  /* Now process the message */
  Process_Message( (signed_message*)(srv_recv_scat.elements[0].buf),  
		   received_bytes);
  
  if(get_ref_cnt(srv_recv_scat.elements[0].buf) > 1) {
    dec_ref_cnt(srv_recv_scat.elements[0].buf);
    if((srv_recv_scat.elements[0].buf = 
	(char *) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
      Alarm(EXIT, "Net_Cli_Recv: Could not allocate packet body obj\n");
    }
  }
}

int32u Validate_Message( signed_message *mess, int32u num_bytes ) 
{
  client_response_message *r;
  signed_message *app;
  /* int ret; */
 
  if(mess->type != CLIENT_RESPONSE) {
    Alarm(PRINT, "Invalid response type: %d\n", mess->type);
    return 0;
  }

  /* Size should be at least signed update message */
  if(num_bytes < (sizeof(signed_message) + sizeof(client_response_message))) {
    Alarm(PRINT, "Response too small: only %d bytes\n", num_bytes);
    return 0;
  }

  r = (client_response_message *)(mess+1);
  app = (signed_message *) (r+1);
  if(r->machine_id != My_Client_ID) {
    if(app->type==CLIENT_SYSTEM_RECONF && mess->global_configuration_number==my_global_configuration_number){
  	if(time_stamp<needed_count && My_Server_Alive==1){
        	Alarm(DEBUG, "Received System RECONF from my Prime. So, will resume benchmarks\n");
		t.sec=10;
		t.usec=0;
		E_queue(Send_Update,0,NULL,t);
   	}
    }else{
    	Alarm(DEBUG, "Received response not intended for me! targ = %d response type=%d\n", r->machine_id,app->type);
    }
    return 0;
  }

  if(executed[r->seq_num] != 0) {
    Alarm(PRINT, "Already processed response for seq %d\n", r->seq_num);
    return 0;
  }

  /* Check the signature */
  /* if (CLIENTS_SIGN_UPDATES) {
    ret = MT_Verify(mess);

    if(ret == 0) {
      Alarm(PRINT, "Signature on client response message did not verify!\n");
      return 0;
    }
  } */
  /* if (CLIENTS_SIGN_UPDATES) {
    ret = OPENSSL_RSA_Verify( 
             ((byte*)mess) + SIGNATURE_SIZE,
             mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
             (byte*)mess, mess->machine_id, RSA_SERVER);   

    if (ret == 0)  {
      Alarm(PRINT,"  Sig Client Failed %d\n", mess->type);
      return 0;
    }
  } */

  return 1;  
}

void Process_Message( signed_message *mess, int32u num_bytes ) 
{
  client_response_message *response_specific;
  double time;

  Alarm(DEBUG, "Received mess type=%d\n",mess->type);

  response_specific = (client_response_message *)(mess+1);
  
  UTIL_Stopwatch_Stop(&update_sw[response_specific->seq_num]);
  time = UTIL_Stopwatch_Elapsed(&update_sw[response_specific->seq_num]);
  Alarm(STATUS, "Processing conf=%lu, seq=%d\ttotal=%f\tPO=%f\n",mess->global_configuration_number ,response_specific->seq_num, time,response_specific->PO_time);


  if (response_specific->PO_time < Min_PO_Time)
    Min_PO_Time = response_specific->PO_time;
  if (response_specific->PO_time > Max_PO_Time)
    Max_PO_Time = response_specific->PO_time;

  if(response_specific->seq_num % PRINT_INTERVAL == 0)
    Alarm(PRINT, "%d\ttotal=%f\tPO=%f\n", response_specific->seq_num, 
                    time, response_specific->PO_time);
  
  num_outstanding_updates--;

  //sleep(1);
  //usleep(100000);
  /* Wait for a random delay */
  /* usleep(rand() % DELAY_RANGE); */
  if(time_stamp<needed_count){
  	Send_Update(0, NULL);
  }
  return;
}

void Run_Client()
{
  memset(executed, 0, sizeof(int32u) * MAX_ACTIONS);
  memset(Histogram, 0, sizeof(int32u) * NUM_BUCKETS);

  Max_PO_Time = 0;
  Min_PO_Time = 9999;

  num_outstanding_updates = 0;
  my_incarnation = E_get_time().sec;

  if(My_Server_ID != 0)
    send_to_server = My_Server_ID;
  else
    send_to_server = 1;
  if(time_stamp<needed_count){
  	Send_Update(0, NULL);
  }
}

void Send_Update(int dummy, void *dummyp)
{
  signed_message *update;
  update_message *update_specific;
  int ret;

  while(num_outstanding_updates < NUM_CLIENTS_TO_EMULATE) {

    /* Build a new update */
    update             = UTIL_New_Signed_Message();
    update->machine_id = My_Client_ID;
    update->len        = sizeof(update_message) + UPDATE_SIZE;
    update->type       = UPDATE;
    update->global_configuration_number =my_global_configuration_number;

    update_specific = (update_message*)(update+1);

    time_stamp++; 
    //update_specific->server_id   = send_to_server;
    update_specific->server_id   = My_Client_ID;
    update->incarnation          = my_incarnation;
    update_specific->seq_num     = time_stamp; 
    update_specific->address     = NET.My_Address;
    update_specific->port        = NET.Client_Port;

    /* Start the clock on this update */
    UTIL_Stopwatch_Start(&update_sw[time_stamp]);

    /* Sign the message */
    //update->mt_num   = 1;
    //update->mt_index = 1;

    if(CLIENTS_SIGN_UPDATES)
      UTIL_RSA_Sign_Message(update);

    Alarm(DEBUG, "%d Sent %d to server %d\n", 
	  My_Client_ID, time_stamp, send_to_server);

    if (USE_IPC_CLIENT) {
        ret = sendto(sd[send_to_server], update, sizeof(signed_update_message), 0,
                    (struct sockaddr *)&Conn, sizeof(struct sockaddr_un));
    }
    else {
        ret = NET_Write(sd[send_to_server], update, sizeof(signed_update_message));
    }

    if(ret <= 0) {
      perror("sendto prime");
      fflush(stdout);
      close(sd[send_to_server]);
      E_detach_fd(sd[send_to_server], READ_FD);
      CLIENT_Cleanup();
    }
    
    dec_ref_cnt(update);

    /* If we're rotating across all servers, send the next one to the 
     * next server modulo the total number of servers. */
    if(My_Server_ID == 0) {

#if 0
      send_to_server++;
      send_to_server = send_to_server % (NUM_SERVERS);
#endif
      send_to_server = rand() % MAX_NUM_SERVERS;
      if(send_to_server == 0)
        send_to_server = MAX_NUM_SERVERS;
    }

    num_outstanding_updates++;
  }
}

void CLIENT_Cleanup()
{
  int32u i, count;
  int32u num_executed;
  int32u index;
  double sum;

  num_executed = 0;
  sum          = 0.0;

  fprintf(stdout, "Cleaning up...\n");
  fflush(stdout);

  printf("Latencies for first 10 packets\n");
  for (i = 0, count = 1; count <= 10 && i < time_stamp; i++)
  {
    if (executed[i]) {
        printf("Pkt %u latency: %f\n", count, Latencies[i]);
        count++;
    }
  }

  printf("Latency histogram\n");
  for(i = 0; i < time_stamp; i++) {
    if(executed[i]) {
      sum += Latencies[i];
      num_executed++;

      /* Add to histogram */
      index = Latencies[i] * 1000 / BUCKET_SIZE;
      if (index >= NUM_BUCKETS)
        index = NUM_BUCKETS - 1;
      Histogram[index]++;
    }
  }

  Alarm(PRINT, "Histogram of update latency:\n");
  for(i = 0; i < NUM_BUCKETS-1; i++)
    printf("\t[%2u - %2u]: %u\n", i*BUCKET_SIZE, (i+1)*BUCKET_SIZE, Histogram[i]);
  printf("\t[%2u+]: %u\n", i*BUCKET_SIZE, Histogram[i]);

  Alarm(PRINT, "Min PO Time = %f\n", Min_PO_Time);
  Alarm(PRINT, "Max PO Time = %f\n", Max_PO_Time);

  Alarm(PRINT, "%d: %d updates\tAverage Latency: %f\n", 
	My_Client_ID, num_executed, (sum / (double)num_executed));
  fflush(stdout);

  /* fprintf(fp, "%f %d\n", (sum / (double)num_executed), num_executed);
  fsync(fileno(fp)); */

  exit(0);
}

double Compute_Average_Latency()
{
  int32u i;
  double sum = 0.0;

  Alarm(DEBUG, "Action count in Compute(): %d\n", time_stamp);

  for(i = 1; i < time_stamp; i++) {
    if(Latencies[i] > 0.004) {
      Alarm(DEBUG, "High latency for update %d: %f\n", i, Latencies[i]);
    }


  return (sum / (double)(time_stamp-1));
  }
}




void Config_Recv(channel sk, int dummy, void *dummy_p){
  int ret,ret2;
  struct sockaddr_in from_addr;
  socklen_t from_len=sizeof(from_addr);
  byte buff[50000];
  signed_message *mess;
  nm_message *c_mess;

  ret=recvfrom(ca_driver, buff, 50000, 0, (struct sockaddr *) &from_addr, &from_len);
  if(ret>0){
    Alarm(DEBUG, "Received spines message of size=%d\n",ret);
   }else{
    Alarm(DEBUG, "Received spines message of size=%d\n",ret);
	return;
	}
    if(ret < sizeof(signed_message)){
      Alarm(PRINT,"Config Message size smaller than signed message\n");
      return;
        }
  mess = (signed_message*)buff;

  if (ret < (sizeof(signed_message)+mess->len)){
     Alarm(PRINT,"Config Agent: Config Message size smaller than expected\n");
     return;
        }
  if (mess->type != CLIENT_OOB_CONFIG_MSG) {
        Alarm(PRINT, "Got invalid mess type from config spines: %d\n", mess->type);
        return;
    }
  ret=OPENSSL_RSA_Verify(
       ((byte*)mess) + SIGNATURE_SIZE,
       mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
       (byte*)mess,
       mess->machine_id,
       RSA_NM
       );
  if(!ret){
	Alarm(PRINT, "Config Manager Signature verification failed\n");
	}
  
   Alarm(DEBUG,"Verified Config Message type=%d\n",mess->type);
  if (mess->type == CLIENT_OOB_CONFIG_MSG){
       c_mess=(nm_message *)(mess+1);
       if(mess->global_configuration_number<=my_global_configuration_number){
	Alarm(PRINT, "Invalid Global Configuration Number\n");
	return;
	} 
       my_global_configuration_number=mess->global_configuration_number;	
       ret2=sendto(sd[My_Server_ID], mess, sizeof(signed_message)+mess->len, 0,
                    (struct sockaddr *)&Conn, sizeof(struct sockaddr_un));
	if(ret2!=sizeof(signed_message)+mess->len){
	  Alarm(PRINT,"Failed to send config message to prime\n");
	  return;
	}
	else{
	Alarm(DEBUG, "Sent to server %d mess type=%d, size=%d\n",My_Server_ID,mess->type,ret2);
	}
  //Reload Keys
  VAR.Num_Servers= c_mess->N;
  if(c_mess->tpm_based_id[My_Server_ID-1]==0){
	My_Server_Alive=0;
   }else{
	My_Server_Alive=1;
   } 
  OPENSSL_RSA_Read_Keys( My_Client_ID, RSA_CLIENT,"/tmp/test_keys/prime" );
  time_stamp=0;
  num_outstanding_updates = 0;
  }
}
  
