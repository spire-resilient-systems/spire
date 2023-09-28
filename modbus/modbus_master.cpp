/***************************************************************************
 *   client for Modbus with pvbrowser                                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "rlmodbus.h"
#include "rlthread.h"
#include "rlinifile.h"
#include "rlsocket.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <sys/signal.h>

extern "C" {
  #include "../common/scada_packets.h"
  #include "../common/net_wrapper.h"
  #include "../common/def.h"
  #include "../config/cJSON.h"
  #include "../config/config_helpers.h"
}

/* RTU information container */
typedef struct namelist_d {
    int *namelist_count;
    int *namelist_slave;
    int *namelist_function;
    int *namelist_start_adr;
    int *namelist_datasize;
} namelist;
// global values
static int        use_socket;       // 0 or 1
static int        debug;            // 0 or 1
static int        cycletime;        // milliseconds
static int        n_poll_slave;     // poll always
static int        poll_slave_counter[256];
static int        protocol;
int               *n_c_per_rtu;
int               num_rtu;
rlModbus          **mod_array;
rlSocket          **sock_array;
namelist          *namelist_arr;
int               ipc_sock;
int               seq_num;
rtu_data_msg      *subs;
itrc_data         itrc_main;
struct timeval    Poll_Period;

// TODO remove
//int counter = 0;
//int global_val = 0;

//Will write info to SM
int Write_To_SM(int idx)
{
    int ret, nBytes;
    signed_message *mess;

    // TODO: test variables below
   // ems_fields *ems;
   // char buf[MAX_LEN], data[4];
   // int function, adr, buflen, slave;

   // if(subs[idx].scen_type == EMS)
   // {
   //     ems = (ems_fields *)subs[idx].data;
   //     printf("Status: %d\n Max: %d\n Current: %d\n Target: %d\n", ems->status,
   //                                                                 ems->max_generation,
   //                                                                 ems->curr_generation,
   //                                                                 ems->target_generation);
   // }

   // counter++;
   // if (counter == 10) {
   //     global_val += counter;
   //     counter = 0;
   //
   //     adr = 0;
   //     slave = 0;

   //     // Sending binary value (0/1)
   //     /* function     = rlModbus::ForceSingleCoil;
   //     data[0] = adr/256; data[1] = adr & 0x0ff;
   //     data[2] = 0; data[3] = 0;
   //     if(global_val != 0) data[2] = 0x0ff;
   //     global_val = (global_val + 1) % 2;
   //     buflen =  4; */

   //     // May want to change the target_generation here
   //     function     = rlModbus::PresetSingleRegister;
   //     data[0] = adr/256; data[1] = adr & 0x0ff;
   //     data[2] = global_val/256; data[3] = global_val & 0x0ff;
   //     buflen = 4;

   //     if(debug) printf("modbus_write: slave=%d function=%d data[0]=%d\n", slave, function, data[0]);
   //     ret = mod_array[0]->write(slave, function, (const unsigned char *) data, buflen);
   //     if(ret < 0) perror("Write ERROR to RTU");
   //     ret = mod_array[0]->response( &slave, &function, (unsigned char *) buf);
   //     if(ret < 0) perror("Response ERROR from RTU");
   // }

    if (debug) printf("Writing to SM\n");
    if (debug) printf("______________\n");

    mess = PKT_Construct_RTU_Data_Msg(&subs[idx]);
    //mess = PKT_Construct_RTU_Data_Msg(subs[idx].seq, subs[idx].rtu_id,
    //                    n_c_per_rtu[idx] - 1, subs[idx].sw_status, subs[idx].tx_status);
    nBytes = sizeof(signed_message) + mess->len;
    subs[idx].seq.seq_num++;
    ret = IPC_Send(ipc_sock, (void *)mess, nBytes, itrc_main.ipc_remote);
    free(mess);
    return ret;
}

void Process_SM_Msg()
{
    char buf[MAX_LEN], data[4];
    int i, ret, val, function, adr, buflen;
    int which_mod, slave;
    signed_message *mess;
    rtu_feedback_msg *feed;

    ret = IPC_Recv(ipc_sock, buf, MAX_LEN);
    mess = (signed_message *)buf;
    feed = (rtu_feedback_msg *)(mess + 1);
    slave = (int)feed->rtu;
    adr = (int)feed->offset;
    val = feed->val;
    printf("Slave Process_SM_Msg: %d, Value: %d, Adr: %d\n\n", slave, val, adr);

    if(feed->type == TRANSFORMER || feed->type == BREAKER) {
        function     = rlModbus::ForceSingleCoil;
        data[0] = adr/256; data[1] = adr & 0x0ff;
        data[2] = 0; data[3] = 0;
        if(val != 0) data[2] = 0x0ff;
        buflen = 4;
    }
    else if(feed->type == SWITCH) {
        function     = rlModbus::PresetSingleRegister;
        data[0] = adr/256; data[1] = adr & 0x0ff;
        data[2] = val/256; data[3] = val & 0x0ff;
        buflen = 4;
    }
    else if(feed->type == EMS_TARGET_SET) {
        function     = rlModbus::PresetSingleRegister;
        data[0] = adr/256; data[1] = adr & 0x0ff;
        data[2] = val/256; data[3] = val & 0x0ff;
        buflen = 4;
    }
    else {
        printf("USER_ERROR: unknown %s entered\n", buf);
        printf("Possible values:\n");
        printf("coil(slave,adr)\n");
        printf("register(slave,adr)\n");
        return;
    }

    which_mod = -1;
    for (i = 0; i < num_rtu; i++) {
        if (subs[i].rtu_id == (uint32_t)slave) {
            which_mod = i;
            break;
        }
    }
    if (which_mod == -1) {
        printf("Process Error: Slave %d is not monitored by this RTU Proxy\n", slave);
        return;
    }

    if(debug) printf("modbus_write: slave=%d function=%d data[0]=%d\n", slave, function, data[0]);
    ret = mod_array[which_mod]->write(slave, function, (const unsigned char *) data, buflen);
    if(ret < 0) perror("Write ERROR to RTU");
    ret = mod_array[which_mod]->response( &slave, &function, (unsigned char *) buf);
    if(ret < 0) perror("Response ERROR from RTU");
    if (debug) printf("modbusResponse (TO WRITE): ret=%d slave=%d function=%d data=%02x %02x %02x %02x\n",
                                    ret, slave, function, data[0], data[1], data[2], data[3]);
    //rlsleep(10); // sleep so reading can work in parallel even if we are sending a lot of data
}

// Intialize Data Structures
static void init(int ac, char **av)
{
    int x, i, j, port, tmp_id, poll_freq, num_emu_rtu;
    const char *text, *cptr;
    char ip[80], var[80];
    char *cptr2;

    if(ac != 4) {
        printf("Usage: %s ID spinesAddr:spinesPort Num_RTU_Emulated\n", av[0]);
        exit(EXIT_FAILURE);
    }

    Init_SM_Replicas();

    for(i=0; i<256; i++)
        poll_slave_counter[i] = 0;

    sscanf(av[1], "%d", &tmp_id);
    if (tmp_id < 0 || tmp_id > 200) {
        printf("invalid ID: %d. Must be between 0 and 200\n", tmp_id);
        exit(EXIT_FAILURE);
    }
    My_ID = tmp_id;

    // set up reading from json
    printf("Parsing JSON -- modbus init\n");
    char * buffer = config_into_buffer();
    cJSON * root = cJSON_Parse(buffer);
    free(buffer);

    printf("Finding my location\n");
    // find my location in the json file
    cJSON * my_loc = NULL;
    cJSON * locations = cJSON_GetObjectItem(root, "locations");
    for(i = 0 ; i < cJSON_GetArraySize(locations) ; i++) {
        cJSON * loc = cJSON_GetArrayItem(locations, i);
        if(My_ID == cJSON_GetObjectItem(loc, "ID")->valueint) {
            my_loc = loc;
            break;
        }

    }
    if(my_loc == NULL) {
        fprintf(stderr, "LOCATION: %d is not in config\n", My_ID);
        exit(1);
    }

    printf("Done Finding my location\n");
    // get modbus globals
    cJSON * globals = cJSON_GetObjectItem(root, "GLOBALS");
    globals = cJSON_GetObjectItem(globals, "modbus");
    // find number of rtu's
    num_rtu = 0;
    cJSON * rtus = cJSON_GetObjectItem(my_loc, "rtus");
    printf("Finding number of RTU's\n");
    for(i = 0; i < cJSON_GetArraySize(rtus); i++) {
        cJSON * rtu = cJSON_GetArrayItem(rtus, i);
        char * prot_str = cJSON_GetObjectItem(rtu, "protocol")->valuestring;
        if (strcmp(prot_str, "modbus") == 0)
            num_rtu++;
    }

    printf("Done Finding number of RTU's : %d\n",num_rtu);
    // Setup default values for global variables
    use_socket       = 1;
    debug            = 1;
    cycletime        = 1000;        // milliseconds
    n_poll_slave     = 1;           // poll always
    protocol         = rlModbus::MODBUS_RTU;

    printf("Reading Globals\n");
    // Read global variable assignments from .ini file
    use_socket   = 1;
    debug        = cJSON_GetObjectItem(globals, "DEBUG")->valueint;
    cycletime    = cJSON_GetObjectItem(globals, "CYCLETIME")->valueint;
    n_poll_slave = cJSON_GetObjectItem(globals, "N_POLL_SLAVE")->valueint;
    printf("Done Reading Globals\n");

    namelist_arr = new namelist[num_rtu];
    subs = new rtu_data_msg[num_rtu];

    text = cJSON_GetObjectItem(globals, "PROTOCOL")->valuestring;
    if (strcmp(text,"ASCII") == 0) protocol = rlModbus::MODBUS_ASCII;
    else                           protocol = rlModbus::MODBUS_RTU;

    printf("%s starting with debug=%d cycletime=%d use_socket=%d n_poll_slave=%d\n",
            av[0], debug, cycletime, use_socket, n_poll_slave);

    // init data structures
    mod_array = new rlModbus*[num_rtu];
    sock_array = new rlSocket*[num_rtu];
    n_c_per_rtu = new int[num_rtu];

    i = 0;
    for(x = 0; x < cJSON_GetArraySize(rtus); x++) {
        cJSON * rtu = cJSON_GetArrayItem(rtus, x);
        char * prot_str = cJSON_GetObjectItem(rtu, "protocol")->valuestring;
        // modbus rtu
        if (strcmp(prot_str, "modbus") == 0) {
            // set up datastructures
            n_c_per_rtu[i] = cJSON_GetObjectItem(rtu, "NUM_CYCLES")->valueint;
            subs[i].rtu_id = cJSON_GetObjectItem(rtu, "ID")->valueint;
            subs[i].seq.incarnation = 0;   // filled in by proxy
            subs[i].seq.seq_num = 1;
            subs[i].scen_type = JHU;
            namelist_arr[i].namelist_count      = new int[n_c_per_rtu[i]];
            namelist_arr[i].namelist_slave      = new int[n_c_per_rtu[i]];
            namelist_arr[i].namelist_function   = new int[n_c_per_rtu[i]];
            namelist_arr[i].namelist_start_adr  = new int[n_c_per_rtu[i]];
            namelist_arr[i].namelist_datasize   = new int[n_c_per_rtu[i]];

            // set up scenario
            char * scen_str = cJSON_GetObjectItem(rtu, "scenario")->valuestring;
            if (strcmp(scen_str, "JHU") == 0) {
                printf("JHU scenario!\n");
                subs[i].scen_type = JHU;
            }
            else if (strcmp(scen_str, "PNNL") == 0) {
                printf("PNNL scenario!\n");
                subs[i].scen_type = PNNL;
            }
            else if (strcmp(scen_str, "EMS") == 0) {
                printf("EMS scenario!\n");
                subs[i].scen_type = EMS;
            }
            else {
                printf("Invalid scenario specified: %s\n", scen_str);
                exit(EXIT_FAILURE);
            }

            // set up network
            printf("setting up network for %d\n", subs[i].rtu_id);
            strcpy(ip, cJSON_GetObjectItem(rtu, "IP")->valuestring);
            port = cJSON_GetObjectItem(rtu, "PORT")->valueint;
            mod_array[i] = new rlModbus(1024, protocol);
            sock_array[i] = new rlSocket(ip,port,1);
            mod_array[i]->registerSocket(sock_array[i]);
            int sock_ret=sock_array[i]->connect();
            printf("Connecting socket\n");
            while (sock_ret<0){
            
                printf("MS2022: Error creating socket at ip:%s and port:%d return code=%d\n",ip,port,sock_ret);
                sock_ret=sock_array[i]->connect();
            fflush(stdout);
            }
            printf("MS2022: Set up socket at ip:%s and port:%d\n",ip,port);
                fflush(stdout);
            if(sock_array[i]->isConnected())
                printf("success connecting to %s:%d\n", ip, port);
            else
                printf("WARNING: could not connect to %s:%d\n", ip, port);

            fflush(stdout);
            cJSON * cycles = cJSON_GetObjectItem(rtu, "CYCLES");
            for(j = 0; j < cJSON_GetArraySize(cycles); j++) {
                text = cJSON_GetArrayItem(cycles, j)->valuestring;
                // beware here be dragons
                cptr = strchr(text,',');
                if(cptr == NULL) {
                    printf("no , given on CYCLE %s\n", text);
                    exit(EXIT_FAILURE);
                }
                cptr++;
                sscanf(text,"%d", &namelist_arr[i].namelist_count[j]);
                if(debug) printf("CYCLE%d=%s count=%d name=%s\n", j+1, text,
                                 namelist_arr[i].namelist_count[j], cptr);
                if(strlen(cptr) >= sizeof(var)-1) {
                    printf("%s too long. exit\n", cptr);
                    exit(EXIT_FAILURE);
                }
                strcpy(var,cptr);
                cptr2 = strchr(var,'(');
                if(cptr2 == NULL) {
                    printf("no ( given on CYCLE %s\n", text);
                    exit(EXIT_FAILURE);
                }
                *cptr2 = '\0';
                cptr2++;
                sscanf(cptr2,"%d,%d", &namelist_arr[i].namelist_slave[j],
                                      &namelist_arr[i].namelist_start_adr[j]);
                if     (strcmp(var,"coilStatus"       ) == 0) {
                    namelist_arr[i].namelist_function[j] = rlModbus::ReadCoilStatus;
                    namelist_arr[i].namelist_datasize[j] = 1;  // bit
                }
                else if(strcmp(var,"inputStatus"      ) == 0) {
                    namelist_arr[i].namelist_function[j] = rlModbus::ReadInputStatus;
                    namelist_arr[i].namelist_datasize[j] = 1;  // bit
                }
                else if(strcmp(var,"holdingRegisters" ) == 0) {
                    namelist_arr[i].namelist_function[j] = rlModbus::ReadHoldingRegisters;
                    namelist_arr[i].namelist_datasize[j] = 16; // bit
                }
                else if(strcmp(var,"inputRegisters"   ) == 0) {
                    namelist_arr[i].namelist_function[j] = rlModbus::ReadInputRegisters;
                    namelist_arr[i].namelist_datasize[j] = 16; // bit
                }
                else {
                    printf("%s(slave,start_adr) not implemented !\n", var);
                    printf("Possible names:\n");
                    printf("coilStatus(slave,start_adr)\n");
                    printf("inputStatus(slave,start_adr)\n");
                    printf("holdingRegisters(slave,start_adr)\n");
                    printf("inputRegisters(slave,start_adr)\n");
                    exit(EXIT_FAILURE);
                }

            }

            i++;
        }
    }

    // Delete cJSON stuff
    cJSON_Delete(root);

    // Net Setup
    Type = RTU_TYPE;
    Prime_Client_ID = (NUM_SM + 1) + My_ID;
    My_IP = getIP();

    // Setup IPC for the RTU Proxy main thread
    memset(&itrc_main, 0, sizeof(itrc_data));
    sprintf(itrc_main.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_main.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    sprintf(itrc_main.ipc_local, "%s%s%d", (char *)RTU_IPC_MAIN, "modbus", My_ID);
    sprintf(itrc_main.ipc_remote, "%s%s%d", (char *)RTU_IPC_ITRC, "modbus", My_ID);
    ipc_sock = IPC_DGram_Sock(itrc_main.ipc_local);
    if(ipc_sock<0){
        printf("Modbus: Error creating ipc_sock %s\n",itrc_main.ipc_local);
        
    }

    // Grab the Num_RTU_Emulated and calculate Poll timeout frequency
    memset(&Poll_Period, 0, sizeof(struct timeval));
    sscanf(av[3], "%d", (int *)&num_emu_rtu);
    if (num_emu_rtu <= 0 || num_emu_rtu > 10) {
        printf("Invalid Num_RTU: %d, must be betwteen 1 and 10\n", num_emu_rtu);
        exit(EXIT_FAILURE);
    }
    poll_freq = (cycletime * 1000) / num_emu_rtu;
    Poll_Period.tv_sec  = poll_freq / 1000000;
    Poll_Period.tv_usec = poll_freq % 1000000;
    printf("Poll_sec = %lu, Poll_usec = %lu\n", Poll_Period.tv_sec, Poll_Period.tv_usec);
}

// i = which modbus object to use
static int modbusCycle(int slave, int function, int start_adr, int num_register,
                        unsigned char *data, int i)
{
    int ret;
    int sent_function;

    if(slave < 0 || slave >= 256){
        return -1;
        printf("MS2022: slave is %d\n",slave);
    }

    if(poll_slave_counter[slave] > 0) {
        if (debug) printf("modbusCycle not polling slave %d: poll_slave_counter[%d]=%d\n",
                            slave, slave, poll_slave_counter[slave]);
        poll_slave_counter[slave] -= 1;
        if( poll_slave_counter[slave] != 0){
            return -1;
            printf("MS2022: Poll slave =-1\n");
        }
    }

    if (debug) printf("modbusRequest: slave=%d function=%d start_adr=%d num_register=%d\n",
                                   slave, function, start_adr, num_register);
    ret = mod_array[i]->request(slave, function, start_adr, num_register);
    sent_function = function;

    if (ret >= 0) ret = mod_array[i]->response(&slave, &function, data);
    /* if (ret < 0)
        poll_slave_counter[slave] = n_poll_slave; */
    if (debug) printf("modbusResponse: ret=%d slave=%d function=%d data=%02x %02x %02x %02x\n",
                                    ret, slave, function, data[0], data[1], data[2], data[3]);

    if (function != sent_function){
        printf("MS2022: function=%d, sent_function=%d\n",function,sent_function);
        ret = -1;
    }

    return ret;
}

// Poll RTU for info
static int readModbus(int i, int j)
{
    unsigned char data[512];
    int           i1, ind, ret, itr;
    unsigned int  val = 0, k, tmp;
    jhu_fields *jhf;
    pnnl_fields *pf;
    ems_fields *ef;
    unsigned char *c_arr = NULL;
    int32u *s_arr = NULL;

    ret = modbusCycle(namelist_arr[i].namelist_slave[j],
                        namelist_arr[i].namelist_function[j],
                        namelist_arr[i].namelist_start_adr[j],
                        namelist_arr[i].namelist_count[j],
                        data, i);

    if(ret < 0) {
        if(debug) printf("modbusCycle returned error\n");
        return ret;
    }


    // write the RTU status on the JHU struct
    if (subs[i].scen_type == JHU) {
        ind = 0;
        for (i1 = 0; i1 < namelist_arr[i].namelist_count[j]; ) {
            if (namelist_arr[i].namelist_datasize[j] == 1) {
                val = data[ind];
                ind += 1;
                i1  += 8;
            }
            else if (namelist_arr[i].namelist_datasize[j] == 16) {
                val = data[ind]*256 + data[ind+1];
                ind += 2;
                i1  += 1;
            }
            else {
                printf("ERROR: unknown datasize\n");
                return -1;
            }
        }

        jhf = (jhu_fields *)(subs[i].data);
        if (j == 0)
            jhf->tx_status = (int)val;
        else
            jhf->sw_status[j - 1] = (int)val;
    }

    // write the RTU status on the PNNL struct
    if (subs[i].scen_type == PNNL) {
        pf = (pnnl_fields *)(subs[i].data);
        if (namelist_arr[i].namelist_function[j] == rlModbus::ReadCoilStatus) {
            c_arr = pf->breaker_write;
        }
        else if (namelist_arr[i].namelist_function[j] == rlModbus::ReadInputStatus) {
            c_arr = pf->breaker_read;
        }
        //else if (namelist_arr[i].namelist_function[j] == rlModbus::ReadInputRegisters) {
        else if (namelist_arr[i].namelist_function[j] == rlModbus::ReadHoldingRegisters) {
            s_arr= pf->point;
        }

        ind = 0;
        itr = 0;
        for (i1 = 0; i1 < namelist_arr[i].namelist_count[j]; ) {

            // In this case, each byte of data actually contains
            // up to 8 different binary values that were read from
            // the PLC. We read in a whole byte at a time from data[ind],
            // and then extract each individual bit and store that as
            // its own separate byte
            if (namelist_arr[i].namelist_datasize[j] == 1) {
                val = data[ind];
                ind += 1;
                i1 += 8;

                if (i1 > namelist_arr[i].namelist_count[j])
                    tmp = namelist_arr[i].namelist_count[j] % 8;
                else
                    tmp = 8;

                for (k = 0; k < tmp; k++) {
                    c_arr[itr] = (val >> k) & (0x00000001);
                    if (debug) printf("\tc_arr[%d] = %d\n", itr, c_arr[itr]);
                    itr++;
                }
            }

            // Here, each 16-bit number is stored such that
            // data[0] is upper 8 bits and data[1] is lower. In this
            // scenario, we are concatenating two 16-bits together,
            // which looks like:  M2 M1 M4 M3
            else if (namelist_arr[i].namelist_datasize[j] == 16) {
                val = (data[ind] << 8)    + data[ind+1] +
                      (data[ind+2] << 24) + (data[ind+3] << 16);
                s_arr[itr] = val;
                if (debug) printf("s_arr[%d] = %d\n", itr, s_arr[itr]);
                ind += 4;
                i1  += 2;
                itr++;
            }
            else {
                printf("ERROR: unknown datasize\n");
                return -1;
            }
        }
    }

    if (subs[i].scen_type == EMS) {
        ef = (ems_fields *)(subs[i].data);

        if (namelist_arr[i].namelist_function[j] == rlModbus::ReadCoilStatus) {
            ef->status = data[0];
        }
        else if (namelist_arr[i].namelist_function[j] == rlModbus::ReadInputRegisters) {
            ef->max_generation = (data[0] << 8) + data[1];
            ef->curr_generation = (data[2] << 8) + data[3];
            ef->id = (data[4] << 8) + data[5];
        }
        else if (namelist_arr[i].namelist_function[j] == rlModbus::ReadHoldingRegisters) {
            ef->target_generation = (data[0] << 8) + data[1];

        }

    }

    return 0;
}

/* Main Function */
int main(int argc,char *argv[])
{
    int i, j, num, readerr;
    struct timeval timeout, now, topoll; //, poll_time; // period;
    fd_set mask, tmask;

    // this kills the process if the parent gets a sighup
    prctl(PR_SET_PDEATHSIG, SIGHUP);

    setlinebuf(stdout);
    printf("Modbus Proxy\n");
    init(argc, argv);

    // Grab the timeout values
    /*period.tv_usec = cycletime * 1000;
    period.tv_sec = 0;
    if (period.tv_usec >= 1000000) {
        period.tv_sec = period.tv_usec / 1000000;
        period.tv_usec = period.tv_usec % 1000000;
    }*/

    // Setup the FD_SET for use in select
    FD_ZERO(&mask);
    FD_SET(ipc_sock, &mask);

    // Initial timeout setup
    gettimeofday(&topoll, NULL);

    printf("Running Modbus Daemon\n");
    // run the daemon forever
    while (1) {

        gettimeofday(&now, NULL);
        if (compTime(now, topoll) >= 0) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        }
        else {
            timeout = diffTime(topoll, now);
        }

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, &timeout);

        if (num > 0) {
            if(FD_ISSET(ipc_sock, &tmask)) {
                Process_SM_Msg();
            }
        }
        else {
            gettimeofday(&topoll, NULL);
            topoll = addTime(topoll, Poll_Period);

            //Poll all cycles for each RTU
            for(i = 0; i < num_rtu; i++) {
                //gettimeofday(&poll_time, NULL);
                readerr = 0;
                for(j = 0; j < n_c_per_rtu[i]; j++) {
                    if (readModbus(i,j) < 0)
                        readerr = 1;
                }
                //gettimeofday(&now, NULL);
                //printf("poll took %lu microseconds\n", diffTime(now, poll_time).tv_usec);

                //Send info over to scada master
                if (!readerr) Write_To_SM(i);
            }
        }
    }

    pthread_exit(NULL);
}
