#ifndef CONNECTOR_PACKETS_H
#define CONNECTOR_PACKETS_H

#define IED_CC_CMD 1003
#define IED_SS_CMD 1004



/*Message for HMI commands (both CC and SS)*/
typedef struct hmi_cmd{
    uint32_t type;
    uint32_t asset_id;
    uint32_t asset_cmd_value;
} hmi_cmd;


#endif
