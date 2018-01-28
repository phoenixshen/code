#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "cJSON.h"

int parse_data(char * data){

}

int send_signal(){
// get dhcp pid
///var/run/dnsmasq/dnsmasq.pid

}

int32_t do_uci_changes(char *data, char **callback)
{
    int ret = -1;
    ChangesMessage *msg = (ChangesMessage *)malloc(sizeof(ChangesMessage));

    LOG( "strlen(data) = %d", strlen(data));
    LOG( "sizeof(data) = %d", sizeof(data));

    char sn[SN_LENGTH];
    memset(sn, 0, SN_LENGTH);
    if(getSfHardwareConfig("sn",sn) != 0){
    ¦   LOG( "[server] get sn from hardware config fail!\n");
    ¦   return -1;
    }
    cJSON *root=cJSON_Parse(data);
    cJSON_AddStringToObject(root, "sn", sn);
    msg->data = cJSON_Print(root);
    msg->try_count = 0;
    cJSON_Delete(root);
    sendMessage(g_changes_msg, (void *)msg);
    ret = 0;
    return ret;
}
