#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

#include "utils.h"
#include "cJSON.h"

#define URLFILE "/etc/url_list"

char* get_mmap_addr(unsigned expand_len){
  int fd,i, ret = 0;
  struct stat sb;
  unsigned int len = 0;
  char* addr = NULL, * flat_mac_node_hdr = NULL,* flat_url_list = NULL;
  unsigned short pnode_count = 0;

  fd = open(URLFILE, O_RDWR);
  if(fd < 0){
    syslog(LOG_ERR, _("failed to open url list"));
    return;
  }

  if (fstat(fd, &sb) == -1){ /* To obtain file size */
    my_syslog(LOG_ERR, _("get file info error"));
    close(fd);
    return NULL;
  }
  // memory ref to dns_control.pdf
  addr =(char *) mmap(NULL, sb.st_size, PROT_READ,MAP_PRIVATE, fd, 0);
  close(fd);
  if (addr == NULL){
    syslog(LOG_ERR, _("map file error"));
    return NULL;
  }
  return addr;
}
int calc expand_len(cJSON *listitems ){
  unsigned int len = 0;
  for (i = 0 ; i < cJSON_GetArraySize(listitems) ; i++) {
      cJSON * listitem = cJSON_GetArrayItem(listitems, i);
      len += strlen(listitem->valuestring);
  }
  return len;
}

char * generate_flat_list(cJSON *listitems, len ){

  for (i = 0 ; i < cJSON_GetArraySize(listitems) ; i++) {
    cJSON * listitem = cJSON_GetArrayItem(listitems, i);
    len += strlen(listitem->valuestring);
  }
}

int parse_data(cJSON* root){

  cJSON* p_jmac = NULL;
  cJSON* p_jfunc = NULL;
  cJSON* p_juci_func = NULL;
  char mac[6] == NULL;
  unsigned char optype = 0;
  int i;
  cJSON * p_jmac = cJSON_GetObjectItem(root, "mac");
  cJSON * p_jfunc= cJSON_GetObjectItem(root, "mac");
  cJSON * p_juci_func= cJSON_GetObjectItem(root, "mac");
  cJSON *listitems = cJSON_GetObjectItem(root,"list");

  int func = p_jfunc->valueint;
  int uci_func = p_juci_func->valueint;
  memcpy(mac, p_jmac->valuestring, 6);

// 0 add 1 change 2 delete  3 init
  if(func == 0){
    if(uci_func == 1) optype = 2;
    else return 0;
  }

// 0 add 1 change 2 delete  3 init
  if(func == 1){
    if(uci_func == 1) optype = 1;
    else optype = 0;
  }

}

int send_signal(){
  // get dhcp pid
  ///var/run/dnsmasq/dnsmasq.pid
  char buf[7] ={'\0'};
  FILE *file = fopen("/var/run/dnsmasq/dnsmasq.pid", "r");
  if(fread(buf, 1, 7, file) == 0){
    return -1;
  }
  unsigned int dns_pid = atoi(buf);
  kill(dns_pid, SIGUSR2);
  return 0;
}

int32_t do_urllist_change(char *data, char **callback)
{
  int ret = -1;
  LOG( "urllist data %s, len = %d", data, strlen(data));

  cJSON *root=cJSON_Parse(data);
  parse_data(data);
  cJSON_Delete(data);
  ret = 0;
  return ret;
}
