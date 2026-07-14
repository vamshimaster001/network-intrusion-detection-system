#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <linux/if_ether.h> 
#include <errno.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdbool.h>
#include <signal.h>
#include <regex.h>
#include <stdatomic.h>

#define MAX_TRACK 1024
#define BODY_BUFFER_SIZE 65535
#define MAX_RULES 100
#define MAX_TYPES 32
#define MAX_PATTERN_SIZE 256

struct source_ip
{
  char src_ip[16];
  int hits;
};

struct source_ip source_ips[MAX_TRACK];
int source_ips_count = 0;

struct rule
{
  char TYPE[MAX_TYPES];
  char PATTERN[MAX_PATTERN_SIZE];
  int sid;
  int hit_count;
  char severity[16];
  regex_t reg;
  int enabled;
  time_t last_alert_time;
  int suppressed_count;
  int threshold;
  int window;
  int window_count;
};

struct rule rules[MAX_RULES];
int rules_count = 0;


struct port_scan_entry
{
    char src_ip[INET_ADDRSTRLEN];
    uint16_t ports[64];
    int port_count;
    time_t window_start;
    time_t last_alert_time;
};

struct port_scan_entry scans[MAX_TRACK];
int scan_count = 0;

pthread_cond_t cond;
pthread_cond_t not_full;
pthread_cond_t not_empty;
pthread_mutex_t lock;
pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t port_lock = PTHREAD_MUTEX_INITIALIZER;
 
void *parse_packet(char *args, int len);

FILE *fp = NULL;
FILE *fp1 = NULL;
FILE *fp2 = NULL;
int server_fd;
char payload_buf[256];
#define DEBUG 0

atomic_int packets_captured = 0;
atomic_int HTTP_requests = 0;
atomic_int Alerts_Generated = 0;


void logging(char *level, char *msg,...)
{
  pthread_mutex_lock(&log_lock);
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char buffer[24];
  strftime(buffer, sizeof(buffer),"%Y-%m-%d %H:%M:%S", t);

  fprintf(stderr,"[%s] [%s]: ", buffer, level);
  fprintf(fp,"[%s] [%s]: ", buffer, level);
  va_list args,args1;
   va_start(args, msg);
   va_copy(args1,args);
   vfprintf(stderr,msg,args);
   vfprintf(fp,msg,args1);
   va_end(args);
   va_end(args1);
   fprintf(stderr, "\n");
   fprintf(fp, "\n");
   fflush(fp);
   pthread_mutex_unlock(&log_lock);

   return;
   
}

void port_scan_detection(char *src_ip,uint16_t dport)
{
  int ip_found = 0;
  int port_found = 0;
  
  for(int i = 0 ; i < scan_count; i++)
  {
    if(strcmp(scans[i].src_ip,src_ip)==0)
    {
      ip_found = 1;
      int window = time(NULL)-scans[i].window_start;
      if(window < 30)
      {	  
	for(int j = 0; j < scans[i].port_count; j++)
	  { 
	    if(dport == scans[i].ports[j])
	      {
		port_found = 1;
	      }
	  }
	if(!port_found && scans[i].port_count < 64 )
	  {
	    scans[i].ports[scans[i].port_count] = dport;
	    scans[i].port_count++;
	  }
	if(scans[i].port_count >=10)
	  {
	    pthread_mutex_lock(&lock);	
	    fprintf(fp2,"{\"type\":\"PORT_SCAN\",\"src_ip\":\"%s\",\"UNIQUE_PORTS\":%d,\"WINDOW\":%d}\n",src_ip,scans[i].port_count,window);
	    fflush(fp2);
	    pthread_mutex_unlock(&lock);
	    logging("[ALERT]","TYPE=PORT_SCAN SRC=%s UNIQUE_PORTS=%d WINDOW=%d",src_ip,scans[i].port_count,window);
	  }
      }
      else
	{
	  scans[i].window_start = time(NULL);
	  scans[i].port_count = 0;
	  memset(scans[i].ports,0,sizeof(scans[i].ports));
	}
  }
  }
  if(!ip_found && scan_count < MAX_TRACK)
  {
    scans[scan_count].src_ip[0]='\0';
    strcpy(scans[scan_count].src_ip,src_ip);
    scans[scan_count].ports[0] = dport;
    scans[scan_count].port_count = 1;
    scans[scan_count].window_start = time(NULL);
    scan_count++;
  }
  return;
}
  
void parse_ethernet(struct ethhdr *eh)
{
  logging("INFO", "************ETHERNET FRAME INFO*****************");            
  logging("INFO", "Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X",eh->h_dest[0],eh->h_dest[1],eh->h_dest[2],eh->h_dest[3],eh->h\
_dest[4],eh->h_dest[5]);                                                                                                               
  logging("INFO", "SOURCE MAC : %02X:%02X:%02X:%02X:%02X:%02X",eh->h_source[0],eh->h_source[1],eh->h_source[2],eh->h_source[3],eh\
->h_source[4],eh->h_source[5]);                                                                                                        
  unsigned short proto = ntohs(eh->h_proto);

  if(proto == ETH_P_IP)                                                                                                           
       logging("INFO","Protocol : IPv4");                                                                                            
  else if(proto == ETH_P_ARP)                                                                                                     
       logging("INFO","Protocol : ARP");                                                                                             
  else if(proto == ETH_P_IPV6)                                                                                                    
       logging("INFO","Protocol : IPv6");                                                                                            
  else                                                                                                                            
       logging("INFO","Protocol : %d",proto);
}

void parse_ipv4(struct iphdr *ih)
{
       logging("INFO", "************IPV4 PACKET INFO*****************");
       uint32_t svalue = ntohl(ih->saddr);                                                        
       logging("INFO", "Source IP : %u.%u.%u.%u",(svalue >> 24) & 0XFF , (svalue >> 16) & 0XFF, (\
svalue >> 8) & 0XFF , svalue & 0XFF);                                                             
       uint32_t dvalue = ntohl(ih->daddr);                                                        
       logging("INFO", "Destination IP : %u.%u.%u.%u",(dvalue >> 24) & 0XFF , (dvalue >> 16) & 0X\
FF, (dvalue >> 8) & 0XFF , dvalue & 0XFF);                                                        
                                                                                                  
       if(ih->protocol == IPPROTO_TCP)                                                            
         logging("INFO", "Protocol : TCP");                                                       
       else if(ih->protocol == IPPROTO_UDP)                                                       
         logging("INFO", "Protocol : UDP");                                                         
       logging("INFO", "TTL : %u", ih->ttl);                                                      
       logging("INFO", "IP Length : %u", ntohs(ih->tot_len));                                     
      
  return;
}

void handle_tcp_packet(struct tcphdr *tp, uint16_t sport, uint16_t dport)
{
  
   logging("INFO", "************TCP PACKET INFO*****************");                                                                                                               
   logging("INFO","SOURCE PORT is %u", sport);                                                                                    
   logging("INFO","DESTINATION PORT is %u", dport);                                                                               
   logging("INFO","SEQUENCE NUMBER IS is %u", ntohl(tp->seq));                                                                    
   logging("INFO","ACKNOWLEDGEMENT NUMBER is is %u", ntohl(tp->ack_seq));                                                         
   logging("INFO","TCP header length is %u bytes", tp->doff * 4);                                                                 
   logging("INFO","SYN flag is is %u", tp->syn);                                                                                  
   logging("INFO","ACK flag is is %u", tp->ack);                                                                                  
   logging("INFO","FIN flag is is %u", tp->fin);                                                                                  
   logging("INFO","RST flag is is %u", tp->rst);                                                                                  
    return;
}

struct packet_item
{

  unsigned char packet[65535];
  size_t len;
};

struct packet_queue
{
  struct packet_item *items;
  int head;
  int tail;
  int count;
  int capacity;
  pthread_t t[5];
};

struct workerargs
{
  int argc1;
  char **argv1;  
};

struct packet_queue *queue1;
struct workerargs *arg;

void *capture_thread()
{
    char buffer[65535];
    while(1)
    {
       
       memset(buffer,0,sizeof(buffer));
       ssize_t bytes_read = recv(server_fd, buffer, sizeof(buffer), 0);
       if(bytes_read < 0)
         {
           logging("INFO", strerror(errno));
           continue;
         }
       atomic_fetch_add(&packets_captured,1);
                   	   
       pthread_mutex_lock(&lock);
       while(queue1->capacity == queue1->count)
	 {
	   pthread_cond_wait(&not_empty,&lock);
	 } 
       int index = queue1->head;
       memcpy(queue1->items[index].packet, buffer, bytes_read);
       queue1->items[index].len = bytes_read;
       queue1->head = (queue1->head+1)%queue1->capacity;
       queue1->count++;
       pthread_cond_signal(&not_full);
       pthread_mutex_unlock(&lock);
    }
    return NULL;
}

void *worker_thread()
{
    while(1)
    {
       pthread_mutex_lock(&lock);
       
       while(queue1->count == 0)
       {
	 pthread_cond_wait(&not_full, &lock);
       }
       int index = (queue1->tail) % queue1->capacity;
       queue1->tail = (queue1->tail+1) % queue1->capacity;
       char buffer[65535];
       int len;
       memset(buffer,0,sizeof(buffer));
       memcpy(buffer,queue1->items[index].packet, queue1->items[index].len);
       len = queue1->items[index].len;
       queue1->count--;
       pthread_cond_signal(&not_empty);
       pthread_mutex_unlock(&lock);
       parse_packet(buffer,len);    
    }
    return NULL;
}

int load_rules(const char *filename)
{
  fp1 = fopen(filename,"r");
  if(!fp1)
    return 0;
  
  int i = 0;
  int buf_size = MAX_PATTERN_SIZE + MAX_TYPES+1;
  char buf[buf_size];
  char *temp;
  
  while(i < MAX_RULES && fgets(buf,buf_size,fp1) != NULL)
  {
    buf[strcspn(buf,"\n")] = '\0';
    rules[i].TYPE[0] = '\0';
    rules[i].PATTERN[0] = '\0';
    rules[i].sid = -1;
    strcpy(rules[i].severity,"LOW");
    rules[i].hit_count = 0;
    rules[i].last_alert_time= 0;
    rules[i].suppressed_count = 0;
    rules[i].threshold = 0;
    rules[i].window = 0;

    temp = strstr(buf,":");
    if(temp == NULL)
      continue;
    int sid_len = temp-buf;
    char sid_temp[sid_len+1];
    sid_temp[0]='\0';
    memcpy(sid_temp,buf,sid_len);
    sid_temp[sid_len] = '\0';
    rules[i].sid = atoi(sid_temp);


    char *temp1 = temp+1;
    temp = strstr(temp1,":");
    if(temp == NULL)
      continue;
    int en_len = temp-temp1;
    char enabled[en_len+1];
    enabled[0]='\0';
    memcpy(enabled,temp1,en_len);
    enabled[en_len] = '\0';
    rules[i].enabled = strcmp(enabled, "ENABLED") == 0 ? 1 : 0;
   

    temp1 = temp+1;
    temp = strstr(temp1,":");
    if(temp == NULL)
      continue;
    int sev_len = temp-temp1;
    memcpy(rules[i].severity,temp1,sev_len);
    rules[i].severity[sev_len] = '\0';


    temp1 = temp+1;
    temp = strstr(temp1,":");
    if(temp == NULL)
      continue;
    int type_len = temp-temp1;
    memcpy(rules[i].TYPE,temp1,type_len);
    rules[i].TYPE[type_len] = '\0';

    temp = temp+1;    
    regex_t reg1;
    regcomp(&reg1,"threshold=(.*),window=(.*):",REG_EXTENDED | REG_ICASE);
    regmatch_t pmatch[3];
    if(!regexec(&reg1,temp,3,pmatch,0))
    {
      
      char buf1[16];
      int len = pmatch[1].rm_eo-pmatch[1].rm_so;
      memcpy(buf1,temp+pmatch[1].rm_so,len);
      buf1[len]= '\0';
      rules[i].threshold = atoi(buf1);

      char buf2[16];
      len = pmatch[2].rm_eo-pmatch[2].rm_so;
      memcpy(buf2,temp+pmatch[2].rm_so,len);
      buf2[len]= '\0';
      rules[i].window = atoi(buf2);
      temp = strstr(temp,":");
    }

    regfree(&reg1);
    
    int pattern_len = strlen(temp)-1;
    strcpy(rules[i].PATTERN,temp+1);
    rules[i].PATTERN[pattern_len] = '\0';

    regcomp(&rules[i].reg,rules[i].PATTERN, REG_EXTENDED | REG_ICASE);
    logging("[RULES]","SID=%d SEV=%s TYPE=%s | PATTERN =%s | HITS=%d | threshold = %d | window = %d ",rules[i].sid, rules[i].severity,rules[i].TYPE,rules[i].PATTERN,rules[i].hit_count, rules[i].threshold, rules[i].window );
    
    rules_count++;
    i++;
  }
  
  fclose(fp1);
  return 1;
}

bool findheader(unsigned char *temp, char *line, const char * header)
{
  memset(line,0,2048);
  char *start, *end;
  start = strstr((char *)temp,header);
  if(!start)
    return false;
  end = strstr(start,"\r\n");
  if(!end)
    return false;
  int len = end-start;
  memcpy(line,start,len);
  line[len] = '\0';
  return true;
}

void update_source_ip(char *src_ip)
{
      if(source_ips_count >= MAX_TRACK)
	return;

      int ip_found = 0;
      
      for(int i = 0; i < source_ips_count; i++)
      {
        if(strcmp(source_ips[i].src_ip, src_ip) == 0)
        {
          ip_found = 1;
          source_ips[i].hits++;
        }
      }

      if(!ip_found)
      {

        source_ips[source_ips_count].hits++;
        strcpy(source_ips[source_ips_count].src_ip,src_ip);
        source_ips_count++;
      }
}

void detect_patterns(unsigned char *ptr, char *headerbuffer, char *bodybuffer, char *src_ip, char *dst_ip, uint16_t s_port, uint16_t d_port)
{
    
  for(int i = 0; i < rules_count; i++)
  {
    pthread_mutex_lock(&lock);
    if(!rules[i].enabled)
    {
      pthread_mutex_unlock(&lock);
      continue;
    }
      
     pthread_mutex_unlock(&lock);
    

    
    if(!regexec(&rules[i].reg,headerbuffer,0,NULL,0))
    {
      pthread_mutex_lock(&lock);
      if(time(NULL)-rules[i].last_alert_time < rules[i].window)
      {
	rules[i].window_count++;
	rules[i].suppressed_count++;
      }
      else
      {
	rules[i].last_alert_time = time(NULL);
	rules[i].window_count = 1;
      }

      if(rules[i].window_count >= rules[i].threshold)
      {
	rules[i].window_count = 0;
      }
      else
      {
	pthread_mutex_unlock(&lock);
        continue;
      }
      pthread_mutex_unlock(&lock);

      rules[i].hit_count++;
      
      pthread_mutex_lock(&lock);
      update_source_ip(src_ip);
      pthread_mutex_unlock(&lock);
      
      char firstline[2048];
      memset(firstline,0,2048);
      unsigned char *temp =ptr;
      char location[4096];
      
      char *end;
      if(!temp)
	return;
      end = strstr((char *)temp ,"\r\n");
      if(!end)
	return;
      int len = end-(char *)temp;
      memcpy(firstline,temp,len);
      firstline[len] = '\0';
      temp = (unsigned char *)end+2;

      char method[20];
      char version[50];
      char url[1000];
      char Host[256];
      char UserAgent[256];
      char ContentType[128];
      char Contentlength[20];
      char Cookie[512];
      location[0]= '\0';

      int ret = sscanf(firstline,"%19s %999s %49s", method , url, version);
      if(ret < 3)
	{
	  logging("INFO","MALFORMED PACKET");
	  return;
	}
      
      if(!regexec(&rules[i].reg,url,0,NULL,0))
	{
	  snprintf(location, sizeof(location),"url: %s",url); 
	}
      
      if(findheader(temp,firstline,"Host:"))
	{
	  sscanf(firstline,"Host: %s",Host);
	  
	  if(!regexec(&rules[i].reg, Host,0,NULL, 0))
	    {
	      snprintf(location, sizeof(location),"Host: %s",Host);
	    }
	}
      if(findheader(temp,firstline,"User-Agent:"))
	{
	  sscanf(firstline,"User-Agent: %s", UserAgent);
	  
	  if(!regexec(&rules[i].reg, UserAgent ,0,NULL, 0))
            {
              snprintf(location, sizeof(location),"User-Agent: %s",UserAgent);
            }
	}
      if(findheader(temp,firstline,"Content-Type:"))
	{
	  sscanf(firstline,"Content-Type: %s", ContentType);
	  
	  if(!regexec(&rules[i].reg,ContentType ,0,NULL, 0))
            {
              snprintf(location, sizeof(location),"Content-Type: %s",ContentType);
            }
	}
      if(findheader(temp,firstline,"Content-Length:"))
	{
	  sscanf(firstline,"Content-Length: %s", Contentlength);

	  if(!regexec(&rules[i].reg,Contentlength ,0,NULL, 0))
            {
              snprintf(location, sizeof(location),"Content-Length: %s",Contentlength);
            }
	}
      if(findheader(temp,firstline,"Cookie:"))
	{
	  sscanf(firstline,"Cookie: %s", Cookie);

	  if(!regexec(&rules[i].reg,Cookie ,0,NULL, 0))
            {
              snprintf(location, sizeof(location),"Cookie: %s",Cookie);
            }
	}
      pthread_mutex_lock(&lock);
      rules[i].last_alert_time = time(NULL);
      fprintf(fp2,"{\"sid\":%d,\"severity\":\"%s\",\"type\":\"%s\",\"src_ip\":\"%s\",\"src_port\":%u,\"dst_ip\":\"%s\",\"dst_port\":%u,\"location\":\"%s\",\"pattern\":\"%s\",\"hits\":%d}\n",rules[i].sid, rules[i].severity,rules[i].TYPE,src_ip,s_port,dst_ip,d_port,location,rules[i].PATTERN,rules[i].hit_count);
      fflush(fp2);
      pthread_mutex_unlock(&lock);
      logging("[ALERT]","SID=%d SEV=%s TYPE=%s %s:%u -> %s:%u | PATTERN =%s | HITS=%d | LOCATION=%s",rules[i].sid, rules[i].severity,rules[i].TYPE,src_ip,s_port,dst_ip,d_port,rules[i].PATTERN,rules[i].hit_count,location);      
      
      
      atomic_fetch_add(&Alerts_Generated,1);
      
    }
    
    if(!regexec(&rules[i].reg,bodybuffer,0,NULL, 0))
    {
      pthread_mutex_lock(&lock);
      if(time(NULL)-rules[i].last_alert_time < rules[i].window)
      {
        rules[i].window_count++;
        rules[i].suppressed_count++;
      }
      else
      {
        rules[i].last_alert_time = time(NULL);
        rules[i].window_count = 1;
      }

      if(rules[i].window_count >= rules[i].threshold)
      {
        rules[i].window_count = 0;
      }
      else
      {
	pthread_mutex_unlock(&lock);
        continue;
      }
      pthread_mutex_unlock(&lock);

      pthread_mutex_lock(&lock);
      update_source_ip(src_ip);
      pthread_mutex_unlock(&lock);
               
      rules[i].hit_count++;
      pthread_mutex_lock(&lock);
      rules[i].last_alert_time = time(NULL);
      fprintf(fp2,"{\"sid\":%d,\"severity\":\"%s\",\"type\":\"%s\",\"src_ip\":\"%s\",\"src_port\":%u,\"dst_ip\":\"%s\",\"dst_port\":%u,\"location\":\"%s\",\"pattern\":\"%s\",\"hits\":%d}\n",rules[i].sid, rules[i].severity,rules[i].TYPE,src_ip,s_port,dst_ip,d_port,"BODY",rules[i].PATTERN,rules[i].hit_count);
      fflush(fp2);
      pthread_mutex_unlock(&lock);
      logging("[ALERT]","SID=%d SEV=%s TYPE=%s %s:%u -> %s:%u | PATTERN =%s | HITS=%d | LOCATION=%s",rules[i].sid, rules[i].severity, rules[i].TYPE,src_ip,s_port,dst_ip,d_port,rules[i].PATTERN,rules[i].hit_count,"BODY");

      atomic_fetch_add(&Alerts_Generated,1);
    }
  }
  
}

bool find_http_body(unsigned char *ptr,size_t body_len, char *body,size_t bodybuffer_size)
{
  memset(body,0,bodybuffer_size);
  char *temp = strstr((char *)ptr,"\r\n\r\n");
  if(!temp)
    return false;
  temp= temp+4;
  body_len = body_len >= bodybuffer_size ? bodybuffer_size-1 : body_len;
  memcpy(body,temp,body_len);
  body[body_len] = '\0';
  return true;
}

void parse_http_request(unsigned char *ptr, size_t payload_len, char *src_ip, uint16_t sport, char *dst_ip, uint16_t dport)
{
  unsigned char *temp = ptr;
  char bodybuffer[BODY_BUFFER_SIZE];
  char headerbuffer[2048];
  unsigned long int header_len;

  char *start = strstr((char *)ptr,"\r\n\r\n");
  if(!start)
    return;
  start = start+4;
  header_len = start-(char *)ptr;
  header_len = header_len < sizeof(headerbuffer) - 1 ? header_len : sizeof(headerbuffer) - 1;
  memcpy(headerbuffer,ptr,header_len);
  headerbuffer[header_len] = '\0';
    
  int body_len = payload_len - (start - (char *)ptr);
  if(find_http_body(temp,body_len,bodybuffer,sizeof(bodybuffer)))
  {
    logging("INFO","HTTP BODY is :%s",bodybuffer);
  }

  detect_patterns(ptr,headerbuffer,bodybuffer,src_ip,dst_ip,sport,dport);
  return;
}

void *parse_packet(char *args, int bytes_read)
{
  char buffer[65536];
  memset(buffer,0,sizeof(buffer));
  memcpy(buffer,(char *)args,bytes_read);
  buffer[bytes_read] = '\0';
  
  char protocol[16];
  protocol[0] = '\0';
  unsigned char *ptr;
  char app_proto[10];
  app_proto[0] = '\0';
        
  struct ethhdr *eh = (struct ethhdr *)buffer;
  
  unsigned short proto = ntohs(eh->h_proto);
  if(proto == ETH_P_IP)
  {
    
    struct iphdr *ih = (struct iphdr *)(buffer+sizeof(struct ethhdr));
     #if DEBUG
       parse_ipv4(ih);
     #endif

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
       
    inet_ntop(AF_INET, &ih->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ih->daddr, dst_ip, sizeof(dst_ip));
         
    uint16_t ip_header_len = ih->ihl*4;
       
    if(ih->protocol == IPPROTO_TCP)
    {
	  
      strcpy(protocol,"TCP");
	
      struct tcphdr *tp = (struct tcphdr *)(buffer+sizeof(struct ethhdr)+ip_header_len);
      uint16_t sport = ntohs(tp->source);
      uint16_t dport = ntohs(tp->dest);

      uint16_t tcp_header_len = tp->doff*4;                                                                                                                                                                                                
      ptr = (unsigned char *)(buffer+sizeof(struct ethhdr)+ip_header_len+tcp_header_len);                                                                                                                                                  
      size_t  payload_len = ntohs(ih->tot_len)-ip_header_len-tcp_header_len;

      pthread_mutex_lock(&port_lock);
      port_scan_detection(src_ip,dport);
      pthread_mutex_unlock(&port_lock);
	
      if(payload_len == 0 || payload_len > 65535)	
       return NULL;
      
      sscanf((char *)ptr,"%9s",app_proto);
      

      if((strcmp(app_proto,"GET") == 0) || (strcmp(app_proto,"POST") == 0) || (strcmp(app_proto,"PUT") == 0)|| (strcmp(app_proto,"DELETE") == 0) ||
	  (strcmp(app_proto,"HEAD") == 0) || (strcmp(app_proto,"OPTIONS") == 0) || (strcmp(app_proto,"PATCH") == 0) )
      {
	
	atomic_fetch_add(&HTTP_requests,1);
	
	 logging("INFO","APP-PROTO:%s",app_proto);
	 parse_http_request(ptr,payload_len,src_ip,sport,dst_ip,dport);
      }
     }
    }

  return NULL;  
}

void print_stats()
{
  logging("INFO","========== RULE STATISTICS ==========");
  
  logging("INFO","Packets Captured : %d",packets_captured);
  logging("INFO","HTTP Packets : %d",HTTP_requests);
  logging("INFO","Alerts Generated : %d",Alerts_Generated);

  for (int i = 0; i < rules_count; i++)
  {
     logging("INFO","SID=%d  TYPE=%s  SEVERITY=%s  HITS=%d",rules[i].sid, rules[i].TYPE,rules[i].severity,rules[i].hit_count);
  }
  fclose(fp);
  fclose(fp1);
  fclose(fp2);

  for (int i = 0; i < rules_count; i++)
    regfree(&rules[i].reg);
}

void handler_function(int sig)
{
  print_stats();
  exit(0);
}
  
int main()
{
  signal(SIGINT,handler_function);  
  server_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  if(server_fd < 0)
  {
    logging("ERROR",strerror(errno));
    return -1;
  }
  
  queue1 = malloc(sizeof(struct packet_queue));
  queue1->count = 0;
  queue1->head = 0;
  queue1->tail = 0;
  queue1->capacity = 1000;
  queue1->items = (struct packet_item *)malloc(sizeof(struct packet_item)*(queue1->capacity));

  fp = fopen("packets.log","a+");
  if(fp == NULL)
  {
    return -1;
  }
  
  fp2 = fopen("alerts.jsonl","a+");
  if(fp2 == NULL)
  {
    return -1;
  }
  if(!load_rules("rules.txt"))
    return -1;

  for(int i = 0; i < MAX_TRACK; i++)
  {
    source_ips[i].src_ip[0]='\0';
    source_ips[i].hits = 0;
   
  }
  
  pthread_create(&queue1->t[0], NULL, capture_thread, NULL);
  for(int i=1 ; i<5; i++)
  {
    pthread_create(&queue1->t[i], NULL, worker_thread, arg);
  }

  pthread_join(queue1->t[0], NULL);
  for(int i=1 ; i<5; i++)
  {
    pthread_join(queue1->t[i], NULL);
  }

  for (int i = 0; i < rules_count; i++)
    regfree(&rules[i].reg);
  
  fclose(fp);
  fclose(fp2);
  return 0;
}
