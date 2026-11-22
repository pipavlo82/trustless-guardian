#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <openssl/sha.h>
/* Single-purpose bounded synthetic action. No shell, sockets, credentials or arguments. */
static int field(const char *key,const char *expected){
 FILE *f=fopen("/proc/self/status","r");if(!f)return 0;
 char line[256],value[128];int ok=0;
 while(fgets(line,sizeof(line),f))if(!strncmp(line,key,strlen(key))){
  if(sscanf(line+strlen(key),"%127s",value)==1 && !strcmp(value,expected))ok=1;break;
 }fclose(f);return ok;
}
int main(void){
 if(getuid()!=65534||!field("CapEff:","0000000000000000")||!field("NoNewPrivs:","1")||!field("Seccomp:","2"))return 21;
 DIR *d=opendir("/sys/class/net");if(!d)return 22;struct dirent *e;int lo=0;
 while((e=readdir(d))) {if(e->d_name[0]=='.')continue;if(strcmp(e->d_name,"lo")){closedir(d);return 22;}lo=1;}closedir(d);if(!lo)return 22;
 if(access("/var/run/docker.sock",F_OK)==0||access("/host-secret",F_OK)==0)return 23;
 int bad=open("/outside",O_CREAT|O_EXCL|O_WRONLY,0600);if(bad>=0){close(bad);return 24;}
 int in=open("/input/request.json",O_RDONLY|O_NOFOLLOW);if(in<0)return 25;
 unsigned char raw[16385],digest[32];size_t used=0;ssize_t n;
 while((n=read(in,raw+used,sizeof(raw)-used))>0){used+=(size_t)n;if(used==sizeof(raw)){close(in);return 26;}}
 close(in);if(n<0||used==0)return 26;
 if(!SHA256(raw,used,digest))return 27;
 char hex[65];for(int i=0;i<32;i++)sprintf(hex+i*2,"%02x",digest[i]);hex[64]=0;
 int out=open("/tmp/guardian-action",O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);if(out<0)return 28;
 if(write(out,hex,64)!=64||fsync(out)){close(out);return 29;}close(out);
 printf("{\"action\":\"synthetic_request_hash\",\"request_file_sha256\":\"%s\",\"uid\":65534}\n",hex);return 0;
}
