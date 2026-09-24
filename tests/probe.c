// Device-side probes: DNS, STUN over UDP, unsupported datagrams, interface binding, and IPv6.
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
int main(int argc,char **argv) {
 if(argc<4){fprintf(stderr,"usage: probe tcp|udp|dns|stun IP PORT [INTERFACE]\n");return 2;}
 int af=strchr(argv[2],':')?AF_INET6:AF_INET;
 int tcp=strcmp(argv[1],"tcp")==0;
 int fd=socket(af,tcp?SOCK_STREAM:SOCK_DGRAM,0);
 struct timeval tv={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
 if(argc>4){unsigned ix=if_nametoindex(argv[4]);if(!ix||setsockopt(fd,af==AF_INET?IPPROTO_IP:IPPROTO_IPV6,af==AF_INET?25:125,&ix,sizeof(ix))<0){perror("bind interface");return 2;}}
 struct sockaddr_storage ss={0};socklen_t len;
 if(af==AF_INET){struct sockaddr_in *s=(void*)&ss;s->sin_len=sizeof(*s);s->sin_family=af;s->sin_port=htons(atoi(argv[3]));inet_pton(af,argv[2],&s->sin_addr);len=sizeof(*s);}
 else{struct sockaddr_in6 *s=(void*)&ss;s->sin6_len=sizeof(*s);s->sin6_family=af;s->sin6_port=htons(atoi(argv[3]));inet_pton(af,argv[2],&s->sin6_addr);len=sizeof(*s);}
 if(connect(fd,(void*)&ss,len)<0){perror("connect");return 1;}
 unsigned char q[]={0x53,0x51,1,0,0,1,0,0,0,0,0,0,3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
 const char *payload="slipstream-datagram-probe";
 int dns=strcmp(argv[1],"dns")==0;
 int stun=strcmp(argv[1],"stun")==0;
 // RFC 5389 Binding Request: type 0x0001, length 0, magic cookie, transaction id.
 unsigned char st[20]={0,1,0,0,0x21,0x12,0xa4,0x42,'s','l','i','p','s','t','r','e','a','m','0','1'};
 if(tcp){puts("TCP connected");close(fd);return 0;}
 if(stun)send(fd,st,sizeof(st),0);
 else for(int i=0;i<(dns?1:300);i++)send(fd,dns?(void*)q:(void*)payload,dns?sizeof(q):strlen(payload),0);
 unsigned char b[4096];ssize_t n=recv(fd,b,sizeof(b),0);
 if(n<0){perror("receive");return 1;}
 if(stun){if(n>=20 && b[0]==1 && b[1]==1 && !memcmp(b+4,st+4,16)){printf("STUN reply: %zd bytes\n",n);return 0;} printf("unexpected %zd bytes\n",n);return 1;}
 if(dns && n>=12 && b[0]==q[0] && b[1]==q[1] && (b[2]&128)) {printf("DNS reply: %zd bytes, rcode %d, answers %d\n",n,b[3]&15,b[6]*256+b[7]);return (b[3]&15)?1:0;}
 printf("received %zd bytes\n",n);return 0;
}
