#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/types.h>  /* basic system data types */
#include <sys/socket.h> /* basic socket definitions */
#include <sys/time.h>   /* timeval{} for select() */
#include <time.h>       /* timespec{} for pselect() */
#include <netinet/in.h> /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>  /* inet(3) functions */
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/un.h> /* for Unix domain sockets */
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdbool.h>
#include <linux/in6.h>
#include <ifaddrs.h>
#include <fcntl.h>
#ifdef HAVE_SOCKADDR_DL_STRUCT
#include <net/if_dl.h>
#endif

#define IPV6

#define BUFSIZE 1500
#define MAXLINE 4096

/* globals */
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int datalen = 56; /* data that goes with ICMP echo request */
int num;
int result;
int m = 0; // 回传设置器
int n = 0; // 回传次数计数器
bool nn = false;
int send_time_interval = 1; // 设置传输时间间隔，默认为1

int quiet_mode = 0;
int send_cnt = 0;
int recv_cnt = 0;
int recv_icmp_cnt = 0;
double total_rtt = 0.0;

// int datalen; /* #bytes of data, following ICMP header */
char *host;
int nsent = 0; /* add 1 for each sendto() */
pid_t pid;     /* our PID */
int sockfd;
int verbose;
int daemon_proc; /* set nonzero by daemon_init() */
int myTTL = 64;
int myFlowLabel = -1;
char myInterface[8] = "default";

int timeout = 5;
int w_mode = 0;
fd_set rset;
struct timeval;
clock_t start;
clock_t now;
int timeflag = 1;
/* function prototypes */
void proc_v4(char *, ssize_t, struct timeval *);
void proc_v6(char *, ssize_t, struct timeval *);
void send_v4(void);
void send_v6(void);
void readloop(void);
void sig_alrm(int);
void tv_sub(struct timeval *, struct timeval *);

char *Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo *host_serv(const char *host, const char *serv, int family, int socktype);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);
void err_quit(const char *fmt, ...);
void err_sys(const char *fmt, ...);

void Check_IPV4(char *input); // 函数声明
void Check_IPV6(char *input); // 函数声明

int is_interface_valid(const char *interface);
void change_interface(const char *interface);

struct proto
{
  void (*fproc)(char *, ssize_t, struct timeval *);
  void (*fsend)(void);
  struct sockaddr *sasend; /* sockaddr{} for send, from getaddrinfo */
  struct sockaddr *sarecv; /* sockaddr{} for receiving */
  socklen_t salen;         /* length of sockaddr{}s */
  int icmpproto;           /* IPPROTO_xxx value for ICMP */
} *pr;
