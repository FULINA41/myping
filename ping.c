#include "ping.h"

struct proto proto_v4 = {proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};

#ifdef IPV6
struct proto proto_v6 = {proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6};
#endif

struct settings
{
	int AllowBroadcast;
	int bufsize;
	int useDNS;
	int writeFile;
	int printLatency;
} defaultsetting = {0, 1500, 1, 0, 0};
char filename[500];

int main(int argc, char **argv)
{
	int j4, j6 = 0;
	char *input = NULL;
	int c;
	struct addrinfo *ai;
	opterr = 0; /* don't want getopt() writing to stderr */
	while ((c = getopt(argc, argv, "vVhbt:m:46n:qdF:I:w:s:i:z:qDO:C")) != -1)
	{
		switch (c)
		{
		// verbose
		case 'v':
			verbose++;
			break;

		// show version
		case 'V':
			printf("Version:0.3\n");
			printf("Last updated in 2023/06/30\n");
			exit(0);
			break;

		// allow broadcase
		case 'b':
			defaultsetting.AllowBroadcast = 1;
			break;

		// show help message
		case 'h':
			printf("-h show help message\n");
			printf("-V show version\n");
			printf("-C show project repsitory\n");

			printf("----[options]----\n");
			printf("-v verbose\n");
			printf("-b allow broadcast ip\n");
			printf("-4 Ipv4 address only\n");
			printf("-6 Ipv6 address only\n");
			printf("-q quiet mode\n");
			printf("-d forbid dns resolve\n");
			printf("-D print latency\n");

			printf("----[parameters]----\n");
			printf("-t [ttl] set ttl\n");
			printf("-m [mtu] set mtu\n");
			printf("-n [num] send num packets before exit\n");
			printf("-s [icmp_seq] set icmp packet length\n");
			printf("-i [interval] set time interval between packet sent\n");
			printf("-z [icmp_seq] set icmp_seq\n");
			printf("-w [timeout] set timeout between packet received\n");
			printf("-F [Flowlabel] set flowlabel\n");
			printf("-I [interface] set interface\n");
			printf("-O [filepath] redirect output to file\n");

			exit(0);
			break;

		// set TTL
		case 't':
			myTTL = atoi(optarg);
			break;

		// set mtu
		case 'm': //-m功能，基本完成，但是recvbuf无法释放
			num = atoi(optarg);
			if (num > 9000)
			{
				printf("ERROR, the number of MTU must less than 9000");
				exit(0);
			}
			defaultsetting.bufsize = num;
			break;

		// check ipv4 address
		case '4':
			j4++;
			break;

		// check ipv6 address
		case '6':
			j6++;
			break;

		// set send packet numbers
		case 'n':
			m = atoi(optarg);
			nn = true;
			break;

		// set icmp packet length
		case 's':
			datalen = atoi(optarg);
			break;

		// set time between packet sent
		case 'i':
			sscanf(optarg, "%d", &send_time_interval);
			break;

		// set icmp_seq
		case 'z':
			sscanf(optarg, "%d", &nsent);
			break;

		// quiet mode
		case 'q':
			quiet_mode = 1;
			nn = true;
			break;

		// set timeout
		case 'w':
			timeout = atoi(optarg);
			w_mode = 1;
			break;

		// set dns
		case 'd':
			defaultsetting.useDNS = 0;
			break;

		// set flowlabel
		case 'F':
			myFlowLabel = atoi(optarg);
			break;

		// set interface
		case 'I':
			if (!is_interface_valid(optarg))
			{
				printf("error interface\n");
				exit(0);
			}
			strcpy(myInterface, optarg);
			break;

		// set output to file
		case 'O':
			defaultsetting.writeFile = 1;
			sscanf(optarg, "%s", &filename);
			freopen(filename, "w+", stdout);
			break;

		// print latency
		case 'D':
			defaultsetting.printLatency = 1;
			break;

		case 'C':
			printf("github repository address: https://github.com/MrChenYukun/ping\n");
			exit(0);
			break;

		case '?':
			err_quit("unrecognized option: %c", c);
		}
	}

	if (optind != argc - 1)
		err_quit("usage: ping [ -v ] <hostname>");
	host = argv[optind];
	if (j4)
	{
		Check_IPV4(host);
	}

	if (j6)
	{
		Check_IPV6(host);
	}

	if (defaultsetting.AllowBroadcast == 0)
	{
		for(int i=2;i<strlen(host);i++){
			if(host[i-2]=='2'&&host[i-1]=='5'&&host[i]=='5'){
				err_quit("boardcast ip are not allowed, if you want to do so please add -b parameter");
			}
		}
	}

	pid = getpid();
	signal(SIGALRM, sig_alrm);
	ai = host_serv(host, NULL, 0, 0);
	// 回传次数限制

	printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
		   Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen); // 回传

	/* 4initialize according to protocol */
	if (ai->ai_family == AF_INET)
	{
		pr = &proto_v4;
#ifdef IPV6
	}
	else if (ai->ai_family == AF_INET6)
	{
		pr = &proto_v6;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
										ai->ai_addr)
									   ->sin6_addr)))
			err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
	}
	else
		err_quit("unknown address family %d", ai->ai_family);

	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;

	readloop();

	exit(0);
}

void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{

	int hlen1, icmplen;
	double rtt;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	extern int m;
	extern bool nn;
	extern int timeflag;
	timeflag = 1;
	long recvlatency;

	ip = (struct ip *)ptr;	/* start of IP header */
	hlen1 = ip->ip_hl << 2; /* length of IP header */

	icmp = (struct icmp *)(ptr + hlen1); /* start of ICMP header */
	recv_cnt++;
	if ((icmplen = len - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	if (icmp->icmp_type == ICMP_ECHOREPLY)
	{
		if (icmp->icmp_id != pid)
			return; /* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			err_quit("icmplen (%d) < 16", icmplen);
		recv_icmp_cnt++;
		tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		total_rtt += rtt;
		if (!quiet_mode)
		{
			printf(" seq=%u, ttl=%d, rtt=%.3f ms\n",

				   icmp->icmp_seq, ip->ip_ttl, rtt);
		}
	}
	else if (verbose)
	{
		tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		total_rtt += rtt;

		recvlatency = tvrecv->tv_usec + tvsend->tv_usec;
		if (n >= m && nn)
		{
			printf("Connected successful\n");
			verbose--;
			exit(0);
			double loss_rate = ((double)(n - recv_icmp_cnt) / n) * 100.0;
			double avg_rtt = total_rtt / recv_icmp_cnt;

			if (quiet_mode)
			{
				printf("Loss: %.1f%%, %d packets sent,%d received,average rtt %.3f ms\n", loss_rate, n, recv_icmp_cnt, avg_rtt);
				exit(0);
			}
			else
			{
				printf("Connected successful\n");
				exit(0);
			}
		}

		if (!quiet_mode)
		{
			printf(" ## %d bytes from %s: type = %d, code = %d ",
				   icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				   icmp->icmp_type, icmp->icmp_code);
			if (defaultsetting.printLatency == 1)
			{
				printf("latency=%d ", recvlatency - tvsend->tv_usec);
			}
			else
			{
				printf(" ");
			}
		}
		n = n + 1;
		recv_icmp_cnt++;
	}
}

void proc_v6(char *ptr, ssize_t len, struct timeval *tvrecv)
{
#ifdef IPV6
	int hlen1, icmp6len;
	double rtt;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct timeval *tvsend;
	extern int m;
	long recvlatency;

	/*
	ip6 = (struct ip6_hdr *) ptr;		// start of IPv6 header
	hlen1 = sizeof(struct ip6_hdr);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		err_quit("next header not IPPROTO_ICMPV6");

	icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
	if ( (icmp6len = len - hlen1) < 8)
		err_quit("icmp6len (%d) < 8", icmp6len);
	*/

	icmp6 = (struct icmp6_hdr *)ptr;
	if ((icmp6len = len) < 8) // len-40
		err_quit("icmp6len (%d) < 8", icmp6len);

	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY)
	{
		if (icmp6->icmp6_id != pid)
			return; /* not a response to our ECHO_REQUEST */
		if (icmp6len < 16)
			err_quit("icmp6len (%d) < 16", icmp6len);

		tvsend = (struct timeval *)(icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		printf("seq=%u, hlim=%d, rtt=%.3f ms\n", icmp6->icmp6_seq, ip6->ip6_hlim, rtt);
	}
	else if (verbose)
	{
		tvsend = (struct timeval *)(icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		recvlatency = tvrecv->tv_usec + tvsend->tv_usec;
		if (n >= m && nn)
		{
			printf("Connected successful\n");
			exit(0);
		}
		printf(" ## %d bytes from %s: type = %d, code = %d\n send_latency is :%ld, recv_latency is:%ld\n",
			   icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
			   icmp6->icmp6_type, icmp6->icmp6_code, tvsend->tv_usec, recvlatency);
		n = n + 1;
	}
#endif /* IPV6 */
}

unsigned short
in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* 4mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);					/* add carry */
	answer = ~sum;						/* truncate to 16 bits */
	return (answer);
}

void send_v4(void)
{
	int len;
	struct icmp *icmp;

	icmp = (struct icmp *)sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	gettimeofday((struct timeval *)icmp->icmp_data, NULL);

	len = 8 + datalen; /* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *)icmp, len);

	if (strcmp(myInterface, "default") != 0)
	{
		change_interface(myInterface);
	}

	if (myTTL > 0 && myTTL <= 255)
	{
		/*set TTL*/
		if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &myTTL, sizeof(myTTL)) == -1)
			perror("set TTL error");
		sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
	}
	else
	{
		printf("error TTL value\n");
	}
	send_cnt++;
}

void send_v6()
{
#ifdef IPV6
	int len;
	struct icmp6_hdr *icmp6;

	icmp6 = (struct icmp6_hdr *)sendbuf;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = pid;
	icmp6->icmp6_seq = nsent++;
	gettimeofday((struct timeval *)(icmp6 + 1), NULL);

	len = 8 + datalen; /* 8-byte ICMPv6 header */

	if (myFlowLabel > 0 && myFlowLabel <= 1048575)
	{
		if (myFlowLabel != -1 && !setsockopt(sockfd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &myFlowLabel, sizeof(myFlowLabel)) == -1)
		{
			perror("error flowlabel");
			exit(1);
		}
		sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
	}
	else
	{
		printf("error myFlowLabel value\n");
	}

	/* kernel calculates and stores checksum for us */
#endif /* IPV6 */
}

void readloop(void)
{
	int size;
	socklen_t len;
	ssize_t n;
	struct timeval tval;
	extern clock_t start;
	extern clock_t now;
	extern int timeout, timeflag;
	struct timeval Timeout;

	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
	setuid(getuid()); /* don't need special permissions any more */

	size = defaultsetting.bufsize; /* OK if setsockopt fails */
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	sig_alrm(SIGALRM); /* send first packet */

	for (;;)
	{
		Timeout.tv_sec = timeout;
		Timeout.tv_usec = 500000;
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &Timeout, sizeof(Timeout));

		if (w_mode)
		{
			len = pr->salen;
			n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
			if (n < 0)
			{
				if (errno == EINTR)
				{
					if ((clock() - start) >= timeout * 100)
					{
						printf("TIME OUT!\n");
						exit(0);
					}
					continue;
				}
				else
					err_sys("recvfrom error");
			}

			if ((clock() - start) >= timeout * 100)
			{
				printf("TIME OUT!\n");
				exit(0);
			}
			gettimeofday(&tval, NULL);
			(*pr->fproc)(recvbuf, n, &tval);
		}
		else
		{
			len = pr->salen;
			n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
					err_sys("recvfrom error");
			}
			gettimeofday(&tval, NULL);
			(*pr->fproc)(recvbuf, n, &tval);
		}
	}
}

void sig_alrm(int signo)
{
	extern clock_t start;
	extern clock_t now;
	(*pr->fsend)();
	if (timeflag)
	{
		start = clock();
		timeflag = 0;
	}

	alarm(send_time_interval); // 每隔send_time_interval秒触发一次send函数
	return;					   /* probably interrupts recvfrom() */
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)
	{ /* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

char *
sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	static char str[128]; /* Unix domain is largest */

	switch (sa->sa_family)
	{
	case AF_INET:
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return (NULL);
		return (str);
	}

#ifdef IPV6
	case AF_INET6:
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

		if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
			return (NULL);
		return (str);
	}
#endif

#ifdef HAVE_SOCKADDR_DL_STRUCT
	case AF_LINK:
	{
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

		if (sdl->sdl_nlen > 0)
			snprintf(str, sizeof(str), "%*s",
					 sdl->sdl_nlen, &sdl->sdl_data[0]);
		else
			snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
		return (str);
	}
#endif
	default:
		snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
				 sa->sa_family, salen);
		return (str);
	}
	return (NULL);
}

char *
Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	char *ptr;

	if ((ptr = sock_ntop_host(sa, salen)) == NULL)
		err_sys("sock_ntop_host error"); /* inet_ntop() sets errno */
	return (ptr);
}

struct addrinfo *
host_serv(const char *host, const char *serv, int family, int socktype)
{
	int n;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	if (defaultsetting.useDNS == 0)
	{
		hints.ai_flags = AI_NUMERICHOST;
	}
	else
	{
		hints.ai_flags = AI_CANONNAME; /* always return canonical name */
	}
	hints.ai_family = family;	  /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = socktype; /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		return (NULL);

	return (res); /* return pointer to first on linked list */
}
/* end host_serv */

static void
err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLINE];

	errno_save = errno; /* value caller might want printed */
#ifdef HAVE_VSNPRINTF
	vsnprintf(buf, sizeof(buf), fmt, ap); /* this is safe */
#else
	vsprintf(buf, fmt, ap); /* this is not safe */
#endif
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc)
	{
		syslog(level, buf);
	}
	else
	{
		fflush(stdout); /* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void err_quit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void err_sys(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void Check_IPV4(char *input)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, input, &(sa.sin_addr));
	if (result != 1)
	{
		printf("%s is not a valid IPv4 address.\n", input);
	}
	return;
}
void Check_IPV6(char *input)
{
	struct in6_addr addr;
	if (inet_pton(AF_INET6, input, &addr) != 1)
	{
		fprintf(stderr, "%s is not a valid IPv6 address.\n", input);
		exit(EXIT_FAILURE);
	}
}

int is_interface_valid(const char *interface)
{
	struct ifaddrs *ifaddr, *ifa;
	int valid = 0;

	// Get the list of available network interfaces
	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs error");
		return 0; // Not valid if failed to get interface list
	}

	// Traverse the network interface list
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		// Check if the interface names match
		if (ifa->ifa_name && strcmp(ifa->ifa_name, interface) == 0)
		{
			valid = 1; // Interface name is valid
			break;
		}
	}

	freeifaddrs(ifaddr); // Free the interface list

	return valid;
}

void change_interface(const char *interface)
{
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) == -1)
	{
		perror("change interface error");
		exit(1);
	}

	return;
}