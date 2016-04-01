//###########################################//
//              Simple IDS                   //
//    Author: Inho Cho<inho00@kaist.ac.kr    //
//          Last Update: 2016. 4. 1.         //
//###########################################//

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>		// for IP header.
#include <netinet/tcp.h>	// for TCP header.
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>

#define ETH_OFFSET 14		// ethernet header = 14 bytes

typedef struct ids_rule_{
	bool ip_tos_on;
	uint8_t ip_tos;
	bool ip_length_on;
	uint16_t ip_length;
	bool ip_frag_offset_on;
	uint16_t ip_frag_offset;
	bool ip_ttl_on;
	uint8_t ip_ttl;
	bool ip_protocol_on;
	uint8_t ip_protocol;
	bool ip_saddr_on;
	uint32_t ip_saddr;
	bool ip_daddr_on;
	uint32_t ip_daddr;

	bool tcp_sport_on;
	uint16_t tcp_sport;
	bool tcp_dport_on;
	uint16_t tcp_dport;
	bool tcp_seq_on;
	uint32_t tcp_seq;
	bool tcp_ack_on;
	uint32_t tcp_ack;
	bool tcp_flags_on;
	uint8_t tcp_flags;

	bool http_request_on;
	u_char *http_request;
	bool payload_content_on;
	u_char *payload_content;

	struct ids_rule_ *next;
} ids_rule;

typedef struct content_string_{
	char *content;
	struct content_string_ *next;
} content_string;

typedef struct match_result_{
	bool ip_tos;
	bool ip_length;
	bool ip_frag_offset;
	bool ip_ttl;
	bool ip_protocol;
	bool ip_saddr;
	bool ip_daddr;

	bool tcp_sport;
	bool tcp_dport;
	bool tcp_seq;
	bool tcp_ack;
	bool tcp_flags;

	bool http_request;
	content_string *contents;
	content_string *contents_tail;
} match_result;

static pcap_t *handle;			// packet capture handler
static struct bpf_program fp;	// compiled filter program (expression)
static ids_rule *ruleset;
static ids_rule *ruleset_tail;

void parse_pattern(char *pattern, ids_rule *rule){
	char *ptr;
	char *value;

	if(strncmp(pattern,"tos",3)==0){ // tos
		value = pattern+4;
		rule->ip_tos_on = true;
		rule->ip_tos = atoi(value);
	}else if(strncmp(pattern,"fragoffset",10)==0){ // Fragment Offset
		value = pattern+11;
		rule->ip_frag_offset_on = true;
		rule->ip_frag_offset = atoi(value);
	}else if(strncmp(pattern,"ttl",3)==0){ // TTL
		value = pattern+4;
		rule->ip_ttl_on = true;
		rule->ip_ttl = atoi(value);
	}else if(strncmp(pattern,"seq",3)==0){ // seq
		value = pattern+4;
		rule->tcp_seq_on = true;
		rule->tcp_seq = atoi(value);
	}else if(strncmp(pattern,"ack",3)==0){ // ack
		value = pattern+4;
		rule->tcp_ack_on = true;
		rule->tcp_ack = atoi(value);
	}else if(strncmp(pattern,"flags",5)==0){ // flags
		value = pattern+6;
		rule->tcp_flags_on = true;
		uint8_t new_flag = 0;

		while(*value!='\0'){
			switch(*value){
				case 'F':
					new_flag |= 0x01;
					break;
				case 'S':
					new_flag |= 0x02;
					break;
				case 'R':
					new_flag |= 0x04;
					break;
				case 'P':
					new_flag |= 0x08;
					break;
				case 'A':
					new_flag |= 0x10;
					break;
				case 'U':
					new_flag |= 0x20;
					break;
				case 'E':
					new_flag |= 0x40;
					break;
				case 'C':
					new_flag |= 0x80;
					break;
				default:
					fprintf(stderr,"Unkown flag: %c\n.",*value);
					exit(EXIT_FAILURE);
			}
			value = value+1;
			rule->tcp_flags = new_flag;
		}
	}else if(strncmp(pattern,"http_request",12)==0){
		unsigned int value_len;

		rule->http_request_on = true;
		value = strstr(pattern+14,"\"");
		value_len = value - (pattern+14) + 1;
		rule->http_request = malloc(value_len);
		memcpy(rule->http_request,pattern+14,value_len);
		rule->http_request[value_len-1] = '\0';
	}else if(strncmp(pattern,"content",7)==0){
		unsigned int value_len;

		rule->payload_content_on = true;
		value = strstr(pattern+9,"\"");
		value_len = value - (pattern+9) + 1;
		rule->payload_content = malloc(value_len);
		memcpy(rule->payload_content, pattern+9, value_len);
		rule->payload_content[value_len-1] = '\0';	
	}else{
		fprintf(stderr,"Unknown pattern is detected: %s. Please check the IDS rule syntax.\n",pattern);
		exit(EXIT_FAILURE);
	}
}

void parse_rule_file (const char *ruleFile){
	FILE *rfile;
	char buf[1024];

	rfile = fopen(ruleFile,"r");
	if (rfile == NULL){
		fprintf(stderr, "Couldn't open input rule file: %s\n", ruleFile);
		exit(EXIT_FAILURE);
	}
	
	while(fgets(buf,sizeof(buf),rfile)!=NULL){
		ids_rule *new_rule;
		char *ptr;
		char *patterns;
		char *pattern;
		struct sockaddr_in source, dest;

		if(strncmp(buf,"\n",1)==0)
			continue;

		new_rule = calloc(1,sizeof(ids_rule));	

		// alert
		ptr = strtok(buf, " ");
		if(strcmp(ptr,"alert")){
			fprintf(stderr, "Invalid IDS rule. Please check the syntax of the IDS rules.\n");
			exit(EXIT_FAILURE);
		}

		// tcp
		ptr = strtok(NULL, " ");
		if(strcmp(ptr,"tcp")){
			fprintf(stderr, "Invalid IDS rule. This IDS supports only TCP.\n");
			exit(EXIT_FAILURE);
		}else{
			new_rule->ip_protocol_on = true;
			new_rule->ip_protocol = IPPROTO_TCP;
		}

		// source IP
		ptr = strtok(NULL, " ");
		if(strcmp(ptr, "any")){
			new_rule->ip_saddr_on = true;
			inet_aton(ptr,&source.sin_addr);
			new_rule->ip_saddr = source.sin_addr.s_addr;
		}

		// source port
		ptr = strtok(NULL, " ");
		if(strcmp(ptr, "any")){
			new_rule->tcp_sport_on = true;
			new_rule->tcp_sport = atoi(ptr);
		}

		// ->
		ptr = strtok(NULL, " ");
		if(strcmp(ptr, "->")){
			fprintf(stderr, "Failed to parse IDS rule. Please check the syntax of IDS rules.\n");
			exit(EXIT_FAILURE);
		}

		// dest IP
		ptr = strtok(NULL, " ");
		if(strcmp(ptr,"any")){
			new_rule->ip_daddr_on = true;
			inet_aton(ptr, &dest.sin_addr);
			new_rule->ip_daddr = dest.sin_addr.s_addr;
		}

		// dest port
		ptr = strtok(NULL, " ");
		if(strcmp(ptr,"any")){
			new_rule->tcp_dport_on = true;
			new_rule->tcp_dport = atoi(ptr);
		}

		ptr = strtok(NULL, "\n");
		patterns = ptr;

		ptr = strtok(patterns,";");
		pattern = ptr+1;
		parse_pattern(pattern, new_rule);
		while(pattern = strtok(NULL,";")){
			if(strcmp(pattern,")")==0)
				break;
			parse_pattern(pattern, new_rule);
		}

		if(ruleset == NULL){
			ruleset = new_rule;
			ruleset_tail = new_rule;
		}else{
			ruleset_tail->next = new_rule;
			ruleset_tail = new_rule;
		}
	}
	fclose(rfile);			
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
// this function is borrowed from sniffex.c
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("\t%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void
print_payload(const u_char *payload, int len)
// This function is borrowed from sniffex.c
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
	return;
}

void got_packet(u_char *agrs, const struct pcap_pkthdr *header, const u_char *packet){
	// Incoming packet is detected.	
	ids_rule *rule;
	match_result *result = calloc(1,sizeof(match_result));

	struct iphdr *iph = (struct iphdr *)(packet+ETH_OFFSET);
	unsigned int iph_size = (unsigned int)iph->ihl*4;
	struct sockaddr_in source,dest;

	struct tcphdr *tcph = (struct tcphdr *)(packet+ETH_OFFSET+iph_size);
	unsigned int tcph_size = (unsigned int)tcph->doff*4;

	u_char *payload = (u_char *)(packet+ETH_OFFSET+iph_size+tcph_size);
	unsigned int payload_size = ntohs(iph->tot_len)-iph_size-tcph_size;

	u_char *http_request = NULL;
	unsigned int http_request_size;
	u_char *http_contents = NULL;
	unsigned int http_contents_size;

	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));

	source.sin_addr.s_addr = iph->saddr;
	dest.sin_addr.s_addr = iph->daddr;

	if ((strncmp(payload, "OPTIONS", 7) == 0)
		|| (strncmp(payload, "GET", 3) == 0)
		|| (strncmp(payload, "HEAD", 4) == 0)
		|| (strncmp(payload, "POST", 4) == 0)
		|| (strncmp(payload, "PUT", 3) == 0)
		|| (strncmp(payload, "DELETE", 3) == 0)
		|| (strncmp(payload, "TRACE", 5) == 0)
		|| (strncmp(payload, "CONNECT", 7) == 0)
		|| (strncmp(payload, "PATCH", 5) == 0)){
		// HTTP request detected.
		http_request = malloc(payload_size+1);
		memcpy(http_request,payload,payload_size);
		http_request[payload_size]='\0';
		http_contents = (u_char *)strstr(http_request, " ");
		http_contents = (u_char *)strstr(http_contents+1," ");
		*http_contents = '\0';
		http_contents += 1;
		http_request_size = (unsigned int)http_contents - (unsigned int)http_request;
		http_contents_size = payload_size + 1 - http_request_size;
		printf("req size=%d,consize=%d\n",http_request_size, http_contents_size);
	}


	for(rule = ruleset; rule != NULL; rule = rule->next){
		
		if (rule->ip_tos_on && (rule->ip_tos != iph->tos))
			continue;
		if (rule->ip_length_on && (rule->ip_length != ntohs(iph->tot_len)))
			continue;
		if (rule->ip_frag_offset_on && (rule->ip_frag_offset != ntohs(iph->frag_off)))
			continue;
		if (rule->ip_ttl_on && (rule->ip_ttl != iph->ttl))
			continue;
		if (rule->ip_protocol_on && (rule->ip_protocol != iph->protocol))
			continue;
		if (rule->ip_saddr_on && (rule->ip_saddr != iph->saddr))
			continue;
		if (rule->ip_daddr_on && (rule->ip_daddr != iph->daddr))
			continue;
		if (rule->tcp_sport_on && (rule->tcp_sport != ntohs(tcph->source)))
			continue;
		if (rule->tcp_dport_on && (rule->tcp_dport != ntohs(tcph->dest)))
			continue;
		if (rule->tcp_seq_on && (rule->tcp_seq != ntohl(tcph->seq)))
			continue;
		if (rule->tcp_ack_on && (rule->tcp_ack != ntohl(tcph->ack_seq)))
			continue;
		if (rule->tcp_flags_on && (rule->tcp_flags != tcph->th_flags))
			continue;
		if (rule->http_request_on && ((http_request == NULL) || (strstr(http_request,rule->http_request) == NULL)))
			continue;

		// If packet reach here, packet matches!
		if(rule->ip_tos_on)
			result->ip_tos = true;
		if(rule->ip_length_on)
			result->ip_length = true;
		if(rule->ip_frag_offset_on)
			result->ip_frag_offset = true;
		if(rule->ip_ttl_on)
			result->ip_ttl = true;
		if(rule->ip_protocol_on)
			result->ip_protocol = true;
		if(rule->ip_saddr_on)
			result->ip_saddr = true;
		if(rule->ip_daddr_on)
			result->ip_daddr = true;
		if(rule->tcp_sport_on)
			result->tcp_sport = true;
		if(rule->tcp_dport_on)
			result->tcp_dport = true;
		if(rule->tcp_seq_on)
			result->tcp_seq = true;
		if(rule->tcp_ack_on)
			result->tcp_ack = true;
		if(rule->tcp_flags_on)
			result->tcp_flags = true;
		if(rule->http_request_on)
			result->http_request = true;
		if(rule->payload_content_on){
			content_string *cstr = malloc(sizeof(content_string));
			cstr->content = rule->payload_content;
			cstr->next = NULL;
			if (result->contents){
				result->contents_tail->next = cstr;
				result->contents_tail = cstr;
			}else{
				result->contents = cstr;
				result->contents_tail = result->contents;
			}
		}
	}

	// print IP header
	printf("IP Header\n");
	printf("\tIP Version: %d\n", (unsigned int)iph->version);
	printf("\tIP Header Length: %d\n", (unsigned int)iph->ihl*4);

	if(result->ip_tos)	
		printf("\t""\x1b[31m""***Type of Service: %d""\x1b[0m""\n", (unsigned int)iph->tos);
	else
		printf("\tType of Service: %d\n", (unsigned int)iph->tos);

	if(result->ip_length)
		printf("\t""\x1b[31m""***IP Total Length: %d""\x1b[0m""\n", ntohs(iph->tot_len));
	else
		printf("\tIP Total Length: %d\n", ntohs(iph->tot_len));

	if(result->ip_frag_offset)
		printf("\t""\x1b[31m""***Fragment Offset: %d""\x1b[0m""\n", ntohs(iph->frag_off));
	else
		printf("\tFragment Offset: %d\n", ntohs(iph->frag_off));

	printf("\tIdentification: %d\n", ntohs(iph->id));

	if(result->ip_ttl)
		printf("\t""\x1b[31m""***TTL: %d""\x1b[0m""\n", (unsigned int)iph->ttl);
	else
		printf("\tTTL: %d\n", (unsigned int)iph->ttl);

	if(result->ip_protocol)
		printf("\t""\x1b[31m""***Protocol: %d""\x1b[0m""\n", (unsigned int)iph->protocol);
	else
		printf("\tProtocol: %d\n", (unsigned int)iph->protocol);

	printf("\tChecksum: %d\n", ntohs(iph->check));	

	if(result->ip_saddr)
		printf("\t""\x1b[31m""***Source IP = %s""\x1b[0m""\n", inet_ntoa(source.sin_addr));
	else
		printf("\tSource IP = %s\n", inet_ntoa(source.sin_addr));

	if(result->ip_daddr)
		printf("\t""\x1b[31m""***Destination IP = %s""\x1b[0m""\n", inet_ntoa(dest.sin_addr));
	else
		printf("\tDestination IP = %s\n", inet_ntoa(dest.sin_addr));

	// print TCP header
	printf("TCP Header\n");

	if(result->tcp_sport)
		printf("\t""\x1b[31m""***Source Port: %u""\x1b[0m""\n", ntohs(tcph->source));
	else
		printf("\tSource Port: %u\n", ntohs(tcph->source));

	if(result->tcp_dport)
		printf("\t""\x1b[31m""***Destination Port: %u""\x1b[0m""\n", ntohs(tcph->dest));
	else
		printf("\tDestination Port: %u\n", ntohs(tcph->dest));

	if(result->tcp_seq)
		printf("\t""\x1b[31m""***Sequence Number: %u""\x1b[0m""\n", ntohl(tcph->seq));
	else
		printf("\tSequence Number: %u\n", ntohl(tcph->seq));

	if(result->tcp_ack)
		printf("\t""\x1b[31m""***Acknowledge Number: %u""\x1b[0m""\n", ntohl(tcph->ack_seq));
	else
		printf("\tAcknowledge Number: %u\n", ntohl(tcph->ack_seq));

	printf("\tTCP Header Length: %d\n", (unsigned int)tcph->doff*4);

	if(result->tcp_flags){
		printf("\t""\x1b[31m""***Flags: %d""\x1b[0m""\n", (unsigned int)tcph->th_flags);
		printf("\t""\x1b[31m""***CWR Flag: %d""\x1b[0m""\n", (unsigned int)((tcph->th_flags&0x40)>>6));
		printf("\t""\x1b[31m""***ECE Flag: %d""\x1b[0m""\n", (unsigned int)((tcph->th_flags&0x80)>>7));
		printf("\t""\x1b[31m""***URG Flag: %d""\x1b[0m""\n", (unsigned int)tcph->urg);
		printf("\t""\x1b[31m""***ACK Flag: %d""\x1b[0m""\n", (unsigned int)tcph->ack);
		printf("\t""\x1b[31m""***PSH Flag: %d""\x1b[0m""\n", (unsigned int)tcph->psh);
		printf("\t""\x1b[31m""***RST Flag: %d""\x1b[0m""\n", (unsigned int)tcph->rst);
		printf("\t""\x1b[31m""***SYN Flag: %d""\x1b[0m""\n", (unsigned int)tcph->syn);
		printf("\t""\x1b[31m""***FIN Flag: %d""\x1b[0m""\n", (unsigned int)tcph->fin);
	}else{
		printf("\tFlags: %d\n", (unsigned int)tcph->th_flags);
		printf("\tCWR Flag: %d\n", (unsigned int)((tcph->th_flags&0x40)>>6));
		printf("\tECE Flag: %d\n", (unsigned int)((tcph->th_flags&0x80)>>7));
		printf("\tURG Flag: %d\n", (unsigned int)tcph->urg);
		printf("\tACK Flag: %d\n", (unsigned int)tcph->ack);
		printf("\tPSH Flag: %d\n", (unsigned int)tcph->psh);
		printf("\tRST Flag: %d\n", (unsigned int)tcph->rst);
		printf("\tSYN Flag: %d\n", (unsigned int)tcph->syn);
		printf("\tFIN Flag: %d\n", (unsigned int)tcph->fin);
	}
	printf("\tWindow: %d\n", ntohs(tcph->window));
	printf("\tChecksum: %d\n", ntohs(tcph->check));
	printf("\tUrgent Pointer: %d\n", tcph->urg_ptr);
	// print TCP Payload
	printf("TCP Payload\n");
	if(http_request){
		if(result->http_request)
			printf("\t""\x1b[31m""***HTTP Request: %s""\x1b[0m""\n", http_request);
		else
			printf("\tHTTP Request: %s\n", http_request);
	}

	printf("\tPayload:\n");
	print_payload(payload,payload_size);	

	if (result->contents){
		content_string *cstr;
		for(cstr = result->contents; cstr != NULL; cstr = cstr->next){
			if(http_request){ // When this packet is HTTP request
				if((char*)memmem(http_contents, http_contents_size, cstr->content,strlen(cstr->content)) != NULL)
					printf("\x1b[31m""Pattern: '%s' detected.""\x1b[0m""\n",cstr->content);
				else
					printf("Pattern: '%s' NOT detected.\n", cstr->content);
			}else{ // When this is not HTTP request packet.
				if((char *)memmem(payload,payload_size,cstr->content,strlen(cstr->content)) != NULL)
					printf("\x1b[31m""Pattern: '%s' detected.""\x1b[0m""\n",cstr->content);
				else
					printf("Pattern: '%s' NOT detected.\n", cstr->content);
			}
		}
	}

	printf("\n");
	if(http_request)
		free(http_request);

	content_string *temp = result->contents;
	while(temp != NULL){
		content_string *tfree;
		tfree = temp;
		temp = temp->next;
		free(tfree);
	}
	
	free(result);
}

void intHandler (int dummy){
	// clean up when SIGINT signal is detected.
	pcap_freecode(&fp);
	pcap_close(handle);
	exit(0);
}

void printUsage(){
	printf("Usage: ./ids [-i interface_name] ruleFile\n");
	exit(EXIT_FAILURE);
}

int main (int argc, char **argv){
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];	// error buffer
	char *ruleFile;						// rule file name

	char filter_exp[] = "ip";			// filter expression
	bpf_u_int32 mask;						// subnet mask
	bpf_u_int32 net;						// IP addr
	int c;

	// parse the option
	while ((c = getopt (argc, argv, "i:")) != -1){
		switch (c){
			case 'i':
				dev = optarg;
				break;
			case '?':
				if (optopt == 'i')
					fprintf(stderr, "Option '-%c' requires an argument (device name. ex: eth0).\n", optopt);
				else
					fprintf(stderr, "Unkown option '-%c'.\n", optopt);
				printUsage();
				exit(EXIT_FAILURE);
			default:
				abort();
		}
	}

	if (optind != argc-1){
		printUsage();
		exit(EXIT_FAILURE);
	}else{
		ruleFile = argv[optind];
	}
	
	signal(SIGINT, intHandler);

	// parsing rule file
	ruleset = NULL;
	ruleset_tail = NULL;
	parse_rule_file (ruleFile);

	// find a capture device
	if (dev == NULL)
		dev = pcap_lookupdev(errbuf);
	if (dev == NULL){
		fprintf(stderr, "Couldn't find default device: %s.\n",errbuf);
		fprintf(stderr, "Try to execute with sudo or give explicit device name with -i option.\n");
		exit(EXIT_FAILURE);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	// open capture device
	handle = pcap_open_live (dev, 1518, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	// make sure dev is ethernet device.
	if (pcap_datalink(handle) != DLT_EN10MB){
		fprintf(stderr, "%s is not an Ethernet device.\n",dev);
		exit(EXIT_FAILURE);
	}

	// compile the filter expression
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Couldn't parse filter %s: %s.\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	// apply the compiled filter
	if (pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, 0, got_packet, NULL);

	exit (0);
}
