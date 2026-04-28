#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define DEFAULT_QUEUE_NUM 0
#define DEFAULT_BLOCK_HOST "google.com"

typedef struct {
	const char *block_host;
	uint16_t queue_num;
} app_config;

static uint32_t get_packet_id(struct nfq_data *nfa) {
	struct nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(nfa);

	if (packet_header == NULL) {
		return 0;
	}

	return ntohl(packet_header->packet_id);
}

static int is_http_method(const unsigned char *payload, int payload_len) {
	static const char *methods[] = {
		"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
		"OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
	};
	size_t i;

	for (i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i) {
		size_t method_len = strlen(methods[i]);

		if (payload_len >= (int)method_len &&
		    memcmp(payload, methods[i], method_len) == 0) {
			return 1;
		}
	}

	return 0;
}

static const unsigned char *find_case_insensitive(const unsigned char *buffer,
						  int buffer_len,
						  const char *needle) {
	size_t needle_len;
	int i;

	if (buffer == NULL || needle == NULL) {
		return NULL;
	}

	needle_len = strlen(needle);
	if (needle_len == 0 || buffer_len < (int)needle_len) {
		return NULL;
	}

	for (i = 0; i <= buffer_len - (int)needle_len; ++i) {
		if (strncasecmp((const char *)(buffer + i), needle, needle_len) == 0) {
			return buffer + i;
		}
	}

	return NULL;
}

static int extract_host_header(const unsigned char *payload, int payload_len,
			       char *host, size_t host_len) {
	const char *host_key = "\r\nHost:";
	const unsigned char *payload_end = payload + payload_len;
	const unsigned char *cursor;

	if (payload == NULL || payload_len <= 0 || host == NULL || host_len == 0) {
		return 0;
	}

	host[0] = '\0';

	if (payload_len >= 5 && strncasecmp((const char *)payload, "Host:", 5) == 0) {
		cursor = payload;
	} else {
		cursor = find_case_insensitive(payload, payload_len, host_key);
		if (cursor == NULL) {
			return 0;
		}
		cursor += 2;
	}

	cursor += 5;
	while (cursor < payload_end && (*cursor == ' ' || *cursor == '\t')) {
		++cursor;
	}

	{
		size_t index = 0;

		while (cursor < payload_end && *cursor != '\r' && *cursor != '\n') {
			if (index + 1 >= host_len) {
				return 0;
			}
			host[index++] = (char)*cursor++;
		}
		host[index] = '\0';
	}

	if (host[0] == '\0') {
		return 0;
	}

	return 1;
}

static void normalize_host(char *host) {
	char *port_separator;
	size_t len;

	if (host == NULL) {
		return;
	}

	len = strlen(host);
	while (len > 0 && isspace((unsigned char)host[len - 1])) {
		host[--len] = '\0';
	}

	port_separator = strchr(host, ':');
	if (port_separator != NULL) {
		*port_separator = '\0';
	}
}

static int should_block_http_host(const unsigned char *packet, int packet_len,
				  const char *block_host) {
	const struct iphdr *ip_header;
	const struct tcphdr *tcp_header;
	const unsigned char *tcp_payload;
	int ip_header_len;
	int tcp_header_len;
	int tcp_payload_len;
	char host[256];

	if (packet == NULL || packet_len < (int)sizeof(struct iphdr)) {
		return 0;
	}

	ip_header = (const struct iphdr *)packet;
	if (ip_header->version != 4 || ip_header->protocol != IPPROTO_TCP) {
		return 0;
	}

	ip_header_len = ip_header->ihl * 4;
	if (ip_header_len < (int)sizeof(struct iphdr) || packet_len < ip_header_len) {
		return 0;
	}

	tcp_header = (const struct tcphdr *)(packet + ip_header_len);
	if (packet_len < ip_header_len + (int)sizeof(struct tcphdr)) {
		return 0;
	}

	tcp_header_len = tcp_header->doff * 4;
	if (tcp_header_len < (int)sizeof(struct tcphdr) ||
	    packet_len < ip_header_len + tcp_header_len) {
		return 0;
	}

	if (ntohs(tcp_header->dest) != 80) {
		return 0;
	}

	tcp_payload = packet + ip_header_len + tcp_header_len;
	tcp_payload_len = packet_len - ip_header_len - tcp_header_len;
	if (tcp_payload_len <= 0 || !is_http_method(tcp_payload, tcp_payload_len)) {
		return 0;
	}

	if (!extract_host_header(tcp_payload, tcp_payload_len, host, sizeof(host))) {
		return 0;
	}

	normalize_host(host);
	return strcasecmp(host, block_host) == 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *user_data) {
	app_config *config = (app_config *)user_data;
	unsigned char *packet = NULL;
	uint32_t packet_id = get_packet_id(nfa);
	int payload_len = nfq_get_payload(nfa, &packet);
	uint32_t verdict = NF_ACCEPT;

	(void)nfmsg;

	if (payload_len >= 0 &&
	    should_block_http_host(packet, payload_len, config->block_host)) {
		verdict = NF_DROP;
		printf("[DROP] blocked host: %s (packet id=%u)\n",
		       config->block_host, packet_id);
	};

	return nfq_set_verdict(qh, packet_id, verdict, 0, NULL);
}

static void print_usage(const char *program_name) {
	fprintf(stderr, "syntax : %s <host> [queue-num]\n", program_name);
	fprintf(stderr, "sample : %s test.gilgil.net\n", program_name);
	fprintf(stderr, "default host is %s when <host> is omitted\n", DEFAULT_BLOCK_HOST);
}

int main(int argc, char **argv) {
	struct nfq_handle *handle;
	struct nfq_q_handle *queue_handle;
	int fd;
	int received_len;
	char buffer[4096] __attribute__((aligned));
	app_config config = {
		.block_host = DEFAULT_BLOCK_HOST,
		.queue_num = DEFAULT_QUEUE_NUM
	};

	if (argc >= 2) {
		config.block_host = argv[1];
	}

	if (argc >= 3) {
		char *endptr = NULL;
		long parsed_queue = strtol(argv[2], &endptr, 10);

		if (*argv[2] == '\0' || endptr == NULL || *endptr != '\0' ||
		    parsed_queue < 0 || parsed_queue > 65535) {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}

		config.queue_num = (uint16_t)parsed_queue;
	}

	if (argc > 3) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	printf("target host: %s\n", config.block_host);
	printf("queue num  : %u\n", config.queue_num);

	handle = nfq_open();
	if (handle == NULL) {
		fprintf(stderr, "error during nfq_open()\n");
		return EXIT_FAILURE;
	}

	if (nfq_unbind_pf(handle, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	if (nfq_bind_pf(handle, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	queue_handle = nfq_create_queue(handle, config.queue_num, &cb, &config);
	if (queue_handle == NULL) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		nfq_destroy_queue(queue_handle);
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	printf("waiting for packets...\n");
	fd = nfq_fd(handle);

	for (;;) {
		received_len = recv(fd, buffer, sizeof(buffer), 0);
		if (received_len >= 0) {
			nfq_handle_packet(handle, buffer, received_len);
			continue;
		}

		if (errno == ENOBUFS) {
			fprintf(stderr, "losing packets!\n");
			continue;
		}

		perror("recv failed");
		break;
	}

	nfq_destroy_queue(queue_handle);
	nfq_close(handle);
	return EXIT_SUCCESS;
}
