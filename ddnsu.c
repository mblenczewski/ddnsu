#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DDNS_USER_AGENT "User-Agent: Linux-DUC/2.1.9"
#define DDNS_REALIP_DOMAIN "ip1.dynupdate.no-ip.com"
#define DDNS_REALIP_PORT "8245"
#define DDNS_UPDATE_DOMAIN "dynupdate.no-ip.com"
#define DDNS_UPDATE_SCRIPT "ducupdate.php"
#define DDNS_UPDATE_PORT "8245"

bool try_connect_to_host(int *sockfd, char *restrict hostname, char *restrict port) {
	assert(sockfd);
	
	struct addrinfo hints, *result;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(hostname, port, &hints, &result)) {
		fprintf(stderr, "Failed to get address info: %d\n", errno);
		return false;
	}

	int fd;
	if (!(fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol))) {
		fprintf(stderr, "Failed to create socket: %d\n", errno);
		freeaddrinfo(result);
		return 1;
	}

	if (connect(fd, result->ai_addr, result->ai_addrlen)) {
		fprintf(stderr, "Failed to connect socket to %s:%s: %d\n", hostname, port, errno);
		freeaddrinfo(result);
		close(fd);
		return false;
	}

	*sockfd = fd;

	freeaddrinfo(result);
	return true;
}

bool try_send(int sockfd, const void *buf, size_t len, size_t *total_sent) {
	assert(total_sent);

	size_t total = 0;
	do {
		ssize_t sent;
		if ((sent = write(sockfd, buf + total, len - total)) == 0) {
			*total_sent = total;
			return false;
		}

		total += sent;
	} while (total < len);

	*total_sent = total;
	return true;
}

bool try_recv(int sockfd, void *buf, size_t len, size_t *total_read) {
	assert(total_read);

	size_t total = 0;
	do {
		ssize_t recv;
		if ((recv = read(sockfd, buf + total, len - total)) == 0) {
			*total_read = total;
			return false;
		}

		total += recv;
	} while (total < len);

	*total_read = total;
	return true;
}

bool try_parse_ip_addr(char *buf, size_t len, char **out) {
	assert(buf);
	assert(out);

	char *penultimate_line;
	if ((penultimate_line = strrchr(buf, '\n')) == NULL) {
		return false;
	}

	*out = strdup(++penultimate_line);

	return true;
}

void logmsg(const char *fmt, ...) {
#ifndef NDEBUG
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
#endif
}

char msgbuf[4096];

int main(int argc, char **argv) {
	if (argc < 4) {
		printf("Usage: %s <username> <password> <domain>\n", __FILE__);
		return 1;
	}

	char *user = argv[1], *pass = argv[2], *domain = argv[3];

	int sockfd;

	// get current publicly visible ip using the DDNS_REALIP_DOMAIN
	if (!try_connect_to_host(&sockfd, DDNS_REALIP_DOMAIN, DDNS_REALIP_PORT)) {
		fprintf(stderr, "Could not connect to realip domain: %d\n", errno);
		close(sockfd);
		return 1;
	}

	size_t realip_request_bytes = snprintf(msgbuf, sizeof(msgbuf),
		"GET http://" DDNS_REALIP_DOMAIN " HTTP/1.0\r\n" DDNS_USER_AGENT "\r\n\r\n");

	logmsg("DDNS_REALIP_REQ:\n%s\n", msgbuf);

	size_t written_realip_request_bytes = 0;
	if (!try_send(sockfd, msgbuf, realip_request_bytes, &written_realip_request_bytes)) {
		fprintf(stderr, "Could not send HTTP request to realip domain: %d\n", errno);
		close(sockfd);
		return 1;
	}

	size_t read_realip_response_bytes = 0;
	try_recv(sockfd, msgbuf, sizeof(msgbuf) - 1, &read_realip_response_bytes);
	msgbuf[read_realip_response_bytes] = '\0';

	logmsg("DDNS_REALIP_REP:\n%s\n", msgbuf);

	char *public_ip;
	if (!try_parse_ip_addr(msgbuf, read_realip_response_bytes, &public_ip)) {
		fprintf(stderr, "Could not parse public IP address from realip response: %d\n", errno);
		close(sockfd);
		return 1;
	}

	logmsg("Public IP: %s\n", public_ip);

	close(sockfd);

	// update current DDNS A record
	if (!try_connect_to_host(&sockfd, DDNS_UPDATE_DOMAIN, DDNS_UPDATE_PORT)) {
		fprintf(stderr, "Could not connect to update domain: %d\n", errno);
		close(sockfd);
		return 1;
	}

	size_t ddns_request_bytes = snprintf(msgbuf, sizeof(msgbuf),
		"GET http://" DDNS_UPDATE_DOMAIN "/" DDNS_UPDATE_SCRIPT "?username=%s&pass=%s&h[]=%s&ip=%s HTTP/1.0\r\n" DDNS_USER_AGENT "\r\n\r\n",
		user, pass, domain, public_ip);

	free(public_ip);

	logmsg("DDNS_UPDATE_REQ:\n%s\n", msgbuf);

	size_t written_ddns_request_bytes = 0;
	if (!try_send(sockfd, msgbuf, ddns_request_bytes, &written_ddns_request_bytes)) {
		fprintf(stderr, "Could not sent HTTP request to ddns domain: %d\n", errno);
		close(sockfd);
		return 1;
	}

	size_t read_ddns_response_bytes = 0;
	try_recv(sockfd, msgbuf, sizeof(msgbuf) - 1, &read_ddns_response_bytes);
	msgbuf[read_ddns_response_bytes] = '\0';

	logmsg("DDNS_UPDATE_REP:\n%s\n", msgbuf);

	close(sockfd);

	return 0; 
}
