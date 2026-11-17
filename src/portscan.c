/*
 * portscan.c - Concurrent TCP connect() port scanner.
 *
 * Opens up to N non-blocking connections at once and waits for them with
 * poll(). A port is reported as:
 *   open      the TCP handshake succeeded
 *   closed    the host answered with RST (connection refused)
 *   filtered  no answer before the timeout (likely dropped by a firewall)
 *
 * Only scan hosts you own or are authorised to test.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_PORTS 65536

enum port_state { ST_UNKNOWN = 0, ST_OPEN, ST_CLOSED, ST_FILTERED };

static const char *state_name[] = { "unknown", "open", "closed", "filtered" };

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-p ports] [-t timeout_ms] [-c concurrency] [-a] <host>\n"
            "  -p  ports to scan, e.g. 22,80,443 or 1-1024 (default: 1-1024)\n"
            "  -t  connection timeout in milliseconds (default: 1000)\n"
            "  -c  simultaneous connections (default: 200)\n"
            "  -a  also list closed and filtered ports\n",
            prog);
}

static long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int parse_number(const char *s, const char *end, long *out)
{
    long v = 0;

    if (s == end)
        return -1;
    for (; s < end; s++) {
        if (*s < '0' || *s > '9')
            return -1;
        v = v * 10 + (*s - '0');
        if (v > 65535)
            return -1;
    }
    *out = v;
    return 0;
}

/* Parses "22,80,8000-8100" into a sorted list of unique ports. */
static int parse_ports(const char *spec, uint16_t *ports, size_t *count)
{
    static unsigned char wanted[MAX_PORTS];
    const char *p = spec;

    memset(wanted, 0, sizeof wanted);
    while (*p != '\0') {
        const char *end = strchr(p, ',');
        const char *dash;
        long lo, hi;

        if (end == NULL)
            end = p + strlen(p);
        dash = memchr(p, '-', (size_t)(end - p));
        if (dash != NULL) {
            if (parse_number(p, dash, &lo) < 0 || parse_number(dash + 1, end, &hi) < 0)
                return -1;
        } else {
            if (parse_number(p, end, &lo) < 0)
                return -1;
            hi = lo;
        }
        if (lo < 1 || hi < lo)
            return -1;
        for (long port = lo; port <= hi; port++)
            wanted[port] = 1;
        p = (*end == ',') ? end + 1 : end;
    }

    *count = 0;
    for (long port = 1; port < MAX_PORTS; port++)
        if (wanted[port])
            ports[(*count)++] = (uint16_t)port;
    return *count > 0 ? 0 : -1;
}

/* Starts a non-blocking connect(). Returns the socket, or -1 if the state is already known. */
static int start_connect(const struct sockaddr_in *target, uint16_t port, enum port_state *state)
{
    struct sockaddr_in addr = *target;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        *state = ST_FILTERED;
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    addr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) {
        *state = ST_OPEN;
    } else if (errno == EINPROGRESS) {
        return fd;
    } else {
        *state = (errno == ECONNREFUSED) ? ST_CLOSED : ST_FILTERED;
    }
    close(fd);
    return -1;
}

/* Scans ports[first .. first+n-1] in parallel. */
static void scan_batch(const struct sockaddr_in *target, const uint16_t *ports, size_t n,
                       enum port_state *states, int timeout_ms)
{
    struct pollfd *pfds = calloc(n, sizeof *pfds);
    size_t pending = 0;
    long deadline;

    if (pfds == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < n; i++) {
        pfds[i].fd = start_connect(target, ports[i], &states[i]);
        pfds[i].events = POLLOUT;
        if (pfds[i].fd >= 0)
            pending++;
    }

    deadline = now_ms() + timeout_ms;
    while (pending > 0) {
        long remaining = deadline - now_ms();
        int ready;

        if (remaining <= 0)
            break;
        ready = poll(pfds, (nfds_t)n, (int)remaining);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        for (size_t i = 0; i < n && ready > 0; i++) {
            int err = 0;
            socklen_t len = sizeof err;

            if (pfds[i].fd < 0 || pfds[i].revents == 0)
                continue;
            ready--;
            getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0)
                states[i] = ST_OPEN;
            else
                states[i] = (err == ECONNREFUSED) ? ST_CLOSED : ST_FILTERED;
            close(pfds[i].fd);
            pfds[i].fd = -1; /* poll() ignores negative descriptors */
            pending--;
        }
    }

    for (size_t i = 0; i < n; i++) {
        if (pfds[i].fd >= 0) {
            states[i] = ST_FILTERED;
            close(pfds[i].fd);
        }
    }
    free(pfds);
}

static const char *service_name(uint16_t port)
{
    struct servent *se = getservbyport(htons(port), "tcp");

    return se ? se->s_name : "";
}

int main(int argc, char **argv)
{
    static uint16_t ports[MAX_PORTS];
    static enum port_state states[MAX_PORTS];
    const char *spec = "1-1024";
    long timeout_ms = 1000, concurrency = 200;
    int show_all = 0, opt, rc;
    size_t count, counts[4] = { 0 };
    struct addrinfo hints, *res;
    struct sockaddr_in target;
    char ip[INET_ADDRSTRLEN];
    long t0;

    while ((opt = getopt(argc, argv, "p:t:c:ah")) != -1) {
        switch (opt) {
        case 'p': spec = optarg; break;
        case 't': timeout_ms = strtol(optarg, NULL, 10); break;
        case 'c': concurrency = strtol(optarg, NULL, 10); break;
        case 'a': show_all = 1; break;
        case 'h': usage(argv[0]); return EXIT_SUCCESS;
        default:  usage(argv[0]); return EXIT_FAILURE;
        }
    }
    if (optind != argc - 1) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (timeout_ms <= 0 || concurrency <= 0 || concurrency > 1000) {
        fprintf(stderr, "Invalid timeout or concurrency\n");
        return EXIT_FAILURE;
    }
    if (parse_ports(spec, ports, &count) < 0) {
        fprintf(stderr, "Invalid port specification: %s\n", spec);
        return EXIT_FAILURE;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(argv[optind], NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "%s: %s\n", argv[optind], gai_strerror(rc));
        return EXIT_FAILURE;
    }
    memcpy(&target, res->ai_addr, sizeof target);
    freeaddrinfo(res);
    inet_ntop(AF_INET, &target.sin_addr, ip, sizeof ip);

    printf("Scanning %s (%s): %zu port(s), timeout %ld ms\n\n", argv[optind], ip, count, timeout_ms);
    t0 = now_ms();
    for (size_t i = 0; i < count; i += (size_t)concurrency) {
        size_t n = count - i < (size_t)concurrency ? count - i : (size_t)concurrency;

        scan_batch(&target, ports + i, n, states + i, (int)timeout_ms);
    }

    printf("%-8s %-9s %s\n", "PORT", "STATE", "SERVICE");
    for (size_t i = 0; i < count; i++) {
        counts[states[i]]++;
        if (states[i] == ST_OPEN || show_all)
            printf("%-8u %-9s %s\n", (unsigned)ports[i], state_name[states[i]], service_name(ports[i]));
    }
    printf("\nDone in %.2f s: %zu open, %zu closed, %zu filtered\n",
           (double)(now_ms() - t0) / 1000.0, counts[ST_OPEN], counts[ST_CLOSED], counts[ST_FILTERED]);
    return EXIT_SUCCESS;
}
