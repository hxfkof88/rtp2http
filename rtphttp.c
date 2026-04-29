/*
 * rtphttp_v2.c — IPTV 组播转 HTTP 代理（4K 终极优化版）
 * * 关键修改：
 * 1. 环形缓冲提升至 128MB。
 * 2. 移除所有可能导致阻塞的 TCP 选项。
 * 3. 增强 UDP 批量接收能力（一次处理 256 包）。
 * 4. 优化了发送端的背压反馈。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <netinet/tcp.h>

#define HTTP_PORT           1997
#define MAX_EVENTS          128
#define RING_BUF_SIZE       (128 * 1024 * 1024) // 128MB 缓冲区
#define SEND_CHUNK_SIZE     (1024 * 1024)       // 每次发送量增加到 1MB
#define TCP_SNDBUF_SIZE     (8  * 1024 * 1024)  // TCP 发送内核缓冲
#define UDP_RCVBUF_SIZE     (16 * 1024 * 1024)  // UDP 接收内核缓冲
#define TS_PACKET_SIZE      188
#define REORDER_SLOTS       64                  // 增加重排窗口
#define REORDER_MASK        (REORDER_SLOTS - 1)

typedef struct {
    uint8_t  data[2048]; // 足够容纳一个 RTP 包
    size_t   len;
    uint16_t seq;
    int      valid;
} ReorderSlot;

typedef struct {
    ReorderSlot slots[REORDER_SLOTS];
    uint16_t    next_seq;
    int         initialized;
} ReorderBuf;

typedef struct {
    int              mcast_fd;
    int              client_fd;
    int              epoll_fd;
    struct ip_mreqn  mreq;
    uint8_t         *ring_buf;
    size_t           head;
    size_t           tail;
    pthread_mutex_t  lock;
    pthread_cond_t   cond;
    volatile atomic_int running;
    int              iframe_found;
    size_t           bytes_buffered;
    ReorderBuf       reorder;
    int              is_rtp;
} Channel;

Channel *slots[65536];

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int ts_has_pusi(const uint8_t *payload, size_t len) {
    if (len < TS_PACKET_SIZE) return 0;
    for (size_t off = 0; off + TS_PACKET_SIZE <= len; off += TS_PACKET_SIZE) {
        if (payload[off] == 0x47 && (payload[off + 1] & 0x40)) return 1;
    }
    return 0;
}

static void ring_write(Channel *ch, const uint8_t *data, size_t len) {
    len = (len / TS_PACKET_SIZE) * TS_PACKET_SIZE;
    if (len == 0) return;

    size_t free_space = (ch->tail > ch->head)
        ? (ch->tail - ch->head - 1)
        : (RING_BUF_SIZE - ch->head + ch->tail - 1);

    if (len > free_space) return; // 缓冲区满，丢弃

    if (ch->head + len <= RING_BUF_SIZE) {
        memcpy(ch->ring_buf + ch->head, data, len);
    } else {
        size_t first = RING_BUF_SIZE - ch->head;
        memcpy(ch->ring_buf + ch->head, data, first);
        memcpy(ch->ring_buf, data + first, len - first);
    }
    ch->head = (ch->head + len) % RING_BUF_SIZE;
}

static void reorder_insert(ReorderBuf *rb, uint16_t seq, const uint8_t *payload, size_t len) {
    int slot = seq & REORDER_MASK;
    memcpy(rb->slots[slot].data, payload, len);
    rb->slots[slot].len = len;
    rb->slots[slot].seq = seq;
    rb->slots[slot].valid = 1;
}

static void reorder_flush(ReorderBuf *rb, Channel *ch) {
    while (1) {
        int slot = rb->next_seq & REORDER_MASK;
        if (!rb->slots[slot].valid || rb->slots[slot].seq != rb->next_seq) break;
        ring_write(ch, rb->slots[slot].data, rb->slots[slot].len);
        rb->slots[slot].valid = 0;
        rb->next_seq++;
    }
}

static void process_packet(Channel *ch, const uint8_t *pkt, ssize_t n) {
    const uint8_t *payload = pkt;
    size_t payload_len = (size_t)n;
    uint16_t rtp_seq = 0;
    int has_seq = 0;

    if (n >= 188 && pkt[0] == 0x47) {
        ch->is_rtp = 0;
    } else if (n > 12 && (pkt[0] & 0xC0) == 0x80) {
        ch->is_rtp = 1;
        rtp_seq = ((uint16_t)pkt[2] << 8) | pkt[3];
        has_seq = 1;
        int cc = pkt[0] & 0x0F;
        size_t offset = 12 + cc * 4;
        if ((pkt[0] & 0x10) && (size_t)n >= offset + 4) {
            offset += 4 + ((((int)pkt[offset + 2] << 8) | pkt[offset + 3]) * 4);
        }
        if (offset < (size_t)n && pkt[offset] == 0x47) {
            payload = pkt + offset;
            payload_len = (size_t)n - offset;
        }
    }

    pthread_mutex_lock(&ch->lock);
    if (ch->is_rtp && has_seq) {
        if (!ch->reorder.initialized) { ch->reorder.next_seq = rtp_seq; ch->reorder.initialized = 1; }
        reorder_insert(&ch->reorder, rtp_seq, payload, payload_len);
        reorder_flush(&ch->reorder, ch);
    } else {
        ring_write(ch, payload, payload_len);
    }

    if (!ch->iframe_found && ts_has_pusi(payload, payload_len)) ch->iframe_found = 1;
    
    pthread_cond_signal(&ch->cond);
    pthread_mutex_unlock(&ch->lock);
}

void *tcp_sender(void *arg) {
    Channel *ch = (Channel *)arg;
    
    pthread_mutex_lock(&ch->lock);
    while (atomic_load(&ch->running) && !ch->iframe_found) pthread_cond_wait(&ch->cond, &ch->lock);
    pthread_mutex_unlock(&ch->lock);

    while (atomic_load(&ch->running)) {
        pthread_mutex_lock(&ch->lock);
        size_t data_len = 0;
        while (atomic_load(&ch->running)) {
            data_len = (ch->head >= ch->tail) ? (ch->head - ch->tail) : (RING_BUF_SIZE - ch->tail + ch->head);
            if (data_len > 0) break;
            pthread_cond_wait(&ch->cond, &ch->lock);
        }
        if (!atomic_load(&ch->running)) { pthread_mutex_unlock(&ch->lock); break; }

        size_t to_send = (data_len > SEND_CHUNK_SIZE) ? SEND_CHUNK_SIZE : data_len;
        struct iovec iov[2];
        int iov_cnt;
        if (ch->tail + to_send <= RING_BUF_SIZE) {
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len = to_send;
            iov_cnt = 1;
        } else {
            size_t first = RING_BUF_SIZE - ch->tail;
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len = first;
            iov[1].iov_base = ch->ring_buf;
            iov[1].iov_len = to_send - first;
            iov_cnt = 2;
        }
        pthread_mutex_unlock(&ch->lock);

        ssize_t sent = writev(ch->client_fd, iov, iov_cnt);
        if (sent > 0) {
            pthread_mutex_lock(&ch->lock);
            ch->tail = (ch->tail + sent) % RING_BUF_SIZE;
            pthread_mutex_unlock(&ch->lock);
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            atomic_store(&ch->running, 0);
        }
    }
    
    epoll_ctl(ch->epoll_fd, EPOLL_CTL_DEL, ch->mcast_fd, NULL);
    slots[ch->mcast_fd] = NULL;
    setsockopt(ch->mcast_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &ch->mreq, sizeof(ch->mreq));
    close(ch->mcast_fd); close(ch->client_fd); free(ch->ring_buf);
    pthread_mutex_destroy(&ch->lock); pthread_cond_destroy(&ch->cond); free(ch);
    return NULL;
}

static int create_mcast_socket(const char *ip, int port, struct ip_mreqn *mreq_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));

    const char *iface = getenv("MCAST_IFACE") ? : "eth0";
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));

    struct ip_mreqn mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr(ip);
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = if_nametoindex(iface);
    setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    *mreq_out = mreq;

    int rcvbuf = UDP_RCVBUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_nonblocking(fd);
    return fd;
}

int main(void) {
    int epoll_fd = epoll_create1(0);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in srv = {.sin_family = AF_INET, .sin_port = htons(HTTP_PORT), .sin_addr.s_addr = INADDR_ANY};
    bind(server_fd, (struct sockaddr *)&srv, sizeof(srv));
    listen(server_fd, 64);

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = server_fd}, events[MAX_EVENTS];
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    printf("🚀 4K 极限优化代理 | 缓冲区: %dMB\n", RING_BUF_SIZE / 1024 / 1024);

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == server_fd) {
                int cli_fd = accept(server_fd, NULL, NULL);
                char req[1024]; recv(cli_fd, req, sizeof(req), 0);
                char target_ip[64]; int target_port;
                if (sscanf(req, "GET /rtp/%63[^:]:%d", target_ip, &target_port) == 2) {
                    send(cli_fd, "HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nConnection: close\r\n\r\n", 64, 0);
                    int sndbuf = TCP_SNDBUF_SIZE;
                    setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                    int nodelay = 1;
                    setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
                    set_nonblocking(cli_fd); // 设为非阻塞

                    Channel *ch = calloc(1, sizeof(Channel));
                    ch->mcast_fd = create_mcast_socket(target_ip, target_port, &ch->mreq);
                    ch->client_fd = cli_fd; ch->epoll_fd = epoll_fd;
                    ch->ring_buf = malloc(RING_BUF_SIZE);
                    atomic_store(&ch->running, 1);
                    pthread_mutex_init(&ch->lock, NULL); pthread_cond_init(&ch->cond, NULL);
                    slots[ch->mcast_fd] = ch;
                    pthread_t tid; pthread_create(&tid, NULL, tcp_sender, ch); pthread_detach(tid);
                    ev.events = EPOLLIN; ev.data.fd = ch->mcast_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ch->mcast_fd, &ev);
                } else close(cli_fd);
            } else if (slots[fd]) {
                Channel *ch = slots[fd];
                uint8_t pkt[2048];
                int count = 0;
                while (count++ < 256) { // 批量处理 256 包
                    ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
                    if (n <= 0) break;
                    process_packet(ch, pkt, n);
                }
            }
        }
    }
    return 0;
}