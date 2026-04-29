/*
 * rtp2httpd_single.c — 高性能组播转 HTTP 代理（单文件重构版）
 *
 * 基于 stackia/rtp2httpd 架构设计，保留原项目的：
 *   - 频道/客户端分离架构 (stream/connection)
 *   - epoll 事件驱动模型
 *   - 缓冲池 (buffer pool) 设计
 *   - RTP 乱序恢复 (rtp_reorder)
 *   - IGMP 精确加组
 *
 * 编译：gcc -O2 -o rtp2httpd rtp2httpd_single.c -lpthread
 * 运行：./rtp2httpd -p 7099
 *
 * 请求格式：GET /rtp/组播IP:端口 HTTP/1.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>

/* ========================================================================
 * 配置常量（可按需调整）
 * ======================================================================== */
#define DEFAULT_PORT                 7099
#define MAX_EVENTS                   1024
#define BUFFER_SIZE                  (7 * 188)          // 7个TS包 ≈ 1316字节
#define BUFFER_POOL_SIZE             4096               // 缓冲区池大小
#define RING_BUFFER_SIZE_KB          65536              // 64MB 环形缓冲区
#define SEND_CHUNK_SIZE              (1024 * 1024)      // 1MB 发送块
#define TCP_SNDBUF_SIZE              (8 * 1024 * 1024)  // 8MB TCP 发送缓冲
#define UDP_RCVBUF_SIZE              (32 * 1024 * 1024) // 32MB UDP 接收缓冲
#define REORDER_SLOTS                128                // 重排窗口大小
#define REORDER_MAX_PACKETS_BEHIND   32
#define REORDER_TIMEOUT_MS           500
#define MCAST_TIMEOUT_SEC            30

/* ========================================================================
 * 数据结构定义
 * ======================================================================== */

/* 缓冲池条目 */
typedef struct buffer_ref {
    uint8_t  data[BUFFER_SIZE];
    size_t   data_size;
    size_t   data_offset;
    int      refcount;
    struct buffer_ref *next;
} buffer_ref_t;

/* 缓冲池 */
typedef struct {
    buffer_ref_t *pool;
    buffer_ref_t *free_list;
    int           total;
    int           free_count;
    pthread_mutex_t lock;
} buffer_pool_t;

/* RTP 重排序槽位 */
typedef struct {
    buffer_ref_t *buf;
    uint16_t      seq;
    int           valid;
} reorder_slot_t;

/* RTP 重排序缓冲区 */
typedef struct {
    reorder_slot_t slots[REORDER_SLOTS];
    uint16_t       base_seq;
    uint16_t       next_expected;
    int            initialized;
    int            stable;
    size_t         delivered;
    size_t         skipped;
    struct timespec last_flush;
} reorder_buffer_t;

/* 环形缓冲区（单一生产者/多消费者） */
typedef struct {
    uint8_t *buffer;
    size_t   capacity;
    volatile size_t head;
    volatile size_t tail;
} ring_buffer_t;

/* 前向声明 */
typedef struct stream_source stream_source_t;
typedef struct client_conn client_conn_t;

/* 频道源（数据生产者） */
struct stream_source {
    char             mcast_ip[64];
    int              mcast_port;
    int              mcast_sock;
    int              refcount;
    int              cleanup;
    ring_buffer_t    ring;
    reorder_buffer_t reorder;
    client_conn_t   *clients;
    int              client_count;
    pthread_mutex_t  lock;
    pthread_cond_t   cond;
    stream_source_t *hash_next;
};

/* 客户端连接（数据消费者） */
struct client_conn {
    int              fd;
    int              epfd;
    int              active;
    int              headers_sent;
    int              iframe_found;
    stream_source_t *source;
    client_conn_t   *next_conn;
};

/* 频道哈希表 */
#define CHANNEL_HASH_SIZE 256
static stream_source_t *channel_table[CHANNEL_HASH_SIZE];
static pthread_mutex_t channel_lock = PTHREAD_MUTEX_INITIALIZER;

/* 全局缓冲池 */
static buffer_pool_t g_pool;

/* ========================================================================
 * 工具函数
 * ======================================================================== */
static int64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ========================================================================
 * 缓冲池管理
 * ======================================================================== */
static int buffer_pool_init(buffer_pool_t *bp, int count) {
    bp->pool = calloc(count, sizeof(buffer_ref_t));
    if (!bp->pool) return -1;
    bp->total = count;
    bp->free_count = count;
    pthread_mutex_init(&bp->lock, NULL);
    bp->free_list = NULL;
    for (int i = 0; i < count; i++) {
        bp->pool[i].next = bp->free_list;
        bp->free_list = &bp->pool[i];
    }
    return 0;
}

static buffer_ref_t *buffer_pool_alloc(buffer_pool_t *bp) {
    pthread_mutex_lock(&bp->lock);
    if (!bp->free_list) {
        pthread_mutex_unlock(&bp->lock);
        return NULL;
    }
    buffer_ref_t *buf = bp->free_list;
    bp->free_list = buf->next;
    bp->free_count--;
    pthread_mutex_unlock(&bp->lock);
    buf->refcount = 1;
    buf->data_size = 0;
    buf->data_offset = 0;
    buf->next = NULL;
    return buf;
}

static void buffer_ref_put(buffer_pool_t *bp, buffer_ref_t *buf) {
    if (!buf) return;
    pthread_mutex_lock(&bp->lock);
    buf->next = bp->free_list;
    bp->free_list = buf;
    bp->free_count++;
    pthread_mutex_unlock(&bp->lock);
}

/* ========================================================================
 * 环形缓冲区（无锁单一生产者/多消费者）
 * ======================================================================== */
static int ring_buffer_init_capacity(ring_buffer_t *rb, size_t capacity) {
    rb->buffer = malloc(capacity);
    if (!rb->buffer) return -1;
    rb->capacity = capacity;
    rb->head = 0;
    rb->tail = 0;
    return 0;
}

static void ring_buffer_write(ring_buffer_t *rb, const uint8_t *data, size_t len) {
    if (len == 0) return;
    size_t h = __atomic_load_n(&rb->head, __ATOMIC_ACQUIRE);
    size_t t = __atomic_load_n(&rb->tail, __ATOMIC_RELAXED);
    size_t free_space = (t > h) ? (t - h - 1) : (rb->capacity - h + t - 1);
    if (len > free_space) return;
    size_t first = rb->capacity - h;
    if (len <= first) {
        memcpy(rb->buffer + h, data, len);
    } else {
        memcpy(rb->buffer + h, data, first);
        memcpy(rb->buffer, data + first, len - first);
    }
    __atomic_store_n(&rb->head, (h + len) % rb->capacity, __ATOMIC_RELEASE);
}

static size_t ring_buffer_readable(ring_buffer_t *rb, const uint8_t **p1, size_t *l1,
                                   const uint8_t **p2, size_t *l2) {
    size_t h = __atomic_load_n(&rb->head, __ATOMIC_ACQUIRE);
    size_t t = __atomic_load_n(&rb->tail, __ATOMIC_RELAXED);
    if (h == t) { *l1 = 0; *l2 = 0; return 0; }
    if (h > t) {
        *p1 = rb->buffer + t; *l1 = h - t; *p2 = NULL; *l2 = 0;
        return h - t;
    } else {
        *p1 = rb->buffer + t; *l1 = rb->capacity - t;
        *p2 = rb->buffer; *l2 = h;
        return rb->capacity - t + h;
    }
}

static void ring_buffer_consume(ring_buffer_t *rb, size_t len) {
    size_t t = __atomic_load_n(&rb->tail, __ATOMIC_RELAXED);
    __atomic_store_n(&rb->tail, (t + len) % rb->capacity, __ATOMIC_RELEASE);
}

/* ========================================================================
 * RTP 解包与检测
 * ======================================================================== */
static int rtp_get_payload(const uint8_t *pkt, size_t n,
                           const uint8_t **payload, size_t *payload_len, uint16_t *seq) {
    /* 纯 TS 流检测 */
    if (n >= 188 && pkt[0] == 0x47) {
        *payload = pkt;
        *payload_len = n;
        return 0; // 非 RTP
    }
    /* RTP 头检测 */
    if (n > 12 && (pkt[0] & 0xC0) == 0x80) {
        *seq = ((uint16_t)pkt[2] << 8) | pkt[3];
        int cc = pkt[0] & 0x0F;
        size_t offset = 12 + cc * 4;
        if ((pkt[0] & 0x10) && n >= offset + 4) {
            offset += 4 + ((((int)pkt[offset + 2] << 8) | pkt[offset + 3]) * 4);
        }
        if (offset < n && pkt[offset] == 0x47) {
            *payload = pkt + offset;
            *payload_len = n - offset;
            return 1; // RTP
        }
    }
    return -1; // 无效包
}

static int ts_has_pusi(const uint8_t *payload, size_t len) {
    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (payload[off] == 0x47 && (payload[off + 1] & 0x40)) return 1;
    }
    return 0;
}

/* ========================================================================
 * RTP 重排序（带丢包跳过）
 * ======================================================================== */
static void reorder_init(reorder_buffer_t *rb) {
    memset(rb, 0, sizeof(*rb));
}

static void reorder_force_flush(reorder_buffer_t *rb, stream_source_t *source) {
    if (!rb->stable) return;
    int flushed = 0;
    while (1) {
        int slot = rb->base_seq % REORDER_SLOTS;
        if (!rb->slots[slot].valid) break;
        buffer_ref_t *buf = rb->slots[slot].buf;
        ring_buffer_write(&source->ring, buf->data + buf->data_offset, buf->data_size);
        buffer_ref_put(&g_pool, buf);
        rb->slots[slot].valid = 0;
        rb->base_seq++;
        flushed++;
    }
    if (flushed > 0) {
        rb->delivered += flushed;
        pthread_cond_broadcast(&source->cond);
    }
}

static void reorder_deliver(reorder_buffer_t *rb, stream_source_t *source) {
    if (!rb->initialized) return;
    int delivered = 0;
    while (1) {
        int slot = rb->base_seq % REORDER_SLOTS;
        if (!rb->slots[slot].valid || rb->slots[slot].seq != rb->base_seq) break;
        buffer_ref_t *buf = rb->slots[slot].buf;
        ring_buffer_write(&source->ring, buf->data + buf->data_offset, buf->data_size);
        buffer_ref_put(&g_pool, buf);
        rb->slots[slot].valid = 0;
        rb->base_seq++;
        delivered++;
    }
    if (delivered > 0) {
        rb->delivered += delivered;
        rb->stable = 1;
        clock_gettime(CLOCK_MONOTONIC, &rb->last_flush);
        pthread_cond_broadcast(&source->cond);
    }
    /* 丢包跳过检查 */
    if (rb->stable) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t elapsed = (now.tv_sec - rb->last_flush.tv_sec) * 1000 +
                          (now.tv_nsec - rb->last_flush.tv_nsec) / 1000000;
        if (elapsed > REORDER_TIMEOUT_MS) {
            int exp_slot = rb->base_seq % REORDER_SLOTS;
            if (!rb->slots[exp_slot].valid || rb->slots[exp_slot].seq != rb->base_seq) {
                rb->base_seq++;
                rb->skipped++;
                reorder_deliver(rb, source);
            }
        }
    }
}

static void reorder_insert(reorder_buffer_t *rb, stream_source_t *source,
                           buffer_ref_t *buf, uint16_t seq) {
    if (!rb->initialized) { rb->base_seq = seq; rb->initialized = 1; }
    if (rb->stable) {
        uint16_t diff = seq - rb->base_seq;
        if (diff > 0x8000) { buffer_ref_put(&g_pool, buf); return; }
        if (diff >= REORDER_SLOTS) {
            reorder_force_flush(rb, source);
            rb->base_seq = seq;
        }
    }
    int slot = seq % REORDER_SLOTS;
    if (rb->slots[slot].valid && rb->slots[slot].seq == seq) {
        buffer_ref_put(&g_pool, buf); return;
    }
    rb->slots[slot].buf = buf;
    rb->slots[slot].seq = seq;
    rb->slots[slot].valid = 1;
    reorder_deliver(rb, source);
}

/* ========================================================================
 * 频道管理
 * ======================================================================== */
static unsigned int channel_hash(const char *ip, int port) {
    unsigned int hash = 5381;
    while (*ip) hash = ((hash << 5) + hash) + *ip++;
    return (hash + port) % CHANNEL_HASH_SIZE;
}

static stream_source_t *channel_find_or_create(const char *ip, int port, int epfd) {
    unsigned int h = channel_hash(ip, port);
    pthread_mutex_lock(&channel_lock);

    /* 查找已有频道 */
    stream_source_t *ch = channel_table[h];
    while (ch) {
        if (strcmp(ch->mcast_ip, ip) == 0 && ch->mcast_port == port && !ch->cleanup) {
            ch->refcount++;
            pthread_mutex_unlock(&channel_lock);
            printf("🔗 复用频道 %s:%d (ref=%d)\n", ip, port, ch->refcount);
            return ch;
        }
        ch = ch->hash_next;
    }

    /* 创建新频道 */
    ch = calloc(1, sizeof(stream_source_t));
    if (!ch) { pthread_mutex_unlock(&channel_lock); return NULL; }

    strncpy(ch->mcast_ip, ip, sizeof(ch->mcast_ip) - 1);
    ch->mcast_port = port;
    ch->refcount = 1;
    pthread_mutex_init(&ch->lock, NULL);
    pthread_cond_init(&ch->cond, NULL);
    ring_buffer_init_capacity(&ch->ring, RING_BUFFER_SIZE_KB * 1024);
    reorder_init(&ch->reorder);

    /* 创建组播 socket */
    ch->mcast_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ch->mcast_sock < 0) {
        perror("mcast socket"); free(ch); pthread_mutex_unlock(&channel_lock); return NULL;
    }

    int opt = 1;
    setsockopt(ch->mcast_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(ch->mcast_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port),
                               .sin_addr.s_addr = inet_addr(ip)};
    if (bind(ch->mcast_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("mcast bind"); close(ch->mcast_sock); free(ch);
        pthread_mutex_unlock(&channel_lock); return NULL;
    }

    const char *iface = getenv("MCAST_IFACE") ? getenv("MCAST_IFACE") : "eth0";
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(ch->mcast_sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));

    struct ip_mreqn mreq = {.imr_multiaddr.s_addr = inet_addr(ip),
                            .imr_address.s_addr = htonl(INADDR_ANY),
                            .imr_ifindex = if_nametoindex(iface)};
    setsockopt(ch->mcast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    int rcvbuf = UDP_RCVBUF_SIZE;
    setsockopt(ch->mcast_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_nonblocking(ch->mcast_sock);

    /* 添加到 epoll */
    struct epoll_event ev = {.events = EPOLLIN, .data.ptr = NULL};
    ev.data.fd = ch->mcast_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, ch->mcast_sock, &ev);

    /* 插入哈希表 */
    ch->hash_next = channel_table[h];
    channel_table[h] = ch;
    pthread_mutex_unlock(&channel_lock);

    printf("📡 新频道 %s:%d 创建成功 (fd=%d)\n", ip, port, ch->mcast_sock);
    return ch;
}

static void channel_unref(stream_source_t *source, int epfd) {
    pthread_mutex_lock(&channel_lock);
    source->refcount--;
    if (source->refcount <= 0) {
        source->cleanup = 1;
        /* 从哈希表移除 */
        unsigned int h = channel_hash(source->mcast_ip, source->mcast_port);
        stream_source_t **pp = &channel_table[h];
        while (*pp) {
            if (*pp == source) { *pp = source->hash_next; break; }
            pp = &(*pp)->hash_next;
        }
        /* 关闭组播 socket */
        epoll_ctl(epfd, EPOLL_CTL_DEL, source->mcast_sock, NULL);
        close(source->mcast_sock);
        free(source->ring.buffer);
        pthread_mutex_destroy(&source->lock);
        pthread_cond_destroy(&source->cond);
        printf("🧹 频道 %s:%d 已销毁\n", source->mcast_ip, source->mcast_port);
        free(source);
    }
    pthread_mutex_unlock(&channel_lock);
}

/* ========================================================================
 * 客户端管理
 * ======================================================================== */
static client_conn_t *client_create(stream_source_t *source, int fd, int epfd) {
    client_conn_t *c = calloc(1, sizeof(client_conn_t));
    if (!c) return NULL;
    c->fd = fd;
    c->epfd = epfd;
    c->active = 1;
    c->source = source;

    pthread_mutex_lock(&source->lock);
    c->next_conn = source->clients;
    source->clients = c;
    source->client_count++;
    pthread_mutex_unlock(&source->lock);
    return c;
}

static void client_remove(client_conn_t *c) {
    if (!c) return;
    stream_source_t *source = c->source;
    if (source) {
        pthread_mutex_lock(&source->lock);
        client_conn_t **pp = &source->clients;
        while (*pp) {
            if (*pp == c) { *pp = c->next_conn; source->client_count--; break; }
            pp = &(*pp)->next_conn;
        }
        pthread_mutex_unlock(&source->lock);
    }
    if (c->fd >= 0) { epoll_ctl(c->epfd, EPOLL_CTL_DEL, c->fd, NULL); shutdown(c->fd, SHUT_RDWR); close(c->fd); }
    free(c);
}

/* ========================================================================
 * TCP 发送线程（每客户端一个）
 * ======================================================================== */
static void *tcp_sender_thread(void *arg) {
    client_conn_t *c = (client_conn_t *)arg;
    stream_source_t *source = c->source;
    char header[256];

    /* 发送 HTTP 响应头 */
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nConnection: close\r\n\r\n");
    send(c->fd, header, hlen, MSG_NOSIGNAL);
    c->headers_sent = 1;

    /* 等待 I 帧 */
    while (!c->iframe_found && c->active) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000};
        nanosleep(&ts, NULL);
    }

    while (c->active) {
        const uint8_t *p1, *p2; size_t l1, l2;
        size_t avail = ring_buffer_readable(&source->ring, &p1, &l1, &p2, &l2);
        if (avail == 0) { usleep(2000); continue; }

        size_t to_send = avail > SEND_CHUNK_SIZE ? SEND_CHUNK_SIZE : avail;
        struct iovec iov[2]; int iovcnt = 0;
        if (to_send <= l1) { iov[0].iov_base = (void *)p1; iov[0].iov_len = to_send; iovcnt = 1; }
        else { iov[0].iov_base = (void *)p1; iov[0].iov_len = l1;
               iov[1].iov_base = (void *)p2; iov[1].iov_len = to_send - l1; iovcnt = 2; }

        ssize_t sent = writev(c->fd, iov, iovcnt);
        if (sent > 0) ring_buffer_consume(&source->ring, (size_t)sent);
        else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { usleep(1000); continue; }
        else break;
    }

    c->active = 0;
    client_remove(c);
    channel_unref(source, c->epfd);
    return NULL;
}

/* ========================================================================
 * 主事件循环
 * ======================================================================== */
int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc >= 3 && strcmp(argv[1], "-p") == 0) port = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN);
    buffer_pool_init(&g_pool, BUFFER_POOL_SIZE);

    int epfd = epoll_create1(0);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in srv = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
    bind(server_fd, (struct sockaddr *)&srv, sizeof(srv));
    listen(server_fd, SOMAXCONN);
    set_nonblocking(server_fd);

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = server_fd};
    epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &ev);

    struct epoll_event events[MAX_EVENTS];

    printf("🚀 rtp2httpd 启动 (端口: %d, 缓冲池: %d x %dB, 重排窗口: %d)\n",
           port, BUFFER_POOL_SIZE, BUFFER_SIZE, REORDER_SLOTS);

    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, 100);
        if (n < 0) { if (errno == EINTR) continue; break; }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            /* 新连接 */
            if (fd == server_fd) {
                int cli_fd = accept(server_fd, NULL, NULL);
                if (cli_fd < 0) continue;
                set_nonblocking(cli_fd);
                int nodelay = 1, sndbuf = TCP_SNDBUF_SIZE;
                setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
                setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

                char req[2048] = {0};
                recv(cli_fd, req, sizeof(req) - 1, 0);
                char ip[64]; int mport;
                if (sscanf(req, "GET /rtp/%63[^:]:%d", ip, &mport) != 2) {
                    close(cli_fd); continue;
                }

                stream_source_t *src = channel_find_or_create(ip, mport, epfd);
                if (!src) { close(cli_fd); continue; }

                client_conn_t *cli = client_create(src, cli_fd, epfd);
                if (!cli) { channel_unref(src, epfd); close(cli_fd); continue; }

                pthread_t tid;
                pthread_create(&tid, NULL, tcp_sender_thread, cli);
                pthread_detach(tid);
            }
            /* 组播数据接收 */
            else {
                /* 查找 fd 对应的频道 */
                stream_source_t *src = NULL;
                for (int j = 0; j < CHANNEL_HASH_SIZE; j++) {
                    stream_source_t *ch = channel_table[j];
                    while (ch) {
                        if (ch->mcast_sock == fd) { src = ch; break; }
                        ch = ch->hash_next;
                    }
                    if (src) break;
                }
                if (!src) continue;

                /* 批量读取 */
                for (int k = 0; k < 256; k++) {
                    buffer_ref_t *buf = buffer_pool_alloc(&g_pool);
                    if (!buf) break;
                    ssize_t nr = recv(fd, buf->data, BUFFER_SIZE, 0);
                    if (nr <= 0) { buffer_ref_put(&g_pool, buf); break; }
                    buf->data_size = nr;

                    pthread_mutex_lock(&src->lock);
                    const uint8_t *payload; size_t plen; uint16_t seq;
                    int type = rtp_get_payload(buf->data, nr, &payload, &plen, &seq);
                    if (type == 1) {
                        buf->data_offset = payload - buf->data;
                        buf->data_size = plen;
                        reorder_insert(&src->reorder, src, buf, seq);
                    } else if (type == 0) {
                        ring_buffer_write(&src->ring, payload, plen);
                        buffer_ref_put(&g_pool, buf);
                        pthread_cond_broadcast(&src->cond);
                    } else { buffer_ref_put(&g_pool, buf); }

                    /* I 帧检测 */
                    if (ts_has_pusi(payload, plen)) {
                        client_conn_t *cl = src->clients;
                        while (cl) { cl->iframe_found = 1; cl = cl->next_conn; }
                    }
                    pthread_mutex_unlock(&src->lock);
                }
            }
        }
    }

    close(server_fd);
    close(epfd);
    return 0;
}