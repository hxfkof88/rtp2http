/*
 * rtphttp.c — IPTV 组播转 HTTP 代理（高性能重构版）
 * 
 * 编译：gcc -O2 -o rtp2http rtphttp.c -lpthread
 * 运行：MCAST_IFACE=eth0.45 ./rtp2http
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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <pthread.h>

/* ========================================================================
 * 环境配置常量
 * ======================================================================== */
#define HTTP_PORT                    7099
#define MAX_EVENTS                   512
/* 缓冲区配置 - 高码率优化 */
#define RING_BUF_SIZE                (256 * 1024 * 1024) // 256 MB
#define TCP_SNDBUF_SIZE              (8 * 1024 * 1024)   // 8 MB 发送缓冲
#define UDP_RCVBUF_SIZE              (32 * 1024 * 1024)  // 32 MB 接收缓冲
#define CLIENT_READ_CHUNK            (1024 * 1024)       // 1 MB 发送块
#define TS_PACKET_SIZE               188
#define REORDER_SLOTS                128                 // 重排窗口大小

/* RTP 重排序超时处理 */
#define REORDER_DROP_TIMEOUT_MS      500
#define REORDER_FORCE_FLUSH_MS       2000

/* ========================================================================
 * 数据结构定义
 * ======================================================================== */

/* 双向链表通用节点 */
typedef struct client_node {
    int fd;
    volatile int active;
    volatile int headers_sent;
    volatile int iframe_locked;
    volatile int pause_output;
    volatile int close_requested;
    pthread_t thread;
    struct channel *parent;
    struct client_node *next;
    struct client_node *prev;
} client_node_t;

/* 客户端双向链表 */
typedef struct client_list {
    client_node_t *head;
    client_node_t *tail;
    int count;
    pthread_mutex_t lock;
} client_list_t;

/* 高性能无锁环形缓冲区 */
typedef struct {
    uint8_t *buffer;
    size_t   capacity;
    volatile size_t head __attribute__((aligned(64))); // 写指针
    volatile size_t tail __attribute__((aligned(64))); // 读指针
    size_t   write_miss;
    size_t   total_written;
} ring_buffer_t;

/* RTP 重排序槽位 */
typedef struct {
    uint8_t  data[2048];
    size_t   len;
    uint16_t seq;
    int      valid;
} reorder_slot_t;

/* RTP 重排序状态机 */
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

/* 频道对象（共享数据源） */
typedef struct channel {
    char             mcast_ip[64];
    int              mcast_port;
    int              mcast_fd;
    int              refcount;
    int              cleanup;
    struct ip_mreqn  mreq;
    ring_buffer_t    ring;
    reorder_buffer_t reorder;
    client_list_t    clients;
    pthread_mutex_t  lock;
    pthread_cond_t   cond;
} channel_t;

/* 全局频道查找表 */
#define CHANNEL_HASH_SIZE 256
static channel_t *channel_map[CHANNEL_HASH_SIZE];
static pthread_mutex_t channel_map_lock = PTHREAD_MUTEX_INITIALIZER;

/* ========================================================================
 * 工具函数：时间 & 非阻塞设置
 * ======================================================================== */
static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

static int set_tcp_optimized(int fd) {
    int opt;
    /* TCP_NODELAY 禁用 Nagle 算法 */
    opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        perror("TCP_NODELAY");
    }
    /* TCP_QUICKACK 减少延迟 (Linux) */
    opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt)) < 0) {
        // 忽略错误，非必须
    }
    /* 增大 TCP 发送缓冲区 */
    int sndbuf = TCP_SNDBUF_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        perror("SO_SNDBUF");
    }
    set_nonblocking(fd);
    return 0;
}

/* ========================================================================
 * 环形缓冲区：无锁单一生产者/多消费者模型
 * ======================================================================== */
static int ring_buffer_init(ring_buffer_t *rb, size_t capacity) {
    rb->buffer = (uint8_t *)malloc(capacity);
    if (!rb->buffer) return -1;
    rb->capacity = capacity;
    rb->head = 0;
    rb->tail = 0;
    rb->write_miss = 0;
    rb->total_written = 0;
    return 0;
}

static void ring_buffer_destroy(ring_buffer_t *rb) {
    free(rb->buffer);
    rb->buffer = NULL;
}

/* 生产者：写入数据，若空间不足则丢弃整个对齐块 */
static void ring_buffer_write(ring_buffer_t *rb, const uint8_t *data, size_t len) {
    if (len == 0) return;
    /* 计算可用空间 */
    size_t h = __atomic_load_n(&rb->head, __ATOMIC_ACQUIRE);
    size_t t = __atomic_load_n(&rb->tail, __ATOMIC_RELAXED);
    size_t free_space = (t > h) ? (t - h - 1) : (rb->capacity - h + t - 1);
    
    if (len > free_space) {
        __atomic_fetch_add(&rb->write_miss, 1, __ATOMIC_RELAXED);
        return;
    }
    
    size_t first_part = rb->capacity - h;
    if (len <= first_part) {
        memcpy(rb->buffer + h, data, len);
    } else {
        memcpy(rb->buffer + h, data, first_part);
        memcpy(rb->buffer, data + first_part, len - first_part);
    }
    
    __atomic_store_n(&rb->head, (h + len) % rb->capacity, __ATOMIC_RELEASE);
    __atomic_fetch_add(&rb->total_written, len, __ATOMIC_RELAXED);
}

/* 消费者：获取当前可读数据指针与长度（零拷贝） */
static size_t ring_buffer_get_read_ptr(ring_buffer_t *rb, const uint8_t **ptr1, size_t *len1, const uint8_t **ptr2, size_t *len2) {
    size_t h = __atomic_load_n(&rb->head, __ATOMIC_ACQUIRE);
    size_t t = __atomic_load_n(&rb->tail, __ATOMIC_RELAXED);
    
    if (h == t) {
        *len1 = 0;
        *len2 = 0;
        return 0;
    }
    
    size_t avail;
    if (h > t) {
        avail = h - t;
        *ptr1 = rb->buffer + t;
        *len1 = avail;
        *ptr2 = NULL;
        *len2 = 0;
    } else {
        avail = rb->capacity - t + h;
        *ptr1 = rb->buffer + t;
        *len1 = rb->capacity - t;
        *ptr2 = rb->buffer;
        *len2 = h;
    }
    return avail;
}

static void ring_buffer_consume(ring_buffer_t *rb, size_t len) {
    size_t t = __atomic_load_n(&rb->tail, __ATOMIC_RELAXED);
    __atomic_store_n(&rb->tail, (t + len) % rb->capacity, __ATOMIC_RELEASE);
}

/* ========================================================================
 * RTP 重排序：滑动窗口 + 乱序恢复
 * ======================================================================== */
static void reorder_buffer_init(reorder_buffer_t *rb) {
    memset(rb, 0, sizeof(*rb));
}

static int ts_has_pusi(const uint8_t *payload, size_t len) {
    for (size_t off = 0; off + TS_PACKET_SIZE <= len; off += TS_PACKET_SIZE) {
        if (payload[off] == 0x47 && (payload[off + 1] & 0x40)) {
            return 1;
        }
    }
    return 0;
}

static void reorder_force_flush(reorder_buffer_t *rb, channel_t *ch) {
    if (!rb->initialized || !rb->stable) return;
    int flushed = 0;
    while (1) {
        int slot = rb->base_seq % REORDER_SLOTS;
        if (!rb->slots[slot].valid) break;
        ring_buffer_write(&ch->ring, rb->slots[slot].data, rb->slots[slot].len);
        rb->slots[slot].valid = 0;
        rb->base_seq++;
        flushed++;
    }
    if (flushed > 0) {
        rb->delivered += flushed;
        pthread_cond_broadcast(&ch->cond);
    }
}

static void reorder_deliver(reorder_buffer_t *rb, channel_t *ch) {
    if (!rb->initialized) return;
    int delivered = 0;
    while (1) {
        int slot = rb->base_seq % REORDER_SLOTS;
        if (!rb->slots[slot].valid || rb->slots[slot].seq != rb->base_seq) break;
        ring_buffer_write(&ch->ring, rb->slots[slot].data, rb->slots[slot].len);
        rb->slots[slot].valid = 0;
        rb->base_seq++;
        delivered++;
    }
    if (delivered > 0) {
        rb->delivered += delivered;
        rb->stable = 1;
        pthread_cond_broadcast(&ch->cond);
        clock_gettime(CLOCK_MONOTONIC, &rb->last_flush);
    }
    
    /* 超时兜底：超过 REORDER_DROP_TIMEOUT_MS 未收到期望包，主动跳过 */
    if (rb->stable) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t elapsed = (now.tv_sec - rb->last_flush.tv_sec) * 1000 + (now.tv_nsec - rb->last_flush.tv_nsec) / 1000000;
        if (elapsed > REORDER_DROP_TIMEOUT_MS) {
            /* 检查期望包是否还未到达 */
            int exp_slot = rb->base_seq % REORDER_SLOTS;
            if (!rb->slots[exp_slot].valid || rb->slots[exp_slot].seq != rb->base_seq) {
                /* 跳过缺失的包 */
                rb->base_seq++;
                rb->skipped++;
                reorder_deliver(rb, ch);
            }
        }
    }
}

static void reorder_insert_packet(reorder_buffer_t *rb, channel_t *ch, uint16_t seq, const uint8_t *payload, size_t len) {
    if (!rb->initialized) {
        rb->base_seq = seq;
        rb->initialized = 1;
    }
    
    /* 拒绝过旧的包 */
    if (rb->stable) {
        uint16_t diff = seq - rb->base_seq;
        if (diff > 0x8000) { // 包太旧了
            return;
        }
        if (diff >= REORDER_SLOTS) {
            /* 跳跃过大，强制冲刷当前窗口 */
            reorder_force_flush(rb, ch);
            rb->base_seq = seq;
        }
    }
    
    int slot = seq % REORDER_SLOTS;
    if (rb->slots[slot].valid && rb->slots[slot].seq == seq) {
        return; // 重复包
    }
    
    memcpy(rb->slots[slot].data, payload, len);
    rb->slots[slot].len = len;
    rb->slots[slot].seq = seq;
    rb->slots[slot].valid = 1;
    
    reorder_deliver(rb, ch);
}

/* ========================================================================
 * 频道管理
 * ======================================================================== */
static unsigned int channel_hash(const char *ip, int port) {
    unsigned int hash = 5381;
    while (*ip) hash = ((hash << 5) + hash) + *ip++;
    hash = ((hash << 5) + hash) + port;
    return hash % CHANNEL_HASH_SIZE;
}

static channel_t *channel_find_or_create(const char *ip, int port) {
    unsigned int h = channel_hash(ip, port);
    pthread_mutex_lock(&channel_map_lock);
    
    channel_t *ch = channel_map[h];
    while (ch) {
        if (strcmp(ch->mcast_ip, ip) == 0 && ch->mcast_port == port) {
            if (!ch->cleanup) {
                ch->refcount++;
                pthread_mutex_unlock(&channel_map_lock);
                return ch;
            }
            break;
        }
        /* 简单链表，未实现完整哈希链表，此处略 */
        break;
    }
    
    ch = calloc(1, sizeof(channel_t));
    if (!ch) {
        pthread_mutex_unlock(&channel_map_lock);
        return NULL;
    }
    
    strncpy(ch->mcast_ip, ip, sizeof(ch->mcast_ip) - 1);
    ch->mcast_port = port;
    ch->refcount = 1;
    ch->cleanup = 0;
    pthread_mutex_init(&ch->lock, NULL);
    pthread_cond_init(&ch->cond, NULL);
    ring_buffer_init(&ch->ring, RING_BUF_SIZE);
    reorder_buffer_init(&ch->reorder);
    
    /* 创建组播 socket */
    ch->mcast_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ch->mcast_fd < 0) {
        free(ch);
        pthread_mutex_unlock(&channel_map_lock);
        return NULL;
    }
    
    int opt = 1;
    setsockopt(ch->mcast_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(ch->mcast_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (bind(ch->mcast_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(ch->mcast_fd);
        free(ch);
        pthread_mutex_unlock(&channel_map_lock);
        return NULL;
    }
    
    const char *iface = getenv("MCAST_IFACE") ? getenv("MCAST_IFACE") : "eth0";
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(ch->mcast_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    
    struct ip_mreqn mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr(ip);
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = if_nametoindex(iface);
    setsockopt(ch->mcast_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    ch->mreq = mreq;
    
    int rcvbuf = UDP_RCVBUF_SIZE;
    setsockopt(ch->mcast_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_nonblocking(ch->mcast_fd);
    
    pthread_mutex_init(&ch->clients.lock, NULL);
    channel_map[h] = ch;
    pthread_mutex_unlock(&channel_map_lock);
    
    printf("📡 新频道 [%s:%d] 已创建\n", ip, port);
    return ch;
}

static void channel_unref(channel_t *ch) {
    pthread_mutex_lock(&channel_map_lock);
    ch->refcount--;
    if (ch->refcount <= 0) {
        ch->cleanup = 1;
        /* 实际的清理将在主线程安全进行 */
    }
    pthread_mutex_unlock(&channel_map_lock);
}

/* ========================================================================
 * 客户端管理
 * ======================================================================== */
static client_node_t *client_create(channel_t *ch, int fd) {
    client_node_t *c = calloc(1, sizeof(client_node_t));
    c->fd = fd;
    c->parent = ch;
    c->active = 1;
    
    pthread_mutex_lock(&ch->clients.lock);
    if (ch->clients.tail) {
        ch->clients.tail->next = c;
        c->prev = ch->clients.tail;
        ch->clients.tail = c;
    } else {
        ch->clients.head = ch->clients.tail = c;
    }
    ch->clients.count++;
    pthread_mutex_unlock(&ch->clients.lock);
    
    return c;
}

static void client_remove(client_node_t *c) {
    channel_t *ch = c->parent;
    pthread_mutex_lock(&ch->clients.lock);
    if (c->prev) c->prev->next = c->next;
    if (c->next) c->next->prev = c->prev;
    if (ch->clients.head == c) ch->clients.head = c->next;
    if (ch->clients.tail == c) ch->clients.tail = c->prev;
    ch->clients.count--;
    pthread_mutex_unlock(&ch->clients.lock);
    
    shutdown(c->fd, SHUT_RDWR);
    close(c->fd);
    free(c);
}

/* ========================================================================
 * UDP 接收线程（每频道一个）
 * ======================================================================== */
static void *udp_receiver_thread(void *arg) {
    channel_t *ch = (channel_t *)arg;
    uint8_t pkt[2048];
    
    while (!ch->cleanup) {
        ssize_t n = recv(ch->mcast_fd, pkt, sizeof(pkt), 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            break;
        }
        
        const uint8_t *payload = pkt;
        size_t payload_len = (size_t)n;
        uint16_t rtp_seq = 0;
        int is_rtp = 0;
        
        /* RTP 头检测 */
        if (n > 12 && (pkt[0] & 0xC0) == 0x80) {
            is_rtp = 1;
            rtp_seq = ((uint16_t)pkt[2] << 8) | pkt[3];
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
        
        if (is_rtp) {
            reorder_insert_packet(&ch->reorder, ch, rtp_seq, payload, payload_len);
        } else {
            ring_buffer_write(&ch->ring, payload, payload_len);
            pthread_cond_broadcast(&ch->cond);
        }
        
        /* 智能起播检查 */
        if (ts_has_pusi(payload, payload_len)) {
            client_node_t *cli = ch->clients.head;
            while (cli) {
                if (!cli->iframe_locked) {
                    cli->iframe_locked = 1;
                }
                cli = cli->next;
            }
        }
        
        pthread_mutex_unlock(&ch->lock);
    }
    
    return NULL;
}

/* ========================================================================
 * TCP 发送线程（每客户端一个）
 * ======================================================================== */
static void *tcp_sender_thread(void *arg) {
    client_node_t *c = (client_node_t *)arg;
    channel_t *ch = c->parent;
    char http_header[256];
    
    /* 发送 HTTP 响应头 */
    int header_len = snprintf(http_header, sizeof(http_header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: video/mp2t\r\n"
        "Connection: close\r\n"
        "Server: rtp2http/4.0\r\n"
        "\r\n");
    send(c->fd, http_header, header_len, MSG_NOSIGNAL);
    c->headers_sent = 1;
    
    /* 等待 I 帧 */
    while (!c->iframe_locked && c->active) {
        usleep(5000);
        if (c->close_requested) goto exit_thread;
    }
    
    while (c->active && !c->close_requested) {
        const uint8_t *ptr1, *ptr2;
        size_t len1, len2;
        size_t avail = ring_buffer_get_read_ptr(&ch->ring, &ptr1, &len1, &ptr2, &len2);
        
        if (avail == 0) {
            usleep(2000);
            continue;
        }
        
        size_t to_send = avail > CLIENT_READ_CHUNK ? CLIENT_READ_CHUNK : avail;
        struct iovec iov[2];
        int iovcnt = 0;
        
        if (to_send <= len1) {
            iov[0].iov_base = (void *)ptr1;
            iov[0].iov_len = to_send;
            iovcnt = 1;
        } else {
            iov[0].iov_base = (void *)ptr1;
            iov[0].iov_len = len1;
            iov[1].iov_base = (void *)ptr2;
            iov[1].iov_len = to_send - len1;
            iovcnt = 2;
        }
        
        ssize_t sent = writev(c->fd, iov, iovcnt);
        if (sent > 0) {
            ring_buffer_consume(&ch->ring, (size_t)sent);
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1000);
            continue;
        } else {
            break;
        }
    }
    
exit_thread:
    c->active = 0;
    client_remove(c);
    channel_unref(ch);
    return NULL;
}

/* ========================================================================
 * HTTP 请求处理
 * ======================================================================== */
static void handle_http_request(int epoll_fd, int client_fd) {
    char req[2048];
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    req[n] = '\0';
    
    char target_ip[64];
    int target_port;
    
    if (sscanf(req, "GET /rtp/%63[^:]:%d", target_ip, &target_port) == 2) {
        printf("👤 新连接：rtp://%s:%d\n", target_ip, target_port);
        
        set_tcp_optimized(client_fd);
        
        channel_t *ch = channel_find_or_create(target_ip, target_port);
        if (!ch) {
            const char *err = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            send(client_fd, err, strlen(err), MSG_NOSIGNAL);
            close(client_fd);
            return;
        }
        
        client_node_t *cli = client_create(ch, client_fd);
        
        pthread_t tid;
        if (pthread_create(&tid, NULL, tcp_sender_thread, cli) != 0) {
            client_remove(cli);
            channel_unref(ch);
            close(client_fd);
            return;
        }
        pthread_detach(tid);
        
        /* 为新频道启动 UDP 接收线程 */
        if (ch->refcount == 1) {
            pthread_create(&tid, NULL, udp_receiver_thread, ch);
            pthread_detach(tid);
        }
    } else {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, resp, strlen(resp), MSG_NOSIGNAL);
        close(client_fd);
    }
}

/* ========================================================================
 * 主事件循环
 * ======================================================================== */
int main(void) {
    signal(SIGPIPE, SIG_IGN);
    
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return 1;
    }
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(HTTP_PORT);
    srv.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen");
        return 1;
    }
    
    set_nonblocking(server_fd);
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);
    
    struct epoll_event events[MAX_EVENTS];
    
    const char *iface = getenv("MCAST_IFACE") ? getenv("MCAST_IFACE") : "eth0";
    printf("🚀 rtp2http v4.0 启动 (接口: %s, 端口: %d)\n", iface, HTTP_PORT);
    printf("   缓冲区: %d MB | TCP 发送缓冲: %d MB | UDP 接收缓冲: %d MB\n",
           RING_BUF_SIZE / (1024 * 1024), TCP_SNDBUF_SIZE / (1024 * 1024), UDP_RCVBUF_SIZE / (1024 * 1024));
    printf("   重排窗口: %d 包 | 超时: %d ms | 强制冲刷: %d ms\n",
           REORDER_SLOTS, REORDER_DROP_TIMEOUT_MS, REORDER_FORCE_FLUSH_MS);
    
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                while (1) {
                    int client_fd = accept(server_fd, NULL, NULL);
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    handle_http_request(epoll_fd, client_fd);
                }
            }
        }
    }
    
    close(server_fd);
    close(epoll_fd);
    return 0;
}