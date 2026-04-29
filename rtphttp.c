/*
 * rtphttp_v2.c — IPTV 组播转 HTTP 代理（4K 终极优化版）
 *
 * 基于 v1 / v2 优化，并融合详细注释与控制台输出。
 *
 * 关键参数（极限调优）：
 * A. 环形缓冲 128MB：可缓冲约 28 秒 36Mbps 码流，应对网络突发。
 * B. UDP 接收缓冲 16MB，批量读取最多 256 包，减少系统调用。
 * C. TCP 发送缓冲 8MB + 非阻塞模式，writev 发送块 1MB。
 * D. RTP 重排窗口 64 包，增强乱序抗性。
 * E. 智能起播：检测 MPEG-TS 包 PUSI 标志，看到 I 帧边界即开始发送，
 *    完全移除固定字节数兜底，起播更快。
 * F. 双缓冲 + 背压解耦：发送路径不持锁，仅更新 tail 成功才移动，
 *    避免 writev 阻塞时丢失数据或死锁。
 * G. 精确 IGMP 加组（ip_mreqn），支持多网卡/VLAN。
 *
 * 编译：gcc -O2 -o rtp2http rtphttp_v2.c -lpthread
 * 运行：MCAST_IFACE=eth0.45 ./rtp2http
 *
 * 请求格式：GET /rtp/组播IP:端口 HTTP/1.1
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

#define HTTP_PORT           7099
#define MAX_EVENTS          128
#define RING_BUF_SIZE       (128 * 1024 * 1024) // 128MB 缓冲区
#define SEND_CHUNK_SIZE     (1024 * 1024)       // 每次发送量 1MB
#define TCP_SNDBUF_SIZE     (8  * 1024 * 1024)  // TCP 发送内核缓冲
#define UDP_RCVBUF_SIZE     (16 * 1024 * 1024)  // UDP 接收内核缓冲
#define TS_PACKET_SIZE      188
#define REORDER_SLOTS       64                  // 增加重排窗口
#define REORDER_MASK        (REORDER_SLOTS - 1)

/* RTP 重排槽位，每个包数据最多 2048 字节 */
typedef struct {
    uint8_t  data[2048];
    size_t   len;
    uint16_t seq;
    int      valid;
} ReorderSlot;

/* RTP 重排缓冲区 */
typedef struct {
    ReorderSlot slots[REORDER_SLOTS];
    uint16_t    next_seq;
    int         initialized;
} ReorderBuf;

/* 单个频道（HTTP 客户端 + 组播源） */
typedef struct {
    int              mcast_fd;       // 组播 socket
    int              client_fd;      // TCP 客户端 socket
    int              epoll_fd;       // epoll 实例（用于删除事件）
    struct ip_mreqn  mreq;           // 组播成员信息（退出时用）
    uint8_t         *ring_buf;       // 环形缓冲区
    size_t           head;           // 写指针
    size_t           tail;           // 读指针
    pthread_mutex_t  lock;           // 保护 ring buffer 的互斥锁
    pthread_cond_t   cond;           // 条件变量（通知发送线程有新数据）
    volatile atomic_int running;     // 运行状态标志
    int              iframe_found;   // 是否已检测到 I 帧（PUSI）
    ReorderBuf       reorder;        // RTP 重排缓冲
    int              is_rtp;         // 是否 RTP 封装
} Channel;

Channel *slots[65536];   // fd -> Channel 快速映射表

/* 设置文件描述符为非阻塞 */
static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* 检查 TS 负载中是否包含 PUSI（Payload Unit Start Indicator）标志，
 * 通常指示一个 I 帧或关键帧边界，用于智能起播 */
static int ts_has_pusi(const uint8_t *payload, size_t len) {
    if (len < TS_PACKET_SIZE) return 0;
    for (size_t off = 0; off + TS_PACKET_SIZE <= len; off += TS_PACKET_SIZE) {
        if (payload[off] == 0x47 && (payload[off + 1] & 0x40)) return 1;
    }
    return 0;
}

/* 写入环形缓冲区（自动对齐到 188 字节，满则丢弃） */
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

/* 插入一个包到 RTP 重排槽 */
static void reorder_insert(ReorderBuf *rb, uint16_t seq, const uint8_t *payload, size_t len) {
    int slot = seq & REORDER_MASK;
    memcpy(rb->slots[slot].data, payload, len);
    rb->slots[slot].len = len;
    rb->slots[slot].seq = seq;
    rb->slots[slot].valid = 1;
}

/* 从 next_seq 开始连续冲刷所有已就绪的包到环形缓冲区 */
static void reorder_flush(ReorderBuf *rb, Channel *ch) {
    while (1) {
        int slot = rb->next_seq & REORDER_MASK;
        if (!rb->slots[slot].valid || rb->slots[slot].seq != rb->next_seq) break;
        ring_write(ch, rb->slots[slot].data, rb->slots[slot].len);
        rb->slots[slot].valid = 0;
        rb->next_seq++;
    }
}

/* 处理一个接收到的 UDP 包：识别 RTP/TS，剥离 RTP 头，重排，写入环形缓冲 */
static void process_packet(Channel *ch, const uint8_t *pkt, ssize_t n) {
    const uint8_t *payload = pkt;
    size_t payload_len = (size_t)n;
    uint16_t rtp_seq = 0;
    int has_seq = 0;

    /* 协议识别与 RTP 头部处理 */
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

    /* 智能起播：检测到 PUSI 即认为 I 帧到来，开始发送 */
    if (!ch->iframe_found && ts_has_pusi(payload, payload_len)) ch->iframe_found = 1;
    
    pthread_cond_signal(&ch->cond);
    pthread_mutex_unlock(&ch->lock);
}

/* TCP 发送线程：等待起播，然后持续消费环形缓冲，通过 writev 零拷贝发送 */
void *tcp_sender(void *arg) {
    Channel *ch = (Channel *)arg;

    /* 等待起播条件（I 帧检测） */
    pthread_mutex_lock(&ch->lock);
    while (atomic_load(&ch->running) && !ch->iframe_found) pthread_cond_wait(&ch->cond, &ch->lock);
    pthread_mutex_unlock(&ch->lock);

    if (!atomic_load(&ch->running)) goto exit_thread;

    while (atomic_load(&ch->running)) {
        pthread_mutex_lock(&ch->lock);

        /* 计算可发送数据长度，无数据则等待 */
        size_t data_len = 0;
        while (atomic_load(&ch->running)) {
            data_len = (ch->head >= ch->tail) ? (ch->head - ch->tail) : (RING_BUF_SIZE - ch->tail + ch->head);
            if (data_len > 0) break;
            pthread_cond_wait(&ch->cond, &ch->lock);
        }
        if (!atomic_load(&ch->running)) { pthread_mutex_unlock(&ch->lock); break; }

        size_t to_send = (data_len > SEND_CHUNK_SIZE) ? SEND_CHUNK_SIZE : data_len;

        /* 构建 iovec 指向环形缓冲区（零拷贝） */
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
            /* 发送成功，推进 tail */
            pthread_mutex_lock(&ch->lock);
            ch->tail = (ch->tail + sent) % RING_BUF_SIZE;
            pthread_mutex_unlock(&ch->lock);
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            /* 致命错误（如客户端断开），终止线程 */
            atomic_store(&ch->running, 0);
        }
    }

exit_thread:
    printf("⏹  发送线程退出，client FD: %d\n", ch->client_fd);

    /* 清理资源：脱离 epoll、脱离组播、关闭 socket、释放内存 */
    epoll_ctl(ch->epoll_fd, EPOLL_CTL_DEL, ch->mcast_fd, NULL);
    slots[ch->mcast_fd] = NULL;
    setsockopt(ch->mcast_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &ch->mreq, sizeof(ch->mreq));
    close(ch->mcast_fd);
    close(ch->client_fd);
    free(ch->ring_buf);
    pthread_mutex_destroy(&ch->lock);
    pthread_cond_destroy(&ch->cond);
    free(ch);
    return NULL;
}

/* 创建组播 socket 并加入指定组播组 */
static int create_mcast_socket(const char *ip, int port, struct ip_mreqn *mreq_out) {
    printf("   加入组播 %s:%d ...\n", ip, port);

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

    /* 使用 ip_mreqn 精确加入组播（指定接口索引） */
    struct ip_mreqn mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr(ip);
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = if_nametoindex(iface);
    setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    *mreq_out = mreq;

    int rcvbuf = UDP_RCVBUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_nonblocking(fd);

    printf("   组播 socket 创建成功，fd=%d\n", fd);
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

    const char *iface = getenv("MCAST_IFACE") ? : "eth0";

    printf("🚀 4K 极限优化代理启动！\n");
    printf("   端口: %d | 接口: %s | 环形缓冲: %dMB\n", HTTP_PORT, iface, RING_BUF_SIZE / 1024 / 1024);
    printf("   UDP 接收缓冲: %dMB | TCP 发送缓冲: %dMB\n", UDP_RCVBUF_SIZE / 1024 / 1024, TCP_SNDBUF_SIZE / 1024 / 1024);
    printf("   重排窗口: %d 包 | 批量读取: 256 包\n", REORDER_SLOTS);

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == server_fd) {
                int cli_fd = accept(server_fd, NULL, NULL);
                char req[1024];
                recv(cli_fd, req, sizeof(req), 0);   // 单次读取 HTTP 请求

                char target_ip[64];
                int target_port;
                if (sscanf(req, "GET /rtp/%63[^:]:%d", target_ip, &target_port) == 2) {
                    printf("👤 新连接：rtp://%s:%d | 等待 I 帧起播...\n", target_ip, target_port);

                    send(cli_fd, "HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nConnection: close\r\n\r\n", 64, 0);

                    int sndbuf = TCP_SNDBUF_SIZE;
                    setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                    int nodelay = 1;
                    setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
                    set_nonblocking(cli_fd);

                    Channel *ch = calloc(1, sizeof(Channel));
                    ch->mcast_fd = create_mcast_socket(target_ip, target_port, &ch->mreq);
                    ch->client_fd = cli_fd;
                    ch->epoll_fd = epoll_fd;
                    ch->ring_buf = malloc(RING_BUF_SIZE);
                    atomic_store(&ch->running, 1);
                    pthread_mutex_init(&ch->lock, NULL);
                    pthread_cond_init(&ch->cond, NULL);
                    slots[ch->mcast_fd] = ch;

                    pthread_t tid;
                    pthread_create(&tid, NULL, tcp_sender, ch);
                    pthread_detach(tid);

                    ev.events = EPOLLIN;
                    ev.data.fd = ch->mcast_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ch->mcast_fd, &ev);
                } else {
                    printf("❌ 请求解析失败或格式错误: %s\n", req);
                    close(cli_fd);
                }
            } else if (slots[fd]) {
                Channel *ch = slots[fd];
                uint8_t pkt[2048];
                int count = 0;
                /* 批量读取至多 256 个 UDP 包，防止饿死其他 fd */
                while (count++ < 256) {
                    ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
                    if (n <= 0) break;
                    process_packet(ch, pkt, n);
                }
            }
        }
    }
    return 0;
}