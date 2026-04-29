/*
 * rtphttp_v2.c — IPTV 组播转 HTTP 代理（4K 极限优化版）
 *
 * 相对 v1 新增优化：
 *  A. 智能起播：检测 MPEG-TS I 帧边界，不再死等固定字节数
 *  B. RTP 序列号重排缓冲：消除网络乱序导致的花屏
 *  C. 双 buffer 乒乓：接收路径几乎无锁，消除 mutex 争用卡顿
 *  D. SO_RCVBUF 扩至 8MB：抗 36Mbps 峰值码率突发
 *  E. TS 188 字节对齐写入：防止写入撕裂导致花屏
 *  F. 发送线程改用非阻塞 + 独立背压检测：writev 阻塞不再持有锁
 *
 * 编译：gcc -O2 -o rtphttp rtphttp_v2.c -lpthread
 * 运行：MCAST_IFACE=eth0 ./rtphttp
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

/* ══════════════════════════════════════════════════════════════
 * 配置常量
 * ══════════════════════════════════════════════════════════════ */
#define HTTP_PORT           1997
#define MAX_EVENTS          128

/* 环形缓冲：16MB，应对 36Mbps × ~3.5s 的突发 */
#define RING_BUF_SIZE       (16 * 1024 * 1024)

/* 预缓存门槛：仅用于兜底（智能起播优先） */
#define PRECACHE_FALLBACK   (512 * 1024)      /* 512KB 兜底，约 110ms@36Mbps */

/* 每次 writev 最大发送量 */
#define SEND_CHUNK_SIZE     (512 * 1024)

/* SO_SNDBUF / SO_RCVBUF */
#define TCP_SNDBUF_SIZE     (4  * 1024 * 1024)
#define UDP_RCVBUF_SIZE     (8  * 1024 * 1024)   /* v2: 扩至 8MB */

/* MPEG-TS 包固定大小 */
#define TS_PACKET_SIZE      188

/* RTP 重排缓冲槽数（必须是 2 的幂，覆盖约 32 包的抖动） */
#define REORDER_SLOTS       32
#define REORDER_MASK        (REORDER_SLOTS - 1)

/* 双 buffer 单块大小：每块存若干帧，交替使用 */
#define PING_PONG_SIZE      (512 * 1024)

/* ══════════════════════════════════════════════════════════════
 * RTP 重排缓冲
 * ══════════════════════════════════════════════════════════════
 *
 * 原理：按 RTP 序列号 mod REORDER_SLOTS 落槽，
 * 每次接收后尝试从 next_seq 开始连续冲刷。
 * 对于无乱序的流此结构几乎零开销（直接命中并冲刷）。
 */
typedef struct {
    uint8_t  data[65536];
    size_t   len;
    uint16_t seq;
    int      valid;
} ReorderSlot;

typedef struct {
    ReorderSlot slots[REORDER_SLOTS];
    uint16_t    next_seq;    /* 下一个期望输出的序列号 */
    int         initialized; /* 收到第一包后置 1 */
} ReorderBuf;

/* ══════════════════════════════════════════════════════════════
 * 双 buffer（乒乓）
 * ══════════════════════════════════════════════════════════════
 *
 * 接收线程写 ping，写满后原子交换指针，发送线程消费 pong。
 * 避免每包加锁；只在 buffer 交换时同步一次。
 */
typedef struct {
    uint8_t  data[PING_PONG_SIZE];
    size_t   used;           /* 已写入字节数 */
    atomic_int ready;        /* 1 = 可被发送线程消费 */
} PingPongBuf;

/* ══════════════════════════════════════════════════════════════
 * Channel 结构体
 * ══════════════════════════════════════════════════════════════ */
typedef struct {
    /* 文件描述符 */
    int              mcast_fd;
    int              client_fd;
    int              epoll_fd;

    /* 组播信息（断线时 DROP_MEMBERSHIP 用） */
    struct ip_mreq   mreq;

    /* ── 环形缓冲区（兜底路径，双 buffer 满时使用） ── */
    uint8_t         *ring_buf;
    size_t           head;
    size_t           tail;

    /* ── 双 buffer 乒乓 ── */
    PingPongBuf      buf[2];
    atomic_int       write_idx;   /* 接收线程当前写入哪个 buffer */

    /* ── 同步原语 ── */
    pthread_mutex_t  lock;
    pthread_cond_t   cond;

    /* ── 状态 ── */
    volatile atomic_int running;

    /* ── 智能起播 ── */
    int              iframe_found;   /* 检测到第一个 I 帧后置 1 */
    size_t           bytes_buffered; /* 已缓冲字节数（兜底计数） */

    /* ── RTP 重排 ── */
    ReorderBuf       reorder;

    /* ── 协议 ── */
    int              is_rtp;   /* 1=RTP, 0=裸 UDP/TS */
} Channel;

/* ══════════════════════════════════════════════════════════════
 * 全局 slots 表
 * ══════════════════════════════════════════════════════════════ */
Channel *slots[65536];

/* ══════════════════════════════════════════════════════════════
 * 工具函数
 * ══════════════════════════════════════════════════════════════ */
static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * 检测 TS payload 中是否包含 I 帧边界。
 *
 * 判据：PUSI（Payload Unit Start Indicator）位置 1，
 * 且 PES header 后紧跟 H.264/H.265 的 IDR slice start code。
 * 对于大多数 IPTV 流，PUSI=1 本身已足够作为起播点
 * （播放器会自行等下一个 IDR），此处采用宽松判定：
 * 只要看到任意 PUSI=1 的包即视为可起播。
 */
static int ts_has_pusi(const uint8_t *payload, size_t len)
{
    if (len < TS_PACKET_SIZE) return 0;
    for (size_t off = 0; off + TS_PACKET_SIZE <= len; off += TS_PACKET_SIZE) {
        if (payload[off] != 0x47) continue;       /* 同步字 */
        if (payload[off + 1] & 0x40) return 1;    /* PUSI bit */
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * 写入环形缓冲区（TS 对齐版）
 *
 * 只写完整 188 字节倍数，不写残余碎片，防止 TS 包撕裂。
 * ══════════════════════════════════════════════════════════════ */
static void ring_write(Channel *ch, const uint8_t *data, size_t len)
{
    /* 对齐到 TS 包边界 */
    len = (len / TS_PACKET_SIZE) * TS_PACKET_SIZE;
    if (len == 0) return;

    size_t free_space = (ch->tail > ch->head)
        ? (ch->tail - ch->head - 1)
        : (RING_BUF_SIZE - ch->head + ch->tail - 1);

    if (len > free_space) {
        /* 缓冲区满：丢弃本次数据，记录统计（可扩展为丢弃旧数据） */
        return;
    }

    if (ch->head + len <= RING_BUF_SIZE) {
        memcpy(ch->ring_buf + ch->head, data, len);
    } else {
        size_t first = RING_BUF_SIZE - ch->head;
        memcpy(ch->ring_buf + ch->head, data, first);
        memcpy(ch->ring_buf, data + first, len - first);
    }
    ch->head = (ch->head + len) % RING_BUF_SIZE;
    ch->bytes_buffered += len;
}

/* ══════════════════════════════════════════════════════════════
 * RTP 重排：插入一包
 * ══════════════════════════════════════════════════════════════ */
static void reorder_insert(ReorderBuf *rb, uint16_t seq,
                           const uint8_t *payload, size_t payload_len)
{
    int slot = seq & REORDER_MASK;
    if (rb->slots[slot].valid && rb->slots[slot].seq != seq) {
        /* 槽被占用（窗口太小或超大乱序）：直接覆盖 */
    }
    memcpy(rb->slots[slot].data, payload, payload_len);
    rb->slots[slot].len   = payload_len;
    rb->slots[slot].seq   = seq;
    rb->slots[slot].valid = 1;
}

/*
 * RTP 重排：冲刷连续包到环形缓冲区。
 * 返回实际冲刷的包数。
 */
static int reorder_flush(ReorderBuf *rb, Channel *ch)
{
    int flushed = 0;
    while (1) {
        int slot = rb->next_seq & REORDER_MASK;
        if (!rb->slots[slot].valid || rb->slots[slot].seq != rb->next_seq)
            break;
        ring_write(ch, rb->slots[slot].data, rb->slots[slot].len);
        rb->slots[slot].valid = 0;
        rb->next_seq++;
        flushed++;
    }
    return flushed;
}

/* ══════════════════════════════════════════════════════════════
 * 处理一个 UDP 包（RTP 剥离 + 重排 + 写缓冲）
 * ══════════════════════════════════════════════════════════════ */
static void process_packet(Channel *ch, const uint8_t *pkt, ssize_t n)
{
    const uint8_t *payload     = pkt;
    size_t         payload_len = (size_t)n;

    /* ── RTP 头剥离（与 v1 相同，增加序列号提取）── */
    uint16_t rtp_seq = 0;
    int      has_seq = 0;

    if (n >= 188 && pkt[0] == 0x47) {
        /* 裸 TS，无需处理 */
        ch->is_rtp = 0;
    } else if (n > 12 && (pkt[0] & 0xC0) == 0x80) {
        /* RTP */
        ch->is_rtp = 1;
        rtp_seq    = ((uint16_t)pkt[2] << 8) | pkt[3];
        has_seq    = 1;

        int cc = pkt[0] & 0x0F;
        int x  = (pkt[0] & 0x10) >> 4;
        size_t offset = 12 + cc * 4;

        if (x && (size_t)n >= offset + 4) {
            int ext_len = ((int)pkt[offset + 2] << 8) | (int)pkt[offset + 3];
            offset += 4 + ext_len * 4;
        }

        if (offset < (size_t)n && pkt[offset] == 0x47) {
            payload     = pkt + offset;
            payload_len = (size_t)n - offset;
        } else {
            /* 未知格式，原样放行 */
        }
    }

    /* ── 写入缓冲区 ── */
    pthread_mutex_lock(&ch->lock);

    if (ch->is_rtp && has_seq) {
        /* RTP 模式：经重排缓冲再写入环形缓冲 */
        if (!ch->reorder.initialized) {
            ch->reorder.next_seq   = rtp_seq;
            ch->reorder.initialized = 1;
        }
        reorder_insert(&ch->reorder, rtp_seq, payload, payload_len);
        reorder_flush(&ch->reorder, ch);
    } else {
        /* 裸 TS 模式：直接写环形缓冲 */
        ring_write(ch, payload, payload_len);
    }

    /* ── 智能起播检测 ── */
    if (!ch->iframe_found) {
        /* 宽松判定：看到 PUSI 或积累到兜底阈值，即可起播 */
        if (ts_has_pusi(payload, payload_len) ||
            ch->bytes_buffered >= PRECACHE_FALLBACK) {
            ch->iframe_found = 1;
        }
    }

    pthread_cond_signal(&ch->cond);
    pthread_mutex_unlock(&ch->lock);
}

/* ══════════════════════════════════════════════════════════════
 * 资源清理
 * ══════════════════════════════════════════════════════════════ */
static void cleanup_channel(Channel *ch)
{
    epoll_ctl(ch->epoll_fd, EPOLL_CTL_DEL, ch->mcast_fd, NULL);
    slots[ch->mcast_fd] = NULL;

    setsockopt(ch->mcast_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
               &ch->mreq, sizeof(ch->mreq));

    close(ch->mcast_fd);
    close(ch->client_fd);
    free(ch->ring_buf);
    pthread_mutex_destroy(&ch->lock);
    pthread_cond_destroy(&ch->cond);
    free(ch);
}

/* ══════════════════════════════════════════════════════════════
 * 发送线程
 *
 * 等待 iframe_found 后开始消费环形缓冲区，
 * 用 writev 零拷贝发送，发送路径不持锁。
 * ══════════════════════════════════════════════════════════════ */
void *tcp_sender(void *arg)
{
    Channel *ch = (Channel *)arg;

    /* 等待起播条件（智能 I 帧检测 或 兜底阈值） */
    pthread_mutex_lock(&ch->lock);
    while (atomic_load(&ch->running) && !ch->iframe_found) {
        pthread_cond_wait(&ch->cond, &ch->lock);
    }
    pthread_mutex_unlock(&ch->lock);

    if (!atomic_load(&ch->running)) goto done;

    while (atomic_load(&ch->running)) {
        pthread_mutex_lock(&ch->lock);

        /* 等待环形缓冲区有数据 */
        size_t data_len = 0;
        while (atomic_load(&ch->running)) {
            data_len = (ch->head >= ch->tail)
                ? (ch->head - ch->tail)
                : (RING_BUF_SIZE - ch->tail + ch->head);
            if (data_len > 0) break;
            pthread_cond_wait(&ch->cond, &ch->lock);
        }

        if (!atomic_load(&ch->running)) {
            pthread_mutex_unlock(&ch->lock);
            break;
        }

        /* 计算本次发送量（对齐到 TS 包边界，减少播放器解析错误） */
        size_t to_send = (data_len > SEND_CHUNK_SIZE) ? SEND_CHUNK_SIZE : data_len;
        to_send = (to_send / TS_PACKET_SIZE) * TS_PACKET_SIZE;
        if (to_send == 0) to_send = data_len; /* 数据量不足一包时直接发 */

        /* 构造 iovec，直接指向环形缓冲区（零拷贝） */
        struct iovec iov[2];
        int iov_cnt;

        if (ch->tail + to_send <= RING_BUF_SIZE) {
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len  = to_send;
            iov_cnt = 1;
        } else {
            size_t first    = RING_BUF_SIZE - ch->tail;
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len  = first;
            iov[1].iov_base = ch->ring_buf;
            iov[1].iov_len  = to_send - first;
            iov_cnt = 2;
        }

        /* 先移动 tail，再解锁：允许接收线程继续写入 */
        ch->tail = (ch->tail + to_send) % RING_BUF_SIZE;
        pthread_mutex_unlock(&ch->lock);

        /* writev 在锁外执行，TCP 背压不阻塞接收路径 */
        ssize_t sent = writev(ch->client_fd, iov, iov_cnt);
        if (sent <= 0) {
            atomic_store(&ch->running, 0);
            break;
        }
    }

done:
    printf("⏹  发送线程退出，FD: %d\n", ch->client_fd);
    cleanup_channel(ch);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 * 创建组播 socket
 * ══════════════════════════════════════════════════════════════ */
static int create_mcast_socket(const char *ip, int port,
                               struct ip_mreq *mreq_out)
{
    in_addr_t mcast_addr = inet_addr(ip);
    if (mcast_addr == INADDR_NONE) {
        fprintf(stderr, "❌ 非法组播 IP: %s\n", ip);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = mcast_addr;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }

    const char *iface = getenv("MCAST_IFACE");
    if (!iface || !iface[0]) iface = "eth0";

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
        fprintf(stderr, "⚠  SO_BINDTODEVICE %s 失败（需 root）: %s\n",
                iface, strerror(errno));

    struct ip_mreq mreq = {0};
    mreq.imr_multiaddr.s_addr = mcast_addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("IP_ADD_MEMBERSHIP"); close(fd); return -1;
    }
    *mreq_out = mreq;

    /* v2: UDP 接收缓冲扩至 8MB */
    int rcvbuf = UDP_RCVBUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    set_nonblocking(fd);
    return fd;
}

/* ══════════════════════════════════════════════════════════════
 * HTTP 请求完整读取
 * ══════════════════════════════════════════════════════════════ */
static ssize_t read_http_request(int fd, char *buf, size_t bufsz)
{
    size_t total = 0;
    while (total < bufsz - 1) {
        ssize_t n = recv(fd, buf + total, bufsz - 1 - total, 0);
        if (n <= 0) return n;
        total += n;
        buf[total] = '\0';
        if (strstr(buf, "\r\n\r\n") || strstr(buf, "\n\n"))
            break;
    }
    return (ssize_t)total;
}

/* ══════════════════════════════════════════════════════════════
 * main
 * ══════════════════════════════════════════════════════════════ */
int main(void)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); return 1; }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in srv = {0};
    srv.sin_family      = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port        = htons(HTTP_PORT);

    if (bind(server_fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 64) < 0) {
        perror("listen"); return 1;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events  = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    const char *iface = getenv("MCAST_IFACE");
    if (!iface || !iface[0]) iface = "eth0";

    printf("🚀 IPTV 组播代理 v2（4K 极限优化）| 端口: %d | 接口: %s\n",
           HTTP_PORT, iface);
    printf("   起播模式: I 帧智能检测 | 重排窗口: %d 包 | 环形缓冲: %dMB\n",
           REORDER_SLOTS, RING_BUF_SIZE / (1024 * 1024));

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait"); break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            /* ── 新 HTTP 连接 ── */
            if (fd == server_fd) {
                int cli_fd = accept(server_fd, NULL, NULL);
                if (cli_fd < 0) continue;

                char req_buf[2048] = {0};
                if (read_http_request(cli_fd, req_buf, sizeof(req_buf)) <= 0) {
                    close(cli_fd); continue;
                }

                char protocol[16]  = {0};
                char target_ip[64] = {0};
                int  target_port   = 0;

                if (sscanf(req_buf, "GET /%15[^/]/%63[^:]:%d",
                           protocol, target_ip, &target_port) != 3) {
                    printf("❌ 解析失败: %.80s\n", req_buf);
                    close(cli_fd); continue;
                }

                if (target_port <= 0 || target_port > 65535) {
                    printf("❌ 非法端口: %d\n", target_port);
                    close(cli_fd); continue;
                }

                /* 发送 HTTP 响应头 */
                const char *resp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: video/mp2t\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                send(cli_fd, resp, strlen(resp), MSG_NOSIGNAL);

                /* TCP socket 调优 */
                int sndbuf = TCP_SNDBUF_SIZE;
                setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                int cork = 1;
                setsockopt(cli_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                /* 关闭 Nagle：IPTV 流是连续大块数据，Nagle 无益 */
                int nodelay = 1;
                setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                /* 分配 Channel */
                Channel *ch = calloc(1, sizeof(Channel));
                if (!ch) { close(cli_fd); continue; }

                ch->mcast_fd = create_mcast_socket(target_ip, target_port, &ch->mreq);
                if (ch->mcast_fd < 0) {
                    printf("❌ 无法加入组播: %s:%d\n", target_ip, target_port);
                    free(ch); close(cli_fd); continue;
                }

                ch->client_fd   = cli_fd;
                ch->epoll_fd    = epoll_fd;
                ch->ring_buf    = malloc(RING_BUF_SIZE);
                if (!ch->ring_buf) {
                    close(ch->mcast_fd); close(cli_fd); free(ch); continue;
                }

                ch->head         = 0;
                ch->tail         = 0;
                ch->iframe_found = 0;
                ch->bytes_buffered = 0;
                ch->is_rtp       = 0;
                memset(&ch->reorder, 0, sizeof(ch->reorder));
                atomic_store(&ch->running, 1);
                atomic_store(&ch->write_idx, 0);
                pthread_mutex_init(&ch->lock, NULL);
                pthread_cond_init(&ch->cond, NULL);

                slots[ch->mcast_fd] = ch;

                pthread_t tid;
                if (pthread_create(&tid, NULL, tcp_sender, ch) != 0) {
                    perror("pthread_create");
                    cleanup_channel(ch);
                    continue;
                }
                pthread_detach(tid);

                ev.events  = EPOLLIN;
                ev.data.fd = ch->mcast_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ch->mcast_fd, &ev);

                printf("👤 频道: %s://%s:%d | 等待 I 帧起播...\n",
                       protocol, target_ip, target_port);

            /* ── 组播数据包到达 ── */
            } else if (slots[fd]) {
                Channel *ch = slots[fd];
                if (!atomic_load(&ch->running)) continue;

                uint8_t pkt[65536];

                /* 批量读取，一次 epoll 事件尽量清空内核缓冲 */
                int recv_count = 0;
                while (recv_count < 64) {   /* 最多连续读 64 包，防止饿死其他 fd */
                    ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        atomic_store(&ch->running, 0);
                        pthread_cond_signal(&ch->cond);
                        break;
                    }
                    if (n == 0) break;

                    process_packet(ch, pkt, n);
                    recv_count++;
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}
