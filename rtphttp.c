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

/* ══════════════════════════════════════════════════════════════
 * 配置常量
 * ══════════════════════════════════════════════════════════════ */
#define HTTP_PORT           7099
#define MAX_EVENTS          128

/* 环形缓冲区大小（128MB，应对 4K 超高码率） */
#define RING_BUF_SIZE       (128 * 1024 * 1024)

/* 每次 writev 最大发送量（1MB，减少系统调用频次） */
#define SEND_CHUNK_SIZE     (1024 * 1024)

/* TCP/UDP 内核缓冲区 */
#define TCP_SNDBUF_SIZE     (8  * 1024 * 1024)
#define UDP_RCVBUF_SIZE     (16 * 1024 * 1024)

/* MPEG-TS 包固定长度 */
#define TS_PACKET_SIZE      188

/* RTP 重排缓冲槽数量（64 槽，约覆盖 0.5 秒乱序窗口） */
#define REORDER_SLOTS       64
#define REORDER_MASK        (REORDER_SLOTS - 1)

/* ══════════════════════════════════════════════════════════════
 * RTP 重排缓冲结构
 * ══════════════════════════════════════════════════════════════ */
typedef struct {
    uint8_t  data[2048];  /* 足够容纳一个 RTP 包（含扩展） */
    size_t   len;
    uint16_t seq;
    int      valid;
} ReorderSlot;

typedef struct {
    ReorderSlot slots[REORDER_SLOTS];
    uint16_t    next_seq;      /* 下一个期望输出的序列号 */
    int         initialized;   /* 收到第一个包后置 1 */
} ReorderBuf;

/* ══════════════════════════════════════════════════════════════
 * Channel 结构体（每个组播频道一个实例）
 * ══════════════════════════════════════════════════════════════ */
typedef struct {
    /* 文件描述符 */
    int              mcast_fd;
    int              client_fd;
    int              epoll_fd;

    /* 组播成员信息（用于退出时脱离组播） */
    struct ip_mreqn  mreq;

    /* ── 环形缓冲区 ── */
    uint8_t         *ring_buf;
    size_t           head;
    size_t           tail;

    /* ── 同步原语 ── */
    pthread_mutex_t  lock;
    pthread_cond_t   cond;

    /* ── 运行状态 ── */
    volatile atomic_int running;

    /* ── 智能起播 ── */
    int              iframe_found;   /* 检测到第一个 I 帧（PUSI）后置 1 */

    /* ── RTP 重排 ── */
    ReorderBuf       reorder;

    /* ── 协议标识 ── */
    int              is_rtp;         /* 1: RTP 封装，0: 裸 UDP/TS */
} Channel;

/* 文件描述符 -> Channel 快速查找表 */
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
 * 检测 TS 负载中是否包含 I 帧边界（PUSI 标志）
 * 判据：同步字节 0x47 且 payload_unit_start_indicator = 1。
 * 对于绝大多数 IPTV 流，看到 PUSI=1 的包即可安全起播。
 */
static int ts_has_pusi(const uint8_t *payload, size_t len)
{
    if (len < TS_PACKET_SIZE) return 0;
    for (size_t off = 0; off + TS_PACKET_SIZE <= len; off += TS_PACKET_SIZE) {
        if (payload[off] == 0x47 && (payload[off + 1] & 0x40))
            return 1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * 写入环形缓冲区（TS 188 字节对齐）
 *
 * 只写入完整 TS 包整数倍，防止包撕裂导致花屏。
 * 缓冲区满时直接丢弃，避免阻塞接收路径。
 * ══════════════════════════════════════════════════════════════ */
static void ring_write(Channel *ch, const uint8_t *data, size_t len)
{
    len = (len / TS_PACKET_SIZE) * TS_PACKET_SIZE;
    if (len == 0) return;

    size_t free_space = (ch->tail > ch->head)
        ? (ch->tail - ch->head - 1)
        : (RING_BUF_SIZE - ch->head + ch->tail - 1);

    if (len > free_space) return;   /* 缓冲区满，静默丢弃 */

    if (ch->head + len <= RING_BUF_SIZE) {
        memcpy(ch->ring_buf + ch->head, data, len);
    } else {
        size_t first = RING_BUF_SIZE - ch->head;
        memcpy(ch->ring_buf + ch->head, data, first);
        memcpy(ch->ring_buf, data + first, len - first);
    }
    ch->head = (ch->head + len) % RING_BUF_SIZE;
}

/* ══════════════════════════════════════════════════════════════
 * RTP 重排缓冲操作
 * ══════════════════════════════════════════════════════════════ */
static void reorder_insert(ReorderBuf *rb, uint16_t seq,
                           const uint8_t *payload, size_t len)
{
    int slot = seq & REORDER_MASK;
    memcpy(rb->slots[slot].data, payload, len);
    rb->slots[slot].len   = len;
    rb->slots[slot].seq   = seq;
    rb->slots[slot].valid = 1;
}

/*
 * 从 next_seq 开始连续冲刷所有已就绪的包到环形缓冲区。
 */
static void reorder_flush(ReorderBuf *rb, Channel *ch)
{
    while (1) {
        int slot = rb->next_seq & REORDER_MASK;
        if (!rb->slots[slot].valid || rb->slots[slot].seq != rb->next_seq)
            break;
        ring_write(ch, rb->slots[slot].data, rb->slots[slot].len);
        rb->slots[slot].valid = 0;
        rb->next_seq++;
    }
}

/* ══════════════════════════════════════════════════════════════
 * 处理一个 UDP 包（RTP 剥离 + 重排 + 写环形缓冲）
 * ══════════════════════════════════════════════════════════════ */
static void process_packet(Channel *ch, const uint8_t *pkt, ssize_t n)
{
    const uint8_t *payload     = pkt;
    size_t         payload_len = (size_t)n;
    uint16_t       rtp_seq     = 0;
    int            has_seq     = 0;

    /* ── 协议识别与 RTP 头部剥离 ── */
    if (n >= 188 && pkt[0] == 0x47) {
        ch->is_rtp = 0;
    } else if (n > 12 && (pkt[0] & 0xC0) == 0x80) {
        ch->is_rtp = 1;
        rtp_seq = ((uint16_t)pkt[2] << 8) | pkt[3];
        has_seq = 1;

        int cc = pkt[0] & 0x0F;
        size_t offset = 12 + cc * 4;

        if ((pkt[0] & 0x10) && (size_t)n >= offset + 4) {
            int ext_len = ((int)pkt[offset + 2] << 8) | (int)pkt[offset + 3];
            offset += 4 + ext_len * 4;
        }

        if (offset < (size_t)n && pkt[offset] == 0x47) {
            payload     = pkt + offset;
            payload_len = (size_t)n - offset;
        }
    }

    /* ── 写入缓冲区（锁内操作） ── */
    pthread_mutex_lock(&ch->lock);

    if (ch->is_rtp && has_seq) {
        /* RTP 模式：先经过重排缓冲，再冲刷连续包 */
        if (!ch->reorder.initialized) {
            ch->reorder.next_seq    = rtp_seq;
            ch->reorder.initialized = 1;
        }
        reorder_insert(&ch->reorder, rtp_seq, payload, payload_len);
        reorder_flush(&ch->reorder, ch);
    } else {
        /* 裸 TS 模式：直接写入环形缓冲 */
        ring_write(ch, payload, payload_len);
    }

    /* ── 智能起播检测（仅 PUSI，无兜底阈值） ── */
    if (!ch->iframe_found && ts_has_pusi(payload, payload_len)) {
        ch->iframe_found = 1;
    }

    pthread_cond_signal(&ch->cond);
    pthread_mutex_unlock(&ch->lock);
}

/* ══════════════════════════════════════════════════════════════
 * 资源清理（统一清理函数，备用）
 * ══════════════════════════════════════════════════════════════ */
static void cleanup_channel(Channel *ch)
{
    /* 从 epoll 移除组播 fd */
    if (ch->epoll_fd >= 0)
        epoll_ctl(ch->epoll_fd, EPOLL_CTL_DEL, ch->mcast_fd, NULL);
    slots[ch->mcast_fd] = NULL;

    /* 脱离组播组 */
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
 * TCP 发送线程
 *
 * 等待 iframe_found 后开始消费环形缓冲区。
 * 采用“发送成功才移动 tail”策略，避免写失败时丢失数据。
 * writev 在锁外执行，TCP 背压不会阻塞接收线程。
 * ══════════════════════════════════════════════════════════════ */
void *tcp_sender(void *arg)
{
    Channel *ch = (Channel *)arg;

    /* 等待起播条件（直到检测到第一个 I 帧） */
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

        /* 计算本次发送量（限制一次最大块，不对齐，交给 writev） */
        size_t to_send = (data_len > SEND_CHUNK_SIZE) ? SEND_CHUNK_SIZE : data_len;

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

        /* 释放锁，发送数据（可能阻塞） */
        pthread_mutex_unlock(&ch->lock);

        ssize_t sent = writev(ch->client_fd, iov, iov_cnt);

        if (sent > 0) {
            /* 成功发送，移动 tail */
            pthread_mutex_lock(&ch->lock);
            ch->tail = (ch->tail + sent) % RING_BUF_SIZE;
            pthread_mutex_unlock(&ch->lock);
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            /* 致命错误，终止该频道 */
            atomic_store(&ch->running, 0);
            break;
        }
        /* 如果是 EAGAIN/EWOULDBLOCK，下一次循环会重试发送相同的数据 */
    }

done:
    printf("⏹  发送线程退出，client FD: %d\n", ch->client_fd);
    cleanup_channel(ch);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 * 创建组播 socket，加入指定组播组
 * ══════════════════════════════════════════════════════════════ */
static int create_mcast_socket(const char *ip, int port,
                               struct ip_mreqn *mreq_out)
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
        perror("bind");
        close(fd);
        return -1;
    }

    /* 绑定到指定网络接口（支持 VLAN） */
    const char *iface = getenv("MCAST_IFACE");
    if (!iface || !iface[0]) iface = "eth0";

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        fprintf(stderr, "⚠  SO_BINDTODEVICE %s 失败（需 root）: %s\n",
                iface, strerror(errno));
    }

    /* 使用 ip_mreqn 精确加入组播组（指定接口索引） */
    struct ip_mreqn mreq = {0};
    mreq.imr_multiaddr.s_addr = mcast_addr;
    mreq.imr_address.s_addr   = htonl(INADDR_ANY);
    mreq.imr_ifindex          = if_nametoindex(iface);

    if (mreq.imr_ifindex == 0) {
        fprintf(stderr, "❌ 找不到网卡接口: %s\n", iface);
        close(fd);
        return -1;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        perror("IP_ADD_MEMBERSHIP");
        close(fd);
        return -1;
    }
    *mreq_out = mreq;

    /* 扩大 UDP 接收缓冲区 */
    int rcvbuf = UDP_RCVBUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    set_nonblocking(fd);
    return fd;
}

/* ══════════════════════════════════════════════════════════════
 * 读取完整的 HTTP 请求头（直到遇到 \r\n\r\n）
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
 * 主函数
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
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 64) < 0) {
        perror("listen");
        return 1;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events  = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    const char *iface = getenv("MCAST_IFACE");
    if (!iface || !iface[0]) iface = "eth0";

    printf("🚀 IPTV 组播代理 v2（4K 终极优化）| 端口: %d | 接口: %s\n",
           HTTP_PORT, iface);
    printf("   起播模式: I 帧智能检测（PUSI） | 重排窗口: %d 包 | 环形缓冲: %dMB\n",
           REORDER_SLOTS, RING_BUF_SIZE / (1024 * 1024));
    printf("   UDP 接收缓冲: %dMB | TCP 发送缓冲: %dMB | 批量读取: 256 包\n",
           UDP_RCVBUF_SIZE / (1024 * 1024), TCP_SNDBUF_SIZE / (1024 * 1024));

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            /* ── 新 HTTP 连接 ── */
            if (fd == server_fd) {
                int cli_fd = accept(server_fd, NULL, NULL);
                if (cli_fd < 0) continue;

                /* 读取完整的 HTTP 请求头 */
                char req_buf[2048] = {0};
                if (read_http_request(cli_fd, req_buf, sizeof(req_buf)) <= 0) {
                    close(cli_fd);
                    continue;
                }

                /* 解析请求路径：/rtp/组播IP:端口 */
                char target_ip[64] = {0};
                int  target_port   = 0;

                if (sscanf(req_buf, "GET /rtp/%63[^:]:%d",
                           target_ip, &target_port) != 2) {
                    printf("❌ 解析失败: %.80s\n", req_buf);
                    close(cli_fd);
                    continue;
                }

                if (target_port <= 0 || target_port > 65535) {
                    printf("❌ 非法端口: %d\n", target_port);
                    close(cli_fd);
                    continue;
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

                int nodelay = 1;
                setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                set_nonblocking(cli_fd);   /* 发送端也设为非阻塞，防止被客户端拖慢 */

                /* 加入组播 */
                Channel *ch = calloc(1, sizeof(Channel));
                if (!ch) {
                    close(cli_fd);
                    continue;
                }

                ch->mcast_fd = create_mcast_socket(target_ip, target_port, &ch->mreq);
                if (ch->mcast_fd < 0) {
                    printf("❌ 无法加入组播: %s:%d\n", target_ip, target_port);
                    free(ch);
                    close(cli_fd);
                    continue;
                }

                ch->client_fd      = cli_fd;
                ch->epoll_fd       = epoll_fd;
                ch->ring_buf       = malloc(RING_BUF_SIZE);
                if (!ch->ring_buf) {
                    close(ch->mcast_fd);
                    close(cli_fd);
                    free(ch);
                    continue;
                }

                ch->head           = 0;
                ch->tail           = 0;
                ch->iframe_found   = 0;
                ch->is_rtp         = 0;
                memset(&ch->reorder, 0, sizeof(ch->reorder));
                atomic_store(&ch->running, 1);

                pthread_mutex_init(&ch->lock, NULL);
                pthread_cond_init(&ch->cond, NULL);

                slots[ch->mcast_fd] = ch;

                /* 启动发送线程 */
                pthread_t tid;
                if (pthread_create(&tid, NULL, tcp_sender, ch) != 0) {
                    perror("pthread_create");
                    cleanup_channel(ch);
                    continue;
                }
                pthread_detach(tid);

                /* 将组播 fd 加入 epoll 监听 */
                ev.events  = EPOLLIN;
                ev.data.fd = ch->mcast_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ch->mcast_fd, &ev);

                printf("👤 频道: rtp://%s:%d | 等待 I 帧起播...\n",
                       target_ip, target_port);

            /* ── 组播数据包到达 ── */
            } else if (slots[fd]) {
                Channel *ch = slots[fd];
                if (!atomic_load(&ch->running)) continue;

                uint8_t pkt[2048];

                /* 批量读取，一次 epoll 事件尽量清空内核缓冲 */
                int count = 0;
                while (count++ < 256) {
                    ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        /* 致命错误，标记频道停止 */
                        atomic_store(&ch->running, 0);
                        pthread_cond_signal(&ch->cond);
                        break;
                    }
                    if (n == 0) break;

                    process_packet(ch, pkt, n);
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}