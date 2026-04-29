/*
 * rtphttp.c — 终极 IPTV 组播转 HTTP 代理（优化版）
 *
 * 优化清单：
 *  1. [BUG修复] Channel 生命周期管理：断线后完整清理 epoll/slots/内存
 *  2. [BUG修复] running 标志改为 volatile + 原子操作，消除竞态条件
 *  3. [性能]    writev() 零拷贝发送，消除 tmp_send_buf 一次 memcpy
 *  4. [性能]    发送批量从 64KB 提升至 256KB，减少系统调用次数
 *  5. [性能]    SO_SNDBUF 调大至 2MB + TCP_CORK 减少小包
 *  6. [健壮性]  inet_addr() 返回值校验，拒绝非法 IP
 *  7. [可移植]  网络接口名通过 MCAST_IFACE 环境变量配置（默认 eth0）
 *  8. [安全]    sscanf 格式字符串宽度与缓冲区声明对齐
 *  9. [健壮性]  HTTP 请求循环读取，确保收到完整 \r\n\r\n
 * 10. [健壮性]  epoll_fd 传入 Channel，供清理线程使用
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/uio.h>      /* writev */
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>    /* atomic_int */

/* ── 配置常量 ─────────────────────────────────────────────── */
#define HTTP_PORT           1997
#define MAX_EVENTS          128
#define RING_BUF_SIZE       (8  * 1024 * 1024)   /* 8MB 环形缓冲 */
#define PRECACHE_THRESHOLD  (1  * 1024 * 1024)   /* 1MB 预缓存门槛 */
#define SEND_CHUNK_SIZE     (256 * 1024)          /* 每次最多发 256KB（原64KB）*/
#define SNDBUF_SIZE         (2  * 1024 * 1024)   /* TCP 发送缓冲 2MB */
#define RCVBUF_SIZE         (4  * 1024 * 1024)   /* UDP 接收缓冲 4MB */

/* ── Channel 结构体 ──────────────────────────────────────── */
typedef struct {
    int              mcast_fd;
    int              client_fd;
    int              epoll_fd;               /* [新增] 供清理时使用 */

    /* 组播信息，断线时用于 IP_DROP_MEMBERSHIP */
    struct ip_mreq   mreq;

    uint8_t         *ring_buf;
    size_t           head;                   /* 写指针（主线程写） */
    size_t           tail;                   /* 读指针（发送线程读）*/

    pthread_mutex_t  lock;
    pthread_cond_t   cond;

    volatile atomic_int running;             /* [修复] 原子标志位 */
} Channel;

/* slots[] 以 mcast_fd 为下标，存 Channel 指针 */
Channel *slots[65536];

/* ── 工具函数 ─────────────────────────────────────────────── */
static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ── Channel 清理（在发送线程退出时调用）────────────────── */
static void cleanup_channel(Channel *ch)
{
    /* 从 epoll 移除组播 fd */
    epoll_ctl(ch->epoll_fd, EPOLL_CTL_DEL, ch->mcast_fd, NULL);

    /* 从 slots 表清除（先置 NULL 再 close，防止主线程再次进入）*/
    slots[ch->mcast_fd] = NULL;

    /* 离开组播组，释放路由器状态 */
    setsockopt(ch->mcast_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
               &ch->mreq, sizeof(ch->mreq));

    close(ch->mcast_fd);
    close(ch->client_fd);
    free(ch->ring_buf);
    pthread_mutex_destroy(&ch->lock);
    pthread_cond_destroy(&ch->cond);
    free(ch);
}

/* ── 发送线程：writev 零拷贝推送 ────────────────────────── */
/*
 * [优化3] 使用 writev() + iovec[2] 直接从环形缓冲区发送，
 *         完全消除原来的 tmp_send_buf 中间拷贝。
 * [优化4] SEND_CHUNK_SIZE 从 64KB 提升至 256KB。
 * [优化1] 退出前调用 cleanup_channel() 完整释放资源。
 */
void *tcp_sender(void *arg)
{
    Channel *ch = (Channel *)arg;
    int is_precached = 0;

    while (atomic_load(&ch->running)) {
        pthread_mutex_lock(&ch->lock);

        /* 等待缓冲区数据满足发送条件 */
        size_t data_len = 0;
        while (atomic_load(&ch->running)) {
            if (ch->head >= ch->tail)
                data_len = ch->head - ch->tail;
            else
                data_len = RING_BUF_SIZE - ch->tail + ch->head;

            if (!is_precached) {
                if (data_len >= PRECACHE_THRESHOLD) {
                    is_precached = 1;
                    break;
                }
            } else {
                if (data_len > 0) break;
            }
            pthread_cond_wait(&ch->cond, &ch->lock);
        }

        if (!atomic_load(&ch->running)) {
            pthread_mutex_unlock(&ch->lock);
            break;
        }

        /* 本次发送量（最多 SEND_CHUNK_SIZE） */
        size_t to_send = (data_len > SEND_CHUNK_SIZE) ? SEND_CHUNK_SIZE : data_len;

        /* [优化3] 构造 iovec，直接指向环形缓冲区，无需 memcpy */
        struct iovec iov[2];
        int iov_cnt;

        if (ch->tail + to_send <= RING_BUF_SIZE) {
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len  = to_send;
            iov_cnt = 1;
        } else {
            size_t first = RING_BUF_SIZE - ch->tail;
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len  = first;
            iov[1].iov_base = ch->ring_buf;
            iov[1].iov_len  = to_send - first;
            iov_cnt = 2;
        }

        /* 先移动 tail，再解锁，让主线程尽快继续写入 */
        ch->tail = (ch->tail + to_send) % RING_BUF_SIZE;
        pthread_mutex_unlock(&ch->lock);

        /* writev 在锁外执行，不阻塞组播接收 */
        ssize_t sent = writev(ch->client_fd, iov, iov_cnt);
        if (sent <= 0) {
            atomic_store(&ch->running, 0);
            break;
        }
    }

    printf("⏹️  发送线程退出，FD: %d\n", ch->client_fd);
    cleanup_channel(ch);   /* [修复1] 完整清理 */
    return NULL;
}

/* ── 创建组播套接字 ──────────────────────────────────────── */
/*
 * [优化7] 网络接口名从环境变量 MCAST_IFACE 读取，默认 eth0。
 * [优化1] mreq 写入 Channel，供断线时 IP_DROP_MEMBERSHIP 使用。
 */
static int create_mcast_socket(const char *ip, int port, struct ip_mreq *mreq_out)
{
    /* [安全] 提前校验 IP 合法性 */
    in_addr_t mcast_addr = inet_addr(ip);
    if (mcast_addr == INADDR_NONE) {
        fprintf(stderr, "❌ 非法组播 IP: %s\n", ip);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

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

    /* [优化7] 接口名可配置 */
    const char *iface = getenv("MCAST_IFACE");
    if (!iface || iface[0] == '\0') iface = "eth0";

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   (char *)&ifr, sizeof(ifr)) < 0) {
        fprintf(stderr, "⚠️  SO_BINDTODEVICE %s 失败（可能需要 root）: %s\n",
                iface, strerror(errno));
    }

    struct ip_mreq mreq = {0};
    mreq.imr_multiaddr.s_addr = mcast_addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("IP_ADD_MEMBERSHIP");
        close(fd);
        return -1;
    }

    /* 保存 mreq，供断线清理用 */
    *mreq_out = mreq;

    int rcvbuf = RCVBUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_nonblocking(fd);
    return fd;
}

/* ── HTTP 请求读取（循环读到 \r\n\r\n）──────────────────── */
/*
 * [优化9] 原始代码单次 recv 可能收不全请求头，
 *         此处循环读取直到看到空行或缓冲区满。
 */
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

/* ── main ────────────────────────────────────────────────── */
int main(void)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); return 1; }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in srv_addr = {0};
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_addr.s_addr = INADDR_ANY;
    srv_addr.sin_port        = htons(HTTP_PORT);

    if (bind(server_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 64) < 0) {
        perror("listen"); return 1;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events   = EPOLLIN;
    ev.data.fd  = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    const char *iface = getenv("MCAST_IFACE");
    if (!iface || iface[0] == '\0') iface = "eth0";

    printf("🚀 IPTV 组播代理（优化版）启动 | 端口: %d | 接口: %s\n",
           HTTP_PORT, iface);

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

                /* [优化9] 循环读取完整 HTTP 请求 */
                char req_buf[2048] = {0};
                ssize_t req_len = read_http_request(cli_fd, req_buf, sizeof(req_buf));
                if (req_len <= 0) { close(cli_fd); continue; }

                /* [安全/优化8] 格式字符串宽度与缓冲区对齐 */
                char protocol[16]  = {0};
                char target_ip[64] = {0};
                int  target_port   = 0;

                /* 兼容 /udp/ip:port 和 /rtp/ip:port */
                if (sscanf(req_buf,
                           "GET /%15[^/]/%63[^:]:%d",
                           protocol, target_ip, &target_port) != 3) {
                    printf("❌ 解析地址失败: %.80s\n", req_buf);
                    close(cli_fd);
                    continue;
                }

                /* [优化6] 校验端口范围 */
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

                /* [优化5] 调大 TCP 发送缓冲 + TCP_CORK */
                int sndbuf = SNDBUF_SIZE;
                setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                int cork = 1;
                setsockopt(cli_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

                /* 创建 Channel */
                Channel *ch = calloc(1, sizeof(Channel));
                if (!ch) { close(cli_fd); continue; }

                ch->mcast_fd = create_mcast_socket(target_ip, target_port, &ch->mreq);
                if (ch->mcast_fd < 0) {
                    printf("❌ 无法加入组播: %s:%d\n", target_ip, target_port);
                    free(ch);
                    close(cli_fd);
                    continue;
                }

                ch->client_fd = cli_fd;
                ch->epoll_fd  = epoll_fd;         /* [修复1] 传入 epoll_fd */
                ch->ring_buf  = malloc(RING_BUF_SIZE);
                if (!ch->ring_buf) {
                    close(ch->mcast_fd); close(cli_fd); free(ch); continue;
                }
                ch->head    = 0;
                ch->tail    = 0;
                atomic_store(&ch->running, 1);    /* [修复2] 原子写 */
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

                /* 注册组播 fd 到 epoll */
                ev.events  = EPOLLIN;
                ev.data.fd = ch->mcast_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ch->mcast_fd, &ev);

                printf("👤 频道接入: %s://%s:%d | 预缓存 %dMB...\n",
                       protocol, target_ip, target_port,
                       PRECACHE_THRESHOLD / (1024 * 1024));

            /* ── 组播数据可读 ── */
            } else if (slots[fd]) {
                Channel *ch = slots[fd];

                /* [修复2] 若发送线程已停，跳过继续写入 */
                if (!atomic_load(&ch->running)) continue;

                uint8_t pkt[65536];

                while (1) {
                    ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        /* 其他错误，停止频道 */
                        atomic_store(&ch->running, 0);
                        pthread_cond_signal(&ch->cond);
                        break;
                    }
                    if (n == 0) break;

                    /* ── RTP 智能剥离逻辑（与原版相同）── */
                    size_t payload_offset = 0;
                    size_t payload_len    = (size_t)n;

                    /* 标准 MPEG-TS：首字节 0x47 */
                    if (n >= 188 && pkt[0] == 0x47) {
                        payload_offset = 0;

                    /* RTP 封装：版本 V=2，即 10xxxxxx */
                    } else if (n > 12 && (pkt[0] & 0xC0) == 0x80) {
                        int cc = pkt[0] & 0x0F;
                        int x  = (pkt[0] & 0x10) >> 4;
                        payload_offset = 12 + cc * 4;

                        /* 跳过 RTP 扩展头 */
                        if (x && (size_t)n >= payload_offset + 4) {
                            int ext_len =
                                ((int)pkt[payload_offset + 2] << 8) |
                                 (int)pkt[payload_offset + 3];
                            payload_offset += 4 + ext_len * 4;
                        }

                        /* 二次校验：剥离后首字节应为 0x47 */
                        if (payload_offset < (size_t)n &&
                            pkt[payload_offset] == 0x47) {
                            payload_len = (size_t)n - payload_offset;
                        } else {
                            /* 未知格式，原样放行 */
                            payload_offset = 0;
                            payload_len    = (size_t)n;
                        }
                    }

                    /* ── 写入环形缓冲区 ── */
                    pthread_mutex_lock(&ch->lock);

                    size_t free_space = (ch->tail > ch->head)
                        ? (ch->tail - ch->head - 1)
                        : (RING_BUF_SIZE - ch->head + ch->tail - 1);

                    if (payload_len <= free_space) {
                        if (ch->head + payload_len <= RING_BUF_SIZE) {
                            memcpy(ch->ring_buf + ch->head,
                                   pkt + payload_offset, payload_len);
                        } else {
                            size_t first = RING_BUF_SIZE - ch->head;
                            memcpy(ch->ring_buf + ch->head,
                                   pkt + payload_offset, first);
                            memcpy(ch->ring_buf,
                                   pkt + payload_offset + first,
                                   payload_len - first);
                        }
                        ch->head = (ch->head + payload_len) % RING_BUF_SIZE;
                        pthread_cond_signal(&ch->cond);
                    }
                    /* 若空间不足，丢弃本包（缓冲区满，客户端消费过慢）*/

                    pthread_mutex_unlock(&ch->lock);
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}
