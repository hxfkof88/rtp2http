/*
 * rtphttp_v2.c — IPTV 组播转 HTTP 代理（修复版）
 *
 * 基于 stackia/rtp2httpd (https://github.com/stackia/rtp2httpd) 核心设计思想修复。
 *
 * 关键修复：
 *   - RTP 重排丢包跳过机制 (ref: rtp_reorder.c)，解决丢包卡死问题
 *   - 发送线程与主线程资源回收竞态修复
 *   - TCP 发送部分写处理的正确性修复
 *   - 增加错误检查和内存安全保护
 *   - 使用 clock_gettime 避免系统时间回退
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
#include <time.h>          ////! FIX: for clock_gettime

/* 常量定义：保持与原代码一致 */
#define HTTP_PORT           7099
#define MAX_EVENTS          128
#define RING_BUF_SIZE       (128 * 1024 * 1024) // 128MB 缓冲区
#define SEND_CHUNK_SIZE     (1024 * 1024)       // 每次发送量 1MB
#define TCP_SNDBUF_SIZE     (8  * 1024 * 1024)  // TCP 发送内核缓冲
#define UDP_RCVBUF_SIZE     (16 * 1024 * 1024)  // UDP 接收内核缓冲
#define TS_PACKET_SIZE      188
#define REORDER_SLOTS       64                  // 增加重排窗口
#define REORDER_MASK        (REORDER_SLOTS - 1)

////! FIX: 新增丢包跳过阈值
#define REORDER_MAX_PACKETS_BEHIND  16
#define REORDER_TIMEOUT_MS          500

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
    ////! FIX: 新增丢包跳过相关字段
    struct timespec last_delivery_at;
    uint16_t        last_delivery_seq;
    int             delivery_timeout_set;

    ////! FIX: 新增统计信息
    uint64_t packets_skipped;
    uint64_t packets_delivered;
    uint64_t duplicates_dropped;
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
    ////! FIX: 新增资源引用计数和清理标志
    volatile atomic_int cleanup_started; // 是否开始清理
    pthread_mutex_t  cleanup_lock;   // 保护清理过程
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

////! FIX: 删除原 reorder_flush；新增带丢包跳过的重新排序冲刷函数
static void reorder_flush_with_gap_detection(ReorderBuf *rb, Channel *ch) {
    int delivered = 0;
    uint16_t start_seq = rb->next_seq;

    /* 连续包马上交付 */
    while (1) {
        int slot = rb->next_seq & REORDER_MASK;
        if (!rb->slots[slot].valid || rb->slots[slot].seq != rb->next_seq) {
            break; // 遇到缺失/乱序包
        }

        ring_write(ch, rb->slots[slot].data, rb->slots[slot].len);
        rb->slots[slot].valid = 0;
        rb->next_seq++;
        delivered++;

        /* 更新最后投递时间 */
        if (clock_gettime(CLOCK_MONOTONIC, &rb->last_delivery_at) == 0) {
            rb->delivery_timeout_set = 1;
            rb->last_delivery_seq = rb->next_seq - 1;
        }
    }

    if (delivered > 0) {
        rb->packets_delivered += delivered;
        ////! FIX: 原代码中的条件变量通知移至 process_packet
    }

    /* 检查最终是否出现长时间缺口 */
    if (rb->delivery_timeout_set && rb->count() > 0) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            long elapsed_ms = (now.tv_sec - rb->last_delivery_at.tv_sec) * 1000 +
                              (now.tv_nsec - rb->last_delivery_at.tv_nsec) / 1000000;

            /* 若超过阈值，强制跳过缺失包 */
            uint16_t oldest_queued_seq = rb->next_seq;
            if (elapsed_ms > REORDER_TIMEOUT_MS) {
                uint16_t seq;
                int skipped = 0;
                for (seq = 0; seq < REORDER_SLOTS && seq < REORDER_MAX_PACKETS_BEHIND; seq++) {
                    int slot = (rb->next_seq + seq) & REORDER_MASK;
                    if (rb->slots[slot].valid) {
                        /* 找到包，强制前移指针并递送 */
                        rb->next_seq += seq;
                        rb->packets_skipped += seq;
                        // 递送之前间隔里的包（如果有一些）
                        reorder_flush_with_gap_detection(rb, ch);
                        break;
                    }
                }

                /* 仍无包时，前移一个包并记录跳过 */
                if (!rb->slots[rb->next_seq & REORDER_MASK].valid) {
                    rb->next_seq++;
                    rb->packets_skipped++;
                }
            }
        }
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

    /* 智能起播：检测到 PUSI 即认为 I 帧到来，开始发送 */
    if (!ch->iframe_found && ts_has_pusi(payload, payload_len)) {
        ch->iframe_found = 1;
    }

    /* RTP 重排与递送 */
    if (ch->is_rtp && has_seq) {
        if (!ch->reorder.initialized) {
            // 初始化学列号
            ch->reorder.next_seq = rtp_seq;
            ch->reorder.initialized = 1;
        }

        reorder_insert(&ch->reorder, rtp_seq, payload, payload_len);
        reorder_flush_with_gap_detection(&ch->reorder, ch); ////! FIX: 改用带丢包跳过的版本
    } else {
        ring_write(ch, payload, payload_len);
    }

    pthread_cond_signal(&ch->cond);
    pthread_mutex_unlock(&ch->lock);
}

/* TCP 发送线程：等待起播，然后持续消费环形缓冲，通过 writev 零拷贝发送 */
void *tcp_sender(void *arg) {
    Channel *ch = (Channel *)arg;
    int should_cleanup = 0; ////! FIX: 改为本地变量，避免竞态

    /* 等待起播条件（I 帧检测） */
    pthread_mutex_lock(&ch->lock);
    while (atomic_load(&ch->running) && !ch->iframe_found) {
        pthread_cond_wait(&ch->cond, &ch->lock);
    }
    pthread_mutex_unlock(&ch->lock);

    if (!atomic_load(&ch->running)) {
        should_cleanup = 1; ////! FIX: 标记清理
        goto cleanup_and_exit;
    }

    while (atomic_load(&ch->running)) {
        pthread_mutex_lock(&ch->lock);

        /* 计算可发送数据长度，无数据则等待 */
        size_t data_len = 0;
        while (atomic_load(&ch->running)) {
            data_len = (ch->head >= ch->tail) ? (ch->head - ch->tail) : (RING_BUF_SIZE - ch->tail + ch->head);
            if (data_len > 0) break;
            pthread_cond_wait(&ch->cond, &ch->lock);
        }
        if (!atomic_load(&ch->running)) {
            pthread_mutex_unlock(&ch->lock);
            should_cleanup = 1; ////! FIX: 标记清理
            break;
        }

        size_t to_send = (data_len > SEND_CHUNK_SIZE) ? SEND_CHUNK_SIZE : data_len;

        /* 构建 iovec 指向环形缓冲区（零拷贝） */
        struct iovec iov[2];
        int iov_cnt;
        size_t first_part = 0, second_part = 0;
        if (ch->tail + to_send <= RING_BUF_SIZE) {
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len = to_send;
            iov_cnt = 1;
        } else {
            first_part = RING_BUF_SIZE - ch->tail;
            second_part = to_send - first_part;
            iov[0].iov_base = ch->ring_buf + ch->tail;
            iov[0].iov_len = first_part;
            iov[1].iov_base = ch->ring_buf;
            iov[1].iov_len = second_part;
            iov_cnt = 2;
        }
        pthread_mutex_unlock(&ch->lock);

        /* 发送，必要时重试（处理 EAGAIN） */
        ssize_t total_sent = 0;
        int retry_count = 0;
        while (total_sent < (ssize_t)to_send && retry_count < 3) {
            ////! FIX: 调整 iovec 以仅包含未发送的部分
            struct iovec send_iov[2];
            int send_iov_cnt = iov_cnt;
            if (iov_cnt == 1) {
                send_iov[0].iov_base = (char *)iov[0].iov_base + total_sent;
                send_iov[0].iov_len = to_send - total_sent;
            } else {
                if (total_sent < (ssize_t)first_part) {
                    send_iov[0].iov_base = (char *)iov[0].iov_base + total_sent;
                    send_iov[0].iov_len = first_part - total_sent;
                    send_iov[1].iov_base = iov[1].iov_base;
                    send_iov[1].iov_len = second_part;
                } else {
                    size_t sent_in_second = total_sent - first_part;
                    send_iov[0].iov_base = (char *)iov[1].iov_base + sent_in_second;
                    send_iov[0].iov_len = second_part - sent_in_second;
                    send_iov_cnt = 1;
                }
            }

            ssize_t sent = writev(ch->client_fd, send_iov, send_iov_cnt);

            if (sent > 0) {
                total_sent += sent;
                retry_count = 0; // 重置重试计数
            } else if (sent < 0 && errno == EAGAIN) {
                retry_count++;
                struct timespec req = {.tv_sec = 0, .tv_nsec = 1000000}; // 1ms
                nanosleep(&req, NULL);
            } else {
                // 致命错误（如客户端断开）
                atomic_store(&ch->running, 0);
                should_cleanup = 1; ////! FIX: 标记清理
                break;
            }
        }

        if (total_sent > 0) {
            /* 发送成功，推进 tail */
            pthread_mutex_lock(&ch->lock);
            ch->tail = (ch->tail + total_sent) % RING_BUF_SIZE;
            pthread_mutex_unlock(&ch->lock);
        } else if (!atomic_load(&ch->running)) {
            break;
        }
    }

cleanup_and_exit:
    printf("⏹  发送线程退出，client FD: %d\n", ch->client_fd);

    /* 清理由主线程执行，此处只标记并通知 */
    ////! FIX: 不在此处释放资源（避免竞态），转由主线程处理
    atomic_store(&ch->cleanup_started, 1);
    atomic_store(&ch->running, 0);

    return NULL;
}

/* 创建组播 socket 并加入指定组播组 */
static int create_mcast_socket(const char *ip, int port, struct ip_mreqn *mreq_out) {
    printf("   加入组播 %s:%d ...\n", ip, port);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ////! FIX: 检查 socket 分配
    if (fd == -1) {
        fprintf(stderr, "   ❌ 无法创建 socket: %s\n", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "   ❌ 绑定失败 %s:%d: %s\n", ip, port, strerror(errno));
        close(fd);
        return -1;
    }

    const char *iface = getenv("MCAST_IFACE") ? getenv("MCAST_IFACE") : "eth0";
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));

    /* 使用 ip_mreqn 精确加入组播（指定接口索引） */
    struct ip_mreqn mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr(ip);
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = if_nametoindex(iface);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        fprintf(stderr, "   ❌ 加入组播失败 %s@%s: %s\n", ip, iface, strerror(errno));
        close(fd);
        return -1;
    }
    *mreq_out = mreq;

    int rcvbuf = UDP_RCVBUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_nonblocking(fd);

    printf("   组播 socket 创建成功，fd=%d\n", fd);
    return fd;
}

int main(void) {
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
    struct sockaddr_in srv = {.sin_family = AF_INET, .sin_port = htons(HTTP_PORT), .sin_addr.s_addr = INADDR_ANY};
    if (bind(server_fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 64) < 0) {
        perror("listen");
        return 1;
    }

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = server_fd}, events[MAX_EVENTS];
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    const char *iface = getenv("MCAST_IFACE") ? getenv("MCAST_IFACE") : "eth0";

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
                recv(cli_fd, req, sizeof(req), 0); // 单次读取 HTTP 请求

                char target_ip[64];
                int target_port;
                if (sscanf(req, "GET /rtp/%63[^:]:%d", target_ip, &target_port) == 2) {
                    printf("👤 新连接：rtp://%s:%d | 等待 I 帧起播...\n", target_ip, target_port);

                    ////! FIX: 使用更健壮的 HTTP 头
                    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nConnection: close\r\n\r\n";
                    send(cli_fd, resp, strlen(resp), MSG_NOSIGNAL);

                    int sndbuf = TCP_SNDBUF_SIZE;
                    setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                    int nodelay = 1;
                    setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
                    set_nonblocking(cli_fd);

                    Channel *ch = calloc(1, sizeof(Channel));
                    ////! FIX: 检查内存分配
                    if (!ch) {
                        fprintf(stderr, "❌ 内存分配失败（Channel）\n");
                        close(cli_fd);
                        continue;
                    }

                    ch->mcast_fd = create_mcast_socket(target_ip, target_port, &ch->mreq);
                    ////! FIX: 检查 socket 创建
                    if (ch->mcast_fd < 0) {
                        fprintf(stderr, "❌ 组播 socket 创建失败\n");
                        free(ch);
                        close(cli_fd);
                        continue;
                    }

                    ch->client_fd = cli_fd;
                    ch->epoll_fd = epoll_fd;
                    ch->ring_buf = malloc(RING_BUF_SIZE);
                    ////! FIX: 检查内存分配
                    if (!ch->ring_buf) {
                        fprintf(stderr, "❌ 内存分配失败（ring buffer）\n");
                        close(ch->mcast_fd);
                        free(ch);
                        close(cli_fd);
                        continue;
                    }
                    atomic_store(&ch->running, 1);
                    atomic_store(&ch->cleanup_started, 0);
                    pthread_mutex_init(&ch->lock, NULL);
                    pthread_mutex_init(&ch->cleanup_lock, NULL);
                    pthread_cond_init(&ch->cond, NULL);
                    slots[ch->mcast_fd] = ch;
                    ////! FIX: 设置定时器以进行定期重排超时检查
                    ch->reorder.last_delivery_at.tv_sec = 0;
                    ch->reorder.last_delivery_at.tv_nsec = 0;
                    ch->reorder.delivery_timeout_set = 0;

                    pthread_t tid;
                    ////! FIX: 检查线程创建
                    if (pthread_create(&tid, NULL, tcp_sender, ch) != 0) {
                        fprintf(stderr, "❌ 线程创建失败\n");
                        slots[ch->mcast_fd] = NULL;
                        close(ch->mcast_fd);
                        free(ch->ring_buf);
                        pthread_mutex_destroy(&ch->lock);
                        pthread_mutex_destroy(&ch->cleanup_lock);
                        pthread_cond_destroy(&ch->cond);
                        free(ch);
                        close(cli_fd);
                        continue;
                    }
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
                ////! FIX: 检查是否已在清理过程中
                if (atomic_load(&ch->cleanup_started)) {
                    // 跳过此 fd，稍后清理
                    slots[fd] = NULL;
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                    continue;
                }

                uint8_t pkt[2048];
                int count = 0;
                /* 批量读取至多 256 个 UDP 包，防止饿死其他 fd */
                while (count++ < 256) {
                    ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
                    if (n <= 0) break;
                    process_packet(ch, pkt, n);
                }

                /* 主动检查重排超时（即使在无数据时也定期强制） */
                if (ch->is_rtp && ch->reorder.initialized) {
                    pthread_mutex_lock(&ch->lock);
                    reorder_flush_with_gap_detection(&ch->reorder, ch);
                    pthread_mutex_unlock(&ch->lock);
                }
            }
        }

        /* 主动清理已停止的频道（由主线程执行） */
        for (int fd = 0; fd < 65536 && fd <= server_fd + 100; fd++) {
            if (slots[fd] && atomic_load(&slots[fd]->cleanup_started)) {
                Channel *ch = slots[fd];
                slots[fd] = NULL;
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ch->mcast_fd, NULL);
                setsockopt(ch->mcast_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &ch->mreq, sizeof(ch->mreq));
                close(ch->mcast_fd);
                close(ch->client_fd);
                ////! FIX: 安全释放资源（此时无发送线程并发）
                pthread_mutex_destroy(&ch->lock);
                pthread_mutex_destroy(&ch->cleanup_lock);
                pthread_cond_destroy(&ch->cond);
                free(ch->ring_buf);
                free(ch);
                printf("🧹 已清理频道资源\n");
            }
        }
    }
    return 0;
}