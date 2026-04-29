#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#define HTTP_PORT 1997
#define MAX_EVENTS 128
#define RING_BUF_SIZE (8 * 1024 * 1024) // 8MB 缓冲
#define PRECACHE_THRESHOLD (1 * 1024 * 1024) // 1MB 预缓存防线

typedef struct {
    int mcast_fd;
    int client_fd;
    uint8_t *ring_buf;
    size_t head;
    size_t tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int running;
} Channel;

Channel* slots[65536];

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 专职发送线程：负责把数据推向电视
void* tcp_sender(void* arg) {
    Channel* ch = (Channel*)arg;
    uint8_t* tmp_send_buf = malloc(128 * 1024);
    int is_precached = 0;

    while (ch->running) {
        pthread_mutex_lock(&ch->lock);

        size_t data_len = 0;
        while (ch->running) {
            if (ch->head >= ch->tail) {
                data_len = ch->head - ch->tail;
            } else {
                data_len = RING_BUF_SIZE - ch->tail + ch->head;
            }

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

        if (!ch->running) { pthread_mutex_unlock(&ch->lock); break; }

        size_t to_send = (data_len > 65536) ? 65536 : data_len;

        if (ch->tail + to_send <= RING_BUF_SIZE) {
            memcpy(tmp_send_buf, ch->ring_buf + ch->tail, to_send);
        } else {
            size_t first_part = RING_BUF_SIZE - ch->tail;
            memcpy(tmp_send_buf, ch->ring_buf + ch->tail, first_part);
            memcpy(tmp_send_buf + first_part, ch->ring_buf, to_send - first_part);
        }

        ch->tail = (ch->tail + to_send) % RING_BUF_SIZE;
        pthread_mutex_unlock(&ch->lock);

        if (send(ch->client_fd, tmp_send_buf, to_send, MSG_NOSIGNAL) <= 0) {
            ch->running = 0;
            break;
        }
    }
    free(tmp_send_buf);
    printf("⏹️ 发送线程退出，电视端断开连接，FD: %d\n", ch->client_fd);
    return NULL;
}

int create_mcast_socket(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    // ========== 唯一修改：支持 eth0.45 (VLAN 接口) ==========
    // 原代码硬编码为 "eth1"，现改为从环境变量 MCAST_IFACE 读取，
    // 若未设置则默认使用 "eth0.45"
    const char *iface = getenv("MCAST_IFACE");
    if (!iface) iface = "eth0.45";

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr));
    // ========== 修改结束 ==========

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_nonblocking(fd);
    return fd;
}

int main() {
    int epoll_fd = epoll_create1(0);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in srv_addr = {0};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = INADDR_ANY;
    srv_addr.sin_port = htons(HTTP_PORT);
    bind(server_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    listen(server_fd, 64);

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    printf("🚀 终极 IPTV 组播代理 (自动剥离 RTP 头) 启动 | 端口: %d\n", HTTP_PORT);

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == server_fd) {
                int cli_fd = accept(server_fd, NULL, NULL);
                if (cli_fd < 0) continue;

                char req_buf[1024] = {0};
                ssize_t req_len = recv(cli_fd, req_buf, sizeof(req_buf) - 1, 0);
                if (req_len <= 0) {
                    close(cli_fd); continue;
                }

                char protocol[16] = {0};
                char target_ip[32] = {0};
                int target_port = 0;

                // 兼容解析 /udp/ip:port 或 /rtp/ip:port
                if (sscanf(req_buf, "GET /%15[^/]/%15[^:]:%d", protocol, target_ip, &target_port) != 3) {
                    printf("❌ 解析地址失败或格式错误\n");
                    close(cli_fd); continue;
                }

                send(cli_fd, "HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nConnection: close\r\n\r\n", 63, MSG_NOSIGNAL);

                Channel* ch = calloc(1, sizeof(Channel));
                ch->mcast_fd = create_mcast_socket(target_ip, target_port);

                if (ch->mcast_fd < 0) {
                    printf("❌ 无法加入组播: %s:%d\n", target_ip, target_port);
                    free(ch); close(cli_fd); continue;
                }

                ch->client_fd = cli_fd;
                ch->ring_buf = malloc(RING_BUF_SIZE);
                ch->running = 1;
                pthread_mutex_init(&ch->lock, NULL);
                pthread_cond_init(&ch->cond, NULL);

                slots[ch->mcast_fd] = ch;

                pthread_t tid;
                pthread_create(&tid, NULL, tcp_sender, ch);
                pthread_detach(tid);

                ev.events = EPOLLIN;
                ev.data.fd = ch->mcast_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ch->mcast_fd, &ev);
                printf("👤 频道接入: %s://%s:%d | 状态: 预缓存中...\n", protocol, target_ip, target_port);

            } else if (slots[fd]) {
                Channel* ch = slots[fd];
                uint8_t pkt[65536];

                while (1) {
                    ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    if (n == 0) break;

                    // 【终极修复：RTP 智能剥离逻辑】
                    size_t payload_offset = 0;
                    size_t payload_len = n;

                    // 判断是否为标准 MPEG-TS (首字节为 0x47)
                    if (n >= 188 && pkt[0] == 0x47) {
                        payload_offset = 0;
                    }
                    // 检查是否为 RTP 报文 (版本 V=2, 即 10xxxxxx 二进制)
                    else if (n > 12 && (pkt[0] & 0xC0) == 0x80) {
                        int cc = pkt[0] & 0x0F;         // CSRC 计数
                        int x = (pkt[0] & 0x10) >> 4;   // 扩展标志
                        payload_offset = 12 + cc * 4;   // 基础 RTP 头 12 字节 + CSRC

                        // 跳过 RTP 扩展头
                        if (x && n >= payload_offset + 4) {
                            int ext_len = (pkt[payload_offset + 2] << 8) | pkt[payload_offset + 3];
                            payload_offset += 4 + ext_len * 4;
                        }

                        // 二次校验剥离 RTP 头后，是否露出了真实的 MPEG-TS (0x47) 同步字
                        if (payload_offset < n && pkt[payload_offset] == 0x47) {
                            payload_len = n - payload_offset;
                        } else {
                            // 校验失败，可能是未知私有协议，不剥离原样放行
                            payload_offset = 0;
                            payload_len = n;
                        }
                    }

                    pthread_mutex_lock(&ch->lock);

                    size_t free_space = (ch->tail > ch->head) ?
                                        (ch->tail - ch->head - 1) :
                                        (RING_BUF_SIZE - ch->head + ch->tail - 1);

                    if (payload_len <= free_space) {
                        // 只将剥离头部的纯净有效载荷 (payload) 写入环形缓冲区
                        if (ch->head + payload_len <= RING_BUF_SIZE) {
                            memcpy(ch->ring_buf + ch->head, pkt + payload_offset, payload_len);
                        } else {
                            size_t first = RING_BUF_SIZE - ch->head;
                            memcpy(ch->ring_buf + ch->head, pkt + payload_offset, first);
                            memcpy(ch->ring_buf, pkt + payload_offset + first, payload_len - first);
                        }
                        ch->head = (ch->head + payload_len) % RING_BUF_SIZE;
                        pthread_cond_signal(&ch->cond);
                    }

                    pthread_mutex_unlock(&ch->lock);
                }
            }
        }
    }
    return 0;
}