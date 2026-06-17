# 143a077ftcp - Malware Analysis

ELF 64-bit x86-64 后门程序（RAT Dropper）的反编译分析。

## 基本信息

| 项目 | 值 |
|------|-----|
| 源文件名 | `linux_amd64_tcp.c` |
| 架构 | ELF 64-bit LSB, x86-64 |
| 编译器 | GCC 4.9.4 |
| 符号表 | 未剥离 (not stripped) |
| 大小 | ~8KB |

## 行为流程

```
启动
 ├─ 检查 /tmp/log_de.log 是否存在 → 存在则 exit(0)（自杀开关）
 ├─ 连接 C2: 24.144.123.109:20480（失败每 10s 重试）
 ├─ 握手协议
 │   ├─ 发送 6 字节版本标识 "l64   "
 │   ├─ 发送 2 字节端口号（大端序）
 │   └─ 发送 32 字节 IP 标识
 ├─ memfd_create("a") → 创建匿名内存 fd
 ├─ 接收循环
 │   ├─ recv() 从 socket 读取
 │   ├─ XOR 0x99 逐字节解密
 │   └─ write() 写入 memfd
 └─ 执行载荷
     ├─ realpath(argv[0]) → setenv("CWD", ...)
     └─ fexecve(mem_fd, "[kworker/0:2]", environ)
```

## 关键技术

- **无文件执行**: `memfd_create`(syscall 319) + `fexecve` — 载荷完全在内存中运行，不落盘
- **XOR 加密**: 载荷使用单字节 XOR `0x99` 加密传输
- **进程伪装**: argv[0] 设为 `[kworker/0:2]`，伪装为内核工作线程
- **自杀开关**: `/tmp/log_de.log` 存在时自行退出
- **连接重试**: TCP 连接失败时每 10 秒无限重试
- **TCP Keepalive**: 设置 `TCP_KEEPIDLE = 10s`

## 使用的系统调用/API

| API | 用途 |
|-----|------|
| `socket` / `connect` | TCP 连接 C2 |
| `send` / `recv` | 通信 |
| `setsockopt` (TCP_KEEPIDLE) | 保活 |
| `gethostbyname` / `inet_addr` | DNS 解析 |
| `syscall(319)` = `memfd_create` | 创建匿名内存文件 |
| `write` | 将解密后的载荷写入 memfd |
| `fexecve` | 从内存 fd 执行 ELF |
| `realpath` / `setenv` | 设置 CWD 环境变量 |
| `access` | 检查自杀标记文件 |
| `sleep` | 连接重试间隔 |

## 文件说明

| 文件 | 说明 |
|------|------|
| `143a077ftcp` | 原始 ELF 二进制样本 |
| `143a077ftcp_decompiled.c` | 反编译还原的 C 源码 |

## 免责声明

本仓库仅用于安全研究和教育目的。
