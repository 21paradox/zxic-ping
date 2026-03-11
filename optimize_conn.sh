#!/bin/sh
# 4G USB WiFi 盒子极致优化脚本
# 适用于内存 < 128MB 的嵌入式设备

echo "=== 应用极致网络优化 ==="

# # 1. Conntrack 最终压缩（基于你已优化的，再压一半）
# echo 4096 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max
# #echo 512  > /proc/sys/net/ipv4/netfilter/ip_conntrack_buckets
# # echo 30   > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established
# # echo 5    > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait

# # 2. TCP 内存极致压缩（省出 2-4MB 内存）
# echo "256 512 768" > /proc/sys/net/ipv4/tcp_mem          # 原 648 865 1296
# echo "4096 8192 16384" > /proc/sys/net/ipv4/tcp_rmem     # 原 4096 87380 225536  
# echo "4096 8192 16384" > /proc/sys/net/ipv4/tcp_wmem     # 原 4096 16384 225536
# echo 128 > /proc/sys/net/ipv4/tcp_max_orphans            # 原 512，孤儿连接
# echo 128 > /proc/sys/net/ipv4/tcp_max_tw_buckets         # 原 512，TIME_WAIT
# echo 64  > /proc/sys/net/ipv4/tcp_max_syn_backlog        # 原 128，半连接队列
# echo 5   > /proc/sys/net/ipv4/tcp_fin_timeout            # 原 15，FIN 回收
# echo 60  > /proc/sys/net/ipv4/tcp_keepalive_time         # 原 300，保活探测间隔
# echo 3   > /proc/sys/net/ipv4/tcp_keepalive_probes       # 原 9，探测次数
# echo 2   > /proc/sys/net/ipv4/tcp_syn_retries            # 原 5，SYN 重试
# echo 2   > /proc/sys/net/ipv4/tcp_synack_retries         # 原 5，SYNACK 重试

# # 3. ARP/邻居表大幅削减（每个条目省 ~256B，50 个设备省 12KB+）
# echo 64  > /proc/sys/net/ipv4/neigh/default/gc_thresh1   # 原 128，最小保留
# echo 128 > /proc/sys/net/ipv4/neigh/default/gc_thresh2   # 原 512，开始回收
# echo 256 > /proc/sys/net/ipv4/neigh/default/gc_thresh3   # 原 1024，强制回收
# echo 15  > /proc/sys/net/ipv4/neigh/default/base_reachable_time  # 原 30，ARP 有效期减半
# echo 30  > /proc/sys/net/ipv4/neigh/default/gc_stale_time        # 原 60，过期回收

# # 4. 路由表极限精简
# echo 16384 > /proc/sys/net/ipv4/route/max_size            # 原 16384，路由缓存条目
# echo 256  > /proc/sys/net/ipv4/route/gc_thresh           # 原 1024
# echo 60   > /proc/sys/net/ipv4/route/gc_timeout          # 原 300，5分钟改1分钟

# # 5. UDP 内存压缩
# # echo "256 512 768" > /proc/sys/net/ipv4/udp_mem          # 原 660 881 1320
# # echo 1024 > /proc/sys/net/ipv4/udp_rmem_min              # 原 4096
# # echo 1024 > /proc/sys/net/ipv4/udp_wmem_min              # 原 4096

# echo "512 1024 1500" > /proc/sys/net/ipv4/udp_mem          # 原 660 881 1320
# echo 4096 > /proc/sys/net/ipv4/udp_rmem_min              # 原 4096
# echo 4096 > /proc/sys/net/ipv4/udp_wmem_min              # 原 4096

# # 6. IP 分片重组内存砍半（4G 通常不需要大包重组）
# # echo 65536  > /proc/sys/net/ipv4/ipfrag_low_thresh       # 原 196608 (192KB→64KB)
# # echo 81920  > /proc/sys/net/ipv4/ipfrag_high_thresh      # 原 262144 (256KB→80KB)
# # echo 10     > /proc/sys/net/ipv4/ipfrag_time             # 原 30 秒，快速回收

# echo 196608  > /proc/sys/net/ipv4/ipfrag_low_thresh       # 原 196608 (192KB→64KB)
# echo 262144  > /proc/sys/net/ipv4/ipfrag_high_thresh      # 原 262144 (256KB→80KB)
# echo 30     > /proc/sys/net/ipv4/ipfrag_time             # 原 30 秒，快速回收

# # 7. 其他杂项精简
# echo 5   > /proc/sys/net/ipv4/igmp_max_memberships       # 原 20，组播成员
# echo 8192 > /proc/sys/net/ipv4/inet_peer_threshold       # 原 32832，路由 peer 缓存

# # 8. 接口级队列深度削减（减少每个接口的内存占用）
# for iface in usblan0 wlan0 br0; do
#     [ -d "/proc/sys/net/ipv4/neigh/$iface" ] && {
#         echo 8 > /proc/sys/net/ipv4/neigh/$iface/unres_qlen       # 原 34
#         echo 8192 > /proc/sys/net/ipv4/neigh/$iface/unres_qlen_bytes  # 原 65536
#         echo 16 > /proc/sys/net/ipv4/neigh/$iface/proxy_qlen      # 原 64
#     }
# done



echo "=== 开始极致优化 ==="

# ========== 1. IP 分片重组（之前导致速度跳动，已修正）==========
# 保持最低安全值，避免再砍
echo 131072 > /proc/sys/net/ipv4/ipfrag_low_thresh      # 128KB（原256KB砍半）
echo 196608 > /proc/sys/net/ipv4/ipfrag_high_thresh     # 192KB（原262KB减70KB）
echo 20     > /proc/sys/net/ipv4/ipfrag_time            # 20秒（原30秒，留余量）

# echo 196608  > /proc/sys/net/ipv4/ipfrag_low_thresh       # 原 196608 (192KB→64KB)
# echo 262144  > /proc/sys/net/ipv4/ipfrag_high_thresh      # 原 262144 (256KB→80KB)
# echo 30     > /proc/sys/net/ipv4/ipfrag_time             # 原 30 秒，快速回收

# ========== 2. TCP 内存极致压缩（省出 4-8MB）==========
# 全局内存：从 2.5MB/3.4MB/5MB 压到 1MB/2MB/3MB
echo "256 512 768" > /proc/sys/net/ipv4/tcp_mem

# 单连接缓冲：从 225KB 压到 32KB，100连接省 19MB
echo "4096 8192 32768" > /proc/sys/net/ipv4/tcp_rmem
echo "4096 8192 32768" > /proc/sys/net/ipv4/tcp_wmem

# 孤儿连接：512 -> 64，防止内存泄漏
echo 64 > /proc/sys/net/ipv4/tcp_max_orphans

# TIME_WAIT 桶：512 -> 128，快速回收端口
echo 128 > /proc/sys/net/ipv4/tcp_max_tw_buckets

# 半连接队列：128 -> 64，防SYN Flood同时省内存
echo 64 > /proc/sys/net/ipv4/tcp_max_syn_backlog

# FIN 等待：15 -> 5 秒，加速回收
echo 15 > /proc/sys/net/ipv4/tcp_fin_timeout

# ========== 3. TCP 保活与重传（适应4G网络）==========
# 保活间隔：300 -> 60 秒，更快发现死连接
echo 60 > /proc/sys/net/ipv4/tcp_keepalive_time

# 探测次数：9 -> 3 次，更快踢掉
echo 3 > /proc/sys/net/ipv4/tcp_keepalive_probes

# 重试次数：5 -> 2 次，4G网络要么通要么不通，重试多了没用
echo 5 > /proc/sys/net/ipv4/tcp_syn_retries
echo 5 > /proc/sys/net/ipv4/tcp_synack_retries

# 关闭慢启动重启（省CPU，4G网络波动大，慢启动反而拖慢）
echo 0 > /proc/sys/net/ipv4/tcp_slow_start_after_idle

# ========== 4. 路由表精简（省内存）==========
echo 4096 > /proc/sys/net/ipv4/route/max_size           # 16384 -> 4096
echo 256  > /proc/sys/net/ipv4/route/gc_thresh          # 1024 -> 256
echo 60   > /proc/sys/net/ipv4/route/gc_timeout         # 300 -> 60秒

# ========== 5. ARP/邻居表压缩（每个条目256B，50设备省12KB）==========
echo 64  > /proc/sys/net/ipv4/neigh/default/gc_thresh1  # 128 -> 64
echo 128 > /proc/sys/net/ipv4/neigh/default/gc_thresh2  # 512 -> 128
echo 256 > /proc/sys/net/ipv4/neigh/default/gc_thresh3  # 1024 -> 256

# ARP 有效期：30 -> 15 秒，加速过期回收
echo 15 > /proc/sys/net/ipv4/neigh/default/base_reachable_time

# ========== 6. UDP 内存压缩 ==========
echo "256 512 768" > /proc/sys/net/ipv4/udp_mem         # 660/881/1320 -> 256/512/768
echo 2048 > /proc/sys/net/ipv4/udp_rmem_min             # 4096 -> 2048
echo 2048 > /proc/sys/net/ipv4/udp_wmem_min             # 4096 -> 2048


# ========== 7. 杂项精简 ==========
echo 5   > /proc/sys/net/ipv4/igmp_max_memberships      # 20 -> 5，组播成员
echo 8192 > /proc/sys/net/ipv4/inet_peer_threshold      # 32832 -> 8192，路由peer
echo 300 > /proc/sys/net/ipv4/inet_peer_maxttl          # 600 -> 300，peer缓存TTL减半

# ========== 8. ICMP 限速（防攻击+省CPU）==========
echo 100 > /proc/sys/net/ipv4/icmp_ratelimit            # 1000 -> 100
echo 1   > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts  # 保持1，防Smurf


# 极值精简覆写脚本 - 基于当前 kernel 配置
# 目标：最大化性能，移除所有安全/调试限制

echo "=== Kernel 核心参数覆写 ==="

# 1. 禁用所有地址空间随机化 (ASLR) - 提升性能，当前为2
echo 0 > /proc/sys/kernel/randomize_va_space

# 2. 禁用 Oops 触发 Panic - 提升稳定性，当前为1
echo 0 > /proc/sys/kernel/panic_on_oops

# 3. 禁用 Core Dump - 节省存储空间，当前为"core"
echo "|/bin/false" > /proc/sys/kernel/core_pattern
echo 0 > /proc/sys/kernel/core_uses_pid

# 4. 最大化日志静默 - 减少IO，当前为"7 4 1 7"
echo "1 1 1 1" > /proc/sys/kernel/printk

# 5. 禁用 SysRq 键（可选，保留1用于紧急情况调试，改为0完全禁用）
echo 0 > /proc/sys/kernel/sysrq

# 6. 降低线程上限 - 当前753，对于嵌入式改为256足够
echo 256 > /proc/sys/kernel/threads-max

# 7. 降低消息队列 - 当前32768/47，精简为1024/16节省内存
echo 4096 > /proc/sys/kernel/msgmnb
echo 96 > /proc/sys/kernel/msgmni

echo "=== VM 内存管理覆写 ==="

# 8. OOM 时不panic，直接杀死进程
echo 0 > /proc/sys/vm/panic_on_oom

# 9. 最小保留内存 - 当前未显示，嵌入式设为512KB足够
echo 2048 > /proc/sys/vm/min_free_kbytes

echo "=== 实时内核(RT)特定优化 ==="

# 17. 禁用实时调度限制（当前 sched_rt_runtime_us = -1 已是无限制，保持）
# echo -1 > /proc/sys/kernel/sched_rt_runtime_us

# 18. 降低 timer 频率相关的开销（如果支持）
echo 200000 > /proc/sys/kernel/sched_rt_period_us

echo "覆写完成"




# ========== 9. MTU 优化（治本，避免分片）==========
# 设置4G网络最优MTU，减少分片处理开销
# for iface in usblan0 usb0 eth1; do
#     if [ -d "/sys/class/net/$iface" ]; then
#         ip link set dev $iface mtu 1420 2>/dev/null || \
#         ifconfig $iface mtu 1420 2>/dev/null
#         echo "Set $iface MTU to 1420"
#     fi
# done
