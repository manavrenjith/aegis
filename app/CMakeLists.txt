cmake_minimum_required(VERSION 3.22.1)
project(aegiscore)

add_library(
    aegiscore
    SHARED
    src/main/jni/aegiscore/aegiscore.c
    src/main/jni/aegiscore/tcp.c
    src/main/jni/aegiscore/udp.c
    src/main/jni/aegiscore/icmp.c
    src/main/jni/aegiscore/dns.c
    src/main/jni/aegiscore/dhcp.c
    src/main/jni/aegiscore/pcap.c
    src/main/jni/aegiscore/session.c
    src/main/jni/aegiscore/tls.c
    src/main/jni/aegiscore/ip.c
    src/main/jni/aegiscore/util.c
)

find_library(log-lib log)

target_link_libraries(aegiscore ${log-lib})