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

target_compile_options(aegiscore PRIVATE
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    $<$<NOT:$<CONFIG:Debug>>:-DNDEBUG>
    $<$<NOT:$<CONFIG:Debug>>:-flto>
)

target_link_options(aegiscore PRIVATE
    -Wl,--gc-sections
    $<$<NOT:$<CONFIG:Debug>>:-flto>
)

find_library(log-lib log)

target_link_libraries(aegiscore ${log-lib})