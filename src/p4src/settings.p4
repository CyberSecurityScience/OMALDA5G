
#define MA_ID_BITS 24
#define QER_ID_BITS 16
#define DOMAIN_WATCHER_ID_BITS 18
#define SHORT_TEID_BITS 18
#define COMPRESSED_QFI_BITS 2

#define NUM_QFI 5
#define NUM_PORT 5

#define DOMAIN_WATCHER_SIZE 1024 * 8 # 124
#define DOMAIN_WATCHER_DOMAINS 8192
#define DOMAIN_WATCHER_MODELS 2

#define TABLE_SIZE_UL_N6_SIMPLE_IPV4 1024 * 124
#define TABLE_SIZE_UL_N6_COMPLEX_IPV4 1024 * 4

#define TABLE_SIZE_UL_N9_SIMPLE_IPV4 1024 * 2
#define TABLE_SIZE_UL_N9_COMPLEX_IPV4 512 * 4


#define TABLE_SIZE_DL_N6_SIMPLE_IPV4 1024 * 124
#define TABLE_SIZE_DL_N6_COMPLEX_IPV4 1024 * 4

#define TABLE_SIZE_DL_N9_SIMPLE_IPV4 (TABLE_SIZE_UL_N9_SIMPLE_IPV4 + TABLE_SIZE_UL_N9_COMPLEX_IPV4)

#define TABLE_SIZE_ACCOUNTING ( \
    TABLE_SIZE_DL_N6_SIMPLE_IPV4 + \
    TABLE_SIZE_DL_N6_COMPLEX_IPV4 + \
    TABLE_SIZE_DL_N9_SIMPLE_IPV4 + \
    TABLE_SIZE_UL_N6_SIMPLE_IPV4 + \
    TABLE_SIZE_UL_N6_COMPLEX_IPV4 + \
    TABLE_SIZE_UL_N9_SIMPLE_IPV4 + \
    TABLE_SIZE_UL_N9_COMPLEX_IPV4 \
)

#define TABLE_SIZE_IPV4_LPM 512

#define PORT_BUFFER 134
#define PORT_CPU 64

#define N6_MAC_MAPPING 16w0xb17d: parse_overlay; // src MAC xx:xx:xx:xx:b1:7d for N6 interface
#define UPF_MAC 48w0x000c2980b582

#define CPU_HEADER_MAGIC 114
