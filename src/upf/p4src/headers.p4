#include <core.p4>
#include <tna.p4>

#include "settings.p4"

typedef bit<10>                       port_queue_id_t;

typedef bit<48>                       mac_addr_t;
typedef bit<32>                       ipv4_addr_t;
typedef bit<128>                      ipv6_addr_t;
typedef bit<32>                       teid_t;
typedef bit<SHORT_TEID_BITS>          short_teid_t;
typedef bit<26>                       seid_t;
typedef bit<6>                        qfi_t;
typedef bit<COMPRESSED_QFI_BITS>      compressed_qfi_t;
typedef bit<13>                       nexthop_id_t;
typedef bit<MA_ID_BITS>               ma_id_t;
typedef bit<QER_ID_BITS>              qer_id_t;


typedef bit<4>      header_type_t;
typedef bit<4>      header_info_t;

#define DETECTION_TRIGGER 0x8876


typedef bit<DOMAIN_WATCHER_ID_BITS> domain_watcher_id_t;

header detection_trigger_h {
    domain_watcher_id_t                 index;
    bit<(32 - DOMAIN_WATCHER_ID_BITS)>  result;
}

const header_type_t HEADER_TYPE_BRIDGE    = 0xB;
const header_type_t HEADER_TYPE_IG_MIRROR = 0xC;
const header_type_t HEADER_TYPE_EG_MIRROR = 0xC;

const header_info_t HEADER_INFO_FLOW_KEY_REPORTING = 0xA;
const header_info_t HEADER_INFO_OFFPATH_DETECTION = 0xB;
const MirrorId_t    MIRROR_SESSION_FLOW_KEY_REPORTING = 1;
const MirrorId_t    MIRROR_SESSION_OFFPATH_DETECTION = 2;

const MirrorType_t  EG_MIRROR_TYPE_SIMPLE_COPY = 1;

#define INTERNAL_HEADER \
    header_type_t header_type; \
	header_info_t header_info

header internal_header_h {
	INTERNAL_HEADER;
}

header ethernet_h {
	mac_addr_t dst;
	bit<32> src_part1;
	bit<16> src_part2;
	bit<16> etherType;
}

header arp_h {
	bit<16>      h_type;
	bit<16>      p_type;
	bit<8>       h_len;
	bit<8>       p_len;
	bit<16>      op_code;
	mac_addr_t   src_mac;
	ipv4_addr_t  src_ip;
	mac_addr_t   dst_mac;
	ipv4_addr_t  dst_ip;
}

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPE_TO_CPU = 0x1145;

const bit<16> ARP_HTYPE = 0x0001; //Ethernet Hardware type is 1
const bit<16> ARP_PTYPE = TYPE_IPV4; //Protocol used for ARP is IPV4
const bit<8>  ARP_HLEN  = 6; //Ethernet address size is 6 bytes
const bit<8>  ARP_PLEN  = 4; //IP address size is 4 bytes
const bit<16> ARP_REQ = 1; //Operation 1 is request
const bit<16> ARP_REPLY = 2; //Operation 2 is reply

header ipv4_h {
	bit<4>       version;
	bit<4>       ihl;
	bit<8>       diffserv;
	bit<16>      totalLen;
	bit<16>      identification;
	bit<3>       flags;
	bit<13>      fragOffset;
	bit<8>       ttl;
	bit<8>       protocol;
	bit<16>      hdrChecksum;
	bit<32>      srcAddr;
	bit<32>      dstAddr;
}

header ipv4_options_h {
	varbit<320>  options;
}

header ipv6_h {
	bit<4>   version;
	bit<8>   trafficClass;
	bit<20>  flowLabel;
	bit<16>  payloadLen;
	bit<8>   nextHdr;
	bit<8>   hopLimit;
	bit<128> srcAddr;
	bit<128> dstAddr;
}

header udp_h {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> len;
	bit<16> checksum;
}



header dns_h {
    bit<16> id;
    bit<1> qr;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> truncation;
    bit<1> rec_desired;
    bit<1> rec_avail;
    bit<3> reserved;
    bit<4> resp_code;
    bit<16> qdcount;
    bit<16> ancount;
    bit<16> nscount;
    bit<16> arcount;
}

header dns_e {
    bit<8>  lenstop;
    bit<16> qtype;
    bit<16> qclass;
}

header dns_a {
    bit<16> pointer;
    bit<16> type;
    bit<16> clas;
    bit<32> ttl;
    bit<16> rdlength;
}

header dns_a_r {
    bit<32> res;
}

header dns_char {
    bit<8>   c;
}

header dns_len {
    bit<8>   l;
}


header dns_label_1 {
    bit<8>  l;
}

header dns_label_2 {
    bit<16>  l;
}

header dns_label_4 {
    bit<32>  l;
}

header dns_label_8 {
    bit<64>  l;
}

header dns_label_16 {
    bit<128>  l;
}



header tcp_h {
	bit<16>      srcPort;
	bit<16>      dstPort;
	bit<32>      seqNo;
	bit<32>      ackNo;
	bit<4>       dataOffset;
	bit<3>       res;
	bit<3>       ecn;
	bit<6>       ctrl;
	bit<16>      window;
	bit<16>      checksum;
	bit<16>      urgentPtr;
}

header tcp_options_h {
	varbit<320>  options;
}

header tcp_or_udp_port_h {
	bit<16> srcPort;
	bit<16> dstPort;
}

header gtpu_h {
	bit<3>	version;
	bit<1>	protocolType; //  GTP (when PT is '1') and GTP' (when PT is '0')
	bit<1>	spare;
	bit<1>	extensionHeaderFlag;
	bit<1>	sequenceNumberFlag;
	bit<1>	npduNumberFlag;
	bit<8>	messageType;
	bit<16>	payloadLength;
	teid_t	teid;
}

header gtpu_optional_h {
	bit<16>	sequenceNumber;
	bit<8>	npduNumber;
	bit<8>	nextExtensionHeaderType;
}

header gtpu_ext_field_1_h {
	bit<8>	content;
}

header gtpu_ext_field_3_h {
	bit<24>	content;
}

header gtpu_ext_field_4_h {
	bit<32>	content;
}

header gtpu_ext_field_8_h {
	bit<64>	content;
}

header gtpu_ext_field_padding_h {
	varbit<24>	content;
}

struct gtpu_psc_dl_mandatory_t {
	bit<4>				pduType;
	bit<1>				qmp;
	bit<1>				snp;
	bit<2>				_spare1;
	bit<1>				ppp;
	bit<1>				rqi;
	qfi_t				qfi;
}

struct gtpu_psc_dl_t {
	gtpu_psc_dl_mandatory_t	hdr;
	gtpu_ext_field_1_h	ppi;
	gtpu_ext_field_8_h	dlSendingTimestamp;
	gtpu_ext_field_3_h	dlQfiSequenceNumber;
	gtpu_ext_field_padding_h	_padding;
}

struct gtpu_psc_ul_mandatory_t {
	bit<4>				pduType;
	bit<1>				qmp;
	bit<1>				dlDelayInd;
	bit<1>				ulDelayInd;
	bit<1>				snp;
	bit<1>				n3n9DelayInd;
	bit<1>				newIeFlag;
	qfi_t				qfi;
}

struct gtpu_psc_ul_t {
	gtpu_psc_ul_mandatory_t hdr;
	gtpu_ext_field_8_h	dlSendingTimestampRepeated;
	gtpu_ext_field_8_h	dlReceivedTimestamp;
	gtpu_ext_field_8_h	ulSendingTimestamp;
	gtpu_ext_field_4_h	dlDelayResult;
	gtpu_ext_field_4_h	ulDelayResult;
	gtpu_ext_field_3_h	ulQfiSequenceNumber;
	gtpu_ext_field_4_h	n3n9DelayResult;
	gtpu_ext_field_1_h	newIE;
	gtpu_ext_field_1_h	d1UlPDCPDelayResultInd;
	gtpu_ext_field_padding_h	_padding;
}

struct gtpu_psc_t_old {
	gtpu_ext_field_1_h	hdrLength;
	gtpu_psc_dl_t 		psc_dl;
	gtpu_psc_ul_t 		psc_ul;
	gtpu_ext_field_1_h	nextExtensionHeaderType;
}

header gtpu_ext_psc_h {
	bit<8>				extHdrLength;
	bit<4>				pduType;
	bit<6>				dontCare;
	qfi_t				qfi;
}

header gtpu_ext_psc_optional_h {
	varbit<384>			content;
}

enum bit<3> upf_traffic_class_t {
	HIGH_PRIORITY = 0b00,
	OTHER_GBR     = 0b01,
	DC_NON_GBR    = 0b100, // delay crtical non-gbr
	BEST_EFFORT   = 0b10,
	SCAVENGER     = 0b11
}

enum bit<4> upf_traffic_decision_t {
	UL_DECAP_TO_DN   = 0b0000, // to N6
	UL_FORWARD       = 0b0001, // to N9
	UL_FORWARD_RE    = 0b0010, // to N9, RE for remove ext header
	UL_FORWARD_IP    = 0b1001, // to N9, Inter-PLMN
	UL_FORWARD_IP_RE = 0b1010, // to N9, Inter-PLMN, RE for remove ext header
	DL_ENCAP         = 0b0011, // to N9 or N3, but encap
	DL_FORWARD       = 0b0100, // to N9 or N3, no encap
	HO_FORWARDING    = 0b0101, // from N3 back to N3, need to change ext header from UL to DL
	BUFFER           = 0b0110, // send to buffer port
	TO_CP            = 0b0111, // send to CP port
	DROP             = 0b1000, // drop
	DROP_AND_RECORD  = 0b1001  // drop and record how many are dropped, used for reporting
}


header ing_to_egr_data_h {
	INTERNAL_HEADER;
	ma_id_t      ma_id;
	bit<1>       mirror;
	bit<1>       is_downlink;
	bit<6>       padding;
}

header cpu_header_h {
	bit<8>          cpu_header_magic; // = CPU_HEADER_MAGIC
	bit<8>          flags;
	//bit<5>          padding;
	bit<32>         ma_id;
}

const int IPV4_HOST_TABLE_SIZE = 1024;
const int IPV4_LPM_TABLE_SIZE  = 512;

const int IPV6_HOST_TABLE_SIZE = 64;
const int IPV6_LPM_TABLE_SIZE  = 64;


struct ig_metadata_t {
	bool 		recirc;
	
	bit<9> 		rnd_port_for_recirc;
	bit<1> 		rnd_bit;

	bool		error_parsing;
	bool 		uplink; // 0 for DL
	qfi_t		tunnel_qfi;
	bit<(MA_ID_BITS - COMPRESSED_QFI_BITS)>      extracted_teid;

	bit<16>		overlay_length; // include both IP and L4 and rest of payload
	bit<16>     total_pkt_length; // size of the entire packet
	
	// overlay
	bit<8>      l4_protocol;
	bit<16>     l4_src_port;
	bit<16>     l4_dst_port;
	bit<16>     l4_payload_checksum;

	bit<8>      individual_gbr_meter_color;


    ma_id_t    ma_id;
    qfi_t       qfi;
    teid_t      teid;

	bool         drop;
	bool         buffer;
	bool         nocp;
	bool         mark_tos;
	bit<8>       tos;
	nexthop_id_t nexthop;
	qer_id_t     qer_id;
}

struct ig_header_t {
	ing_to_egr_data_h       bridge;
	ethernet_h				ethernet;
	arp_h                   arp;
	cpu_header_h            cpu_header;
	detection_trigger_h     detection_trigger;
	ipv4_h 					underlay_ipv4;
	ipv4_options_h			underlay_ipv4_options;
	ipv6_h 					underlay_ipv6;
	udp_h 					underlay_udp;
	gtpu_h 					gtpu;
	gtpu_optional_h			gtpu_optional;
	gtpu_ext_psc_h 			gtpu_ext_psc;
	gtpu_ext_psc_optional_h	gtpu_ext_psc_optional;
	gtpu_ext_field_1_h		gtpu_ext_psc_next_header_type; // not set during parsing, only used during encap
	ipv4_h 					overlay_ipv4;
	ipv4_options_h			overlay_ipv4_options;
	ipv6_h 					overlay_ipv6;
	tcp_h  					overlay_tcp;
	udp_h  					overlay_udp;

	dns_h                               dns;

    
    dns_len                             len1;
    dns_label_16                     label1_16;
    dns_label_8                     label1_8;
    dns_label_4                     label1_4;
    dns_label_2                     label1_2;
    dns_label_1                     label1_1;
    dns_len                             len2;
    dns_label_16                     label2_16;
    dns_label_8                     label2_8;
    dns_label_4                     label2_4;
    dns_label_2                     label2_2;
    dns_label_1                     label2_1;
    dns_len                             len3;
    dns_label_16                     label3_16;
    dns_label_8                     label3_8;
    dns_label_4                     label3_4;
    dns_label_2                     label3_2;
    dns_label_1                     label3_1;
    dns_len                             len4;
    dns_label_16                     label4_16;
    dns_label_8                     label4_8;
    dns_label_4                     label4_4;
    dns_label_2                     label4_2;
    dns_label_1                     label4_1;

    dns_e                               dns_extra;
}



struct eg_metadata_t {
	ing_to_egr_data_h       bridge;
    header_type_t           mirror_hdr_type;
    header_info_t           mirror_hdr_info;
    MirrorId_t              mirror_session;
	bool                    flow_key_reporting_packet;
	bool                    offpath_detection_packet;
}

header eg_mirror_header_flow_key_reporting_h {
	INTERNAL_HEADER;
}

header eg_mirror_header_offpath_detection_h {
	INTERNAL_HEADER;
}

struct eg_headers_t {
	ethernet_h              ethernet;
	arp_h                   arp;
	cpu_header_h            cpu_header;
	detection_trigger_h     detection_trigger;
	ipv4_h 					underlay_ipv4;
	ipv4_options_h			underlay_ipv4_options;
	ipv6_h 					underlay_ipv6;
	udp_h 					underlay_udp;
	gtpu_h 					gtpu;
	gtpu_optional_h			gtpu_optional;
	gtpu_ext_psc_h 			gtpu_ext_psc;
	gtpu_ext_psc_optional_h	gtpu_ext_psc_optional;
	gtpu_ext_field_1_h		gtpu_ext_psc_next_header_type; // not set during parsing, only used during encap
	ipv4_h 					overlay_ipv4;
	ipv4_options_h			overlay_ipv4_options;
	ipv6_h 					overlay_ipv6;
	tcp_h  					overlay_tcp;
	udp_h  					overlay_udp;

	dns_h                               dns;

    
    dns_len                             len1;
    dns_label_16                     label1_16;
    dns_label_8                     label1_8;
    dns_label_4                     label1_4;
    dns_label_2                     label1_2;
    dns_label_1                     label1_1;
    dns_len                             len2;
    dns_label_16                     label2_16;
    dns_label_8                     label2_8;
    dns_label_4                     label2_4;
    dns_label_2                     label2_2;
    dns_label_1                     label2_1;
    dns_len                             len3;
    dns_label_16                     label3_16;
    dns_label_8                     label3_8;
    dns_label_4                     label3_4;
    dns_label_2                     label3_2;
    dns_label_1                     label3_1;
    dns_len                             len4;
    dns_label_16                     label4_16;
    dns_label_8                     label4_8;
    dns_label_4                     label4_4;
    dns_label_2                     label4_2;
    dns_label_1                     label4_1;

    dns_e                               dns_extra;
}

