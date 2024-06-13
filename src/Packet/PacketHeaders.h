#pragma once
#include <stdint.h>

struct ether_hdr {
    uint8_t dest_mac[6]; 

    uint8_t src_mac[6];    

    uint16_t ether_type;    
};

struct FourBitStruct {
    unsigned int value : 4;
};

struct ipv4_hdr {

    uint8_t version_ihl;

    uint8_t type_of_service;

    uint16_t total_length;

    uint16_t identification;

    uint16_t flags_fragment_offset;

    uint8_t ttl;

    uint8_t protocol;

    uint16_t header_checksum;

    uint32_t source_ip;

    uint32_t dest_ip;

};

struct ipv6_hdr {
    uint32_t ver_tc_fl; 

    uint16_t payload_len;  

    uint8_t next_header;   

    uint8_t hop_limit;     

    uint8_t src_addr[16];   

    uint8_t dest_addr[16];  
};

struct tcp_hdr {
    uint16_t src_port; 

    uint16_t dest_port;  

    uint32_t seq_num;    

    uint32_t ack_num;    

    uint8_t data_offset;   

    uint8_t flags;   

    uint16_t window_size;   

    uint16_t checksum;  

    uint16_t urgent_ptr;    
};

struct udp_hdr {
    uint16_t src_port;   

    uint16_t dest_port;  

    uint16_t length;     

    uint16_t checksum;      
};

struct icmp_hdr {
    uint8_t type;  

    uint8_t code;  

    uint16_t checksum;  

    uint16_t id;      

    uint16_t sequence;   
};

struct null_hdr {
    uint32_t family; 
};

enum ETHER_TYPES {
    UNK = 0x0000,
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
};

enum IP_PROTOCOL_NUMBERS {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
    IP_UNK = 0xff,
};