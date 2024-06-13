#include "Packet.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS




Packet::Packet(const pcap_pkthdr* pkthdr, const u_char* packet, pcap_if* nic): m_nicPkt(nic)
{
    m_pkthdr = *pkthdr;

    m_packet = new u_char[pkthdr->len];
    std::memcpy((u_char*)m_packet, packet, pkthdr->len);

    m_timestamp = std::time(0);

    ProcessPacket();
    
}

bool Packet::ProcessPacket()
{   
    uint8_t ipProtocol;
    ETHER_TYPES eType;
    IP_PROTOCOL_NUMBERS pNum;

    m_loopbackNull = (struct null_hdr*)m_packet;
    m_ethHeader = (struct ether_hdr*)m_packet;

    u_char* payload;

    size_t totalHeaderLength = 0;

    if (m_loopbackNull->family == 0x18 || m_loopbackNull->family == 0x02) {
        
        m_ethHeader = nullptr;

        totalHeaderLength += sizeof(struct null_hdr);
        payload = (u_char*)(m_packet + sizeof(struct null_hdr));

        switch (m_loopbackNull->family)
        {

        case 0x02: m_Protocol = "IPv4";  totalHeaderLength += sizeof(struct ipv4_hdr);  eType = IPV4; m_ipv4Header = (struct ipv4_hdr*)payload; payload += sizeof(struct ipv4_hdr); break;
        case 0x18: m_Protocol = "IPv6";  totalHeaderLength += sizeof(struct ipv6_hdr);  eType = IPV6; m_ipv6Header = (struct ipv6_hdr*)payload; payload += sizeof(struct ipv6_hdr); break;
        default: eType = UNK; break;

        }
    }
    else
    {
        m_loopbackNull = nullptr;
        totalHeaderLength += sizeof(struct ether_hdr);
        payload = (u_char*)(m_packet + sizeof(struct ether_hdr));

        switch (ntohs(m_ethHeader->ether_type))
        {

        case IPV4: m_Protocol = "IPv4"; totalHeaderLength += sizeof(struct ipv4_hdr); eType = IPV4; m_ipv4Header = (struct ipv4_hdr*)payload; payload += sizeof(struct ipv4_hdr); break;
        case IPV6: m_Protocol = "IPv6"; totalHeaderLength += sizeof(struct ipv4_hdr); eType = IPV6; m_ipv6Header = (struct ipv6_hdr*)payload; payload += sizeof(struct ipv6_hdr); break;
        default: eType = UNK; break;

        }
    }

    
    if (eType == UNK)
        return false;

    if (eType == IPV4)
        ipProtocol = m_ipv4Header->protocol;
    else
        ipProtocol = m_ipv6Header->next_header;
    

    switch (ipProtocol)
    {
    case TCP:  m_Protocol = "TCP";  totalHeaderLength += sizeof(struct tcp_hdr); pNum = TCP;    m_tcpHeader = (struct tcp_hdr*)payload;   payload += sizeof(struct tcp_hdr);    break;
    case UDP:  m_Protocol = "UDP";  totalHeaderLength += sizeof(struct udp_hdr); pNum = UDP;    m_udpHeader = (struct udp_hdr*)payload;   payload += sizeof(struct udp_hdr);    break;
    case ICMP: m_Protocol = "ICMP"; totalHeaderLength += sizeof(struct icmp_hdr); pNum = ICMP;  m_icmpHeader = (struct icmp_hdr*)payload; payload += sizeof(struct icmp_hdr);   break;
    default: pNum = IP_UNK; break;
        
    }

    if (m_pkthdr.caplen - totalHeaderLength > 0) {
        m_ProtocolPayload = new u_char[m_pkthdr.caplen - totalHeaderLength];
        std::memcpy(m_ProtocolPayload, payload, m_pkthdr.caplen - totalHeaderLength);
    }


    if (pNum == IP_UNK)
        return false;
    return true;

}

std::string Packet::GetProtocol() const
{
    return this->m_Protocol;
}

bpf_u_int32 Packet::GetPacketSize() const
{
    return this->m_pkthdr.len;
}

std::string Packet::GetIpDest() const
{
    std::string ret;

    if (m_ipv4Header) {

        struct sockaddr_in addr_in;
        memset(&addr_in, 0, sizeof(sockaddr_in));

        addr_in.sin_family = AF_INET;
        addr_in.sin_addr.s_addr = (m_ipv4Header->dest_ip);

        ret = Utils::SockaddrToPair((sockaddr*)&addr_in).second;
        
    }
    else if (m_ipv6Header) {
        struct sockaddr_in6 addr_in;
        memset(&addr_in, 0, sizeof(sockaddr_in6));

        addr_in.sin6_family = AF_INET6;
        memcpy(&addr_in.sin6_addr, m_ipv6Header->dest_addr, sizeof(m_ipv6Header->dest_addr));

        ret = Utils::SockaddrToPair((sockaddr*)&addr_in).second;
    }
        
    return ret;
}

std::string Packet::GetIpSrc() const
{
    std::string ret;

    if (m_ipv4Header) {

        struct sockaddr_in addr_in;
        memset(&addr_in, 0, sizeof(sockaddr_in));

        addr_in.sin_family = AF_INET;
        addr_in.sin_addr.s_addr = (m_ipv4Header->source_ip);

        ret = Utils::SockaddrToPair((sockaddr*)&addr_in).second;

    }
    else if (m_ipv6Header) {
        struct sockaddr_in6 addr_in;
        memset(&addr_in, 0, sizeof(sockaddr_in6));

        addr_in.sin6_family = AF_INET6;
        memcpy(&addr_in.sin6_addr, m_ipv6Header->src_addr, sizeof(m_ipv6Header->src_addr));

        ret = Utils::SockaddrToPair((sockaddr*)&addr_in).second;
    }

    return ret;
}

bool Packet::IsIPv4()
{
    if (m_ipv4Header)
        return true;
    return false;
}

bool Packet::IsICMP()
{
    if (m_icmpHeader)
        return true;
    return false;
}

bool Packet::IsSent()
{
    if (m_nicPkt && m_nicPkt->addresses &&  m_nicPkt->addresses->addr->sa_family == AF_INET && m_ipv4Header) {

        struct sockaddr_in* sa_in = reinterpret_cast<struct sockaddr_in*>(m_nicPkt->addresses->addr);

        uint32_t packetSourceIp = ntohl(m_ipv4Header->source_ip);
        uint32_t interfaceSourceIp = ntohl(sa_in->sin_addr.s_addr);

        if (packetSourceIp == interfaceSourceIp) {
            return true;
        }
    }
    else if (m_nicPkt && m_nicPkt->addresses && m_nicPkt->addresses->addr->sa_family == AF_INET6 && m_ipv6Header) {

        struct sockaddr_in6* sa_in = reinterpret_cast<struct sockaddr_in6*>(m_nicPkt->addresses->addr);

        if (memcmp(&m_ipv6Header->src_addr, &sa_in->sin6_addr, sizeof(struct in6_addr)) == 0) {
            return true;
        }
    }
    return false;
}

Packet::~Packet()
{
    delete[] m_packet;
    delete[] m_ProtocolPayload;
}
