#pragma once
#include <pcap.h>
#include <iostream>
#include <vector>
#include "PacketHeaders.h"
#include "../Utils/Utils.h"

class Packet {
public:
	Packet(const pcap_pkthdr* pkthdr, const u_char* packet, pcap_if* nic);
	~Packet();
public:
	bool IsIPv4();
	bool IsICMP();

	bool IsSent();

	std::string GetProtocol() const;
	bpf_u_int32 GetPacketSize() const;

	std::string GetIpDest() const;
	std::string GetIpSrc() const;


public:

	inline std::time_t GetTimestamp() const { return m_timestamp; }
	inline const u_char* GetPacket() const { return m_packet; }

public:
	inline const null_hdr* GetLoopbackNull() const { return m_loopbackNull; }
	inline const ether_hdr* GetEthHeader() const { return m_ethHeader; }
	inline const ipv4_hdr* GetIpv4Header() const { return m_ipv4Header; }
	inline const ipv6_hdr* GetIpv6Header() const { return m_ipv6Header; }
	inline const tcp_hdr* GetTcpHeader() const { return m_tcpHeader; }
	inline const udp_hdr* GetUdpHeader() const { return m_udpHeader; }
	inline const icmp_hdr* GetIcmpHeader() const { return m_icmpHeader; }

private:
	bool ProcessPacket();
private:
	pcap_pkthdr m_pkthdr;
	pcap_if* m_nicPkt;
	const u_char* m_packet = nullptr;

	std::time_t m_timestamp;

private:
	const null_hdr* m_loopbackNull = nullptr;
	const ether_hdr* m_ethHeader = nullptr;
	const ipv4_hdr* m_ipv4Header = nullptr;
	const ipv6_hdr* m_ipv6Header = nullptr;
	const tcp_hdr* m_tcpHeader = nullptr;
	const udp_hdr* m_udpHeader = nullptr;
	const icmp_hdr* m_icmpHeader = nullptr;
private:
	std::string m_Protocol = "";
	u_char* m_ProtocolPayload = nullptr;
};