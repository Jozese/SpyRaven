#pragma once
#include "../Gui/App.h"
#include "../Packet/Packet.h"
#include <pcap.h>

#include <unordered_map>

class NetworkInterfaceManager {
public:
	NetworkInterfaceManager(std::shared_ptr<Logger> ptrLogger);
	~NetworkInterfaceManager();
public:
	std::mutex m_pktMux;
public:
	inline std::unordered_map<std::string, pcap_if*>& GetInterfaces() { return m_mapInterfaces; }
	inline std::unordered_map<int, std::unique_ptr<Packet>>& GetPackets() { return m_packets; }

private:
	std::shared_ptr<Logger> m_ptrLogger;
private:
	pcap_if_t* m_alldevs;
	
public:
	static 	char s_errbuf[PCAP_ERRBUF_SIZE];

private:
	std::unordered_map<std::string, pcap_if*> m_mapInterfaces;
	std::unordered_map<int, std::unique_ptr<Packet>> m_packets;

};