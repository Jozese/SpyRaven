#pragma once
#include <imgui/imgui.h>
#include <iostream>
#include <string>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <map>
#include <sstream>
#include <vector>
#include <unordered_map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


struct ScrollingBuffer {
	int MaxSize;
	int Offset;
	ImVector<ImVec2> Data;
	ScrollingBuffer(int max_size = 10000) {
		MaxSize = max_size;
		Offset = 0;
		Data.reserve(MaxSize);
	}
	void AddPoint(float x, float y) {
		if (Data.size() < MaxSize)
			Data.push_back(ImVec2(x, y));
		else {
			Data[Offset] = ImVec2(x, y);
			Offset = (Offset + 1) % MaxSize;
		}
	}
	void Erase() {
		if (Data.size() > 0) {
			Data.shrink(0);
			Offset = 0;
		}
	}
};

static void print_mac_address(const uint8_t* mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static std::string macAddrToString(const uint8_t* macAddr) {
	
	if (!macAddr) 
		return "";
	
	char buffer[18]; 

	std::snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
		macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);

	return std::string(buffer);
}


namespace Utils {
	static std::pair<ADDRESS_FAMILY,std::string> SockaddrToPair(sockaddr* addr) {

		char addrStr[INET6_ADDRSTRLEN];
		ADDRESS_FAMILY a;

		if (addr->sa_family == AF_INET) {
			inet_ntop(AF_INET,&(((sockaddr_in*)addr)->sin_addr), addrStr, INET_ADDRSTRLEN);
			a = AF_INET;
		}		
		else if (addr->sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &(((sockaddr_in6 *)addr)->sin6_addr), addrStr, INET6_ADDRSTRLEN);
			a = AF_INET6;
		}
		return {a,addrStr};
	}

	static std::vector<std::string> Split(const std::string& str, char delimiter) {
		std::vector<std::string> tokens;
		std::string token;
		std::stringstream ss(str);

		while (std::getline(ss, token, delimiter)) {
			tokens.push_back(token);
		}

		return tokens;
	}

	static std::vector<std::string> GetAdapterExtraInfo(const std::string& name) {
		//https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses

		std::vector<std::string> ret;

		WSAData d;
		if (WSAStartup(MAKEWORD(2, 2), &d) != 0) {
			return{};
		}

		PIP_ADAPTER_ADDRESSES addrs;
		DWORD a, size;
		a = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);

		addrs = (PIP_ADAPTER_ADDRESSES)malloc(size);

		a = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &size);

		if (a != ERROR_SUCCESS)
			return{};

		std::stringstream ss;

		for (PIP_ADAPTER_ADDRESSES a_ = addrs; a_; a_ = a_->Next) {
			if (name == a_->AdapterName) {
				ret.push_back(SockaddrToPair(a_->FirstDnsServerAddress->Address.lpSockaddr).second);
				ret.push_back(std::to_string(a_->Mtu));
				ret.push_back(std::to_string(a_->TransmitLinkSpeed / 1000000));

				for (ULONG i = 0; i < a_->PhysicalAddressLength; ++i) {
					if (i > 0) ss << "-";
					ss << std::hex << (int)a_->PhysicalAddress[i];
				}

				ret.push_back(ss.str());

			}
		}

		free(addrs);
		return ret;
	}

}

static const std::unordered_map<std::string, std::string> dnsLookupTable = {
		{"8.8.8.8", "Google"},
		{"8.8.4.4", "Google"},
		{"1.1.1.1", "Cloudflare"},
		{"1.0.0.1", "Cloudflare"},
		{"208.67.222.222", "OpenDNS"},
		{"208.67.220.220", "OpenDNS"},
		{"9.9.9.9", "Quad9"},
		{"149.112.112.112", "Quad9"},
		{"84.200.69.80", "DNS.Watch"},
		{"84.200.70.40", "DNS.Watch"},
		{"8.26.56.26", "Comodo Secure DNS"},
		{"8.20.247.20", "Comodo Secure DNS"},
		{"199.85.126.10", "Norton ConnectSafe"},
		{"199.85.127.10", "Norton ConnectSafe"},
		{"156.154.70.1", "Neustar DNS"},
		{"156.154.71.1", "Neustar DNS"},
		{"209.244.0.3", "Level3"},
		{"209.244.0.4", "Level3"},
		{"195.46.39.39", "SafeDNS"},
		{"195.46.39.40", "SafeDNS"},
		{"198.101.242.72", "Alternate DNS"},
		{"23.253.163.53", "Alternate DNS"},
		{"77.88.8.8", "Yandex DNS"},
		{"77.88.8.1", "Yandex DNS"},
		{"94.140.14.14", "AdGuard DNS"},
		{"94.140.15.15", "AdGuard DNS"},
		{"176.103.130.130", "AdGuard DNS"},
		{"176.103.130.131", "AdGuard DNS"},
		{"185.228.168.9", "CleanBrowsing"},
		{"185.228.169.9", "CleanBrowsing"},
		{"185.228.168.10", "CleanBrowsing"},
		{"185.228.169.11", "CleanBrowsing"},
		{"64.6.64.6", "Verisign"},
		{"64.6.65.6", "Verisign"},
		{"202.67.222.222", "Hurricane Electric"},
		{"202.67.220.220", "Hurricane Electric"},
		{"1.1.1.2", "Cloudflare Family"},
		{"1.0.0.2", "Cloudflare Family"},
		{"76.76.19.19", "Control D"},
		{"76.223.122.150", "Control D"}
};
