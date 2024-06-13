#include "NetworkInterfaceManager.h"

char NetworkInterfaceManager::s_errbuf[PCAP_ERRBUF_SIZE];


NetworkInterfaceManager::NetworkInterfaceManager(std::shared_ptr<Logger> ptrLogger): m_ptrLogger(ptrLogger)
{
	m_ptrLogger->log(DEBUG, "NetworkInterfaceManager init");

	if (pcap_findalldevs(&m_alldevs, s_errbuf) == -1)
	{
		m_ptrLogger->log(ERROR_, "NetworkInterfaceManager init error");
		exit(1);
	}

	for (pcap_if_t *d = m_alldevs; d; d = d->next)
	{
		m_mapInterfaces.emplace(d->description, d);
	}
	
	if (m_mapInterfaces.empty() || m_mapInterfaces.size() == 1 ) {
		m_ptrLogger->log(ERROR_, "No interfaces found. Please install npcap");
		exit(EXIT_FAILURE);
	}
	m_ptrLogger->log(INFO, "Found " + std::to_string(m_mapInterfaces.size()) + " interfaces");
}

NetworkInterfaceManager::~NetworkInterfaceManager()
{
	pcap_freealldevs(m_alldevs);
}

