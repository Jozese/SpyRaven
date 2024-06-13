#pragma once

#include "App.h"
#include <pcap.h>
#include <vector>
#include "../NetworkInterfaceManager/NetworkInterfaceManager.h"
#include "../Utils/Utils.h"
#include <mutex>
#include "../Packet/Packet.h"

namespace SelectorWindow {
	
	static std::atomic<uint32_t> w_bytesSent(0);
	static std::atomic<uint32_t> w_bytesRecv(0);

	static std::shared_ptr<Logger> w_Logger;

	static NetworkInterfaceManager* w_sNIM = nullptr;
	
	static std::vector<std::string> w_interfaceKeys;


	//Control
	static bool w_isCapturing = true;
	static bool w_showPlots = true;

	//Adapter info
	static std::string w_selectedInterfaceName = "";
	static std::string w_selectedIPv4 = "N/A";
	static std::string w_selectedIPv6 = "N/A";
	static std::string w_selectedIPv4Brd = "N/A";
	static std::string w_selectedIPv6Brd = "N/A";
	static std::string w_selectedIPv4Mask = "N/A";
	static std::string w_selectedIPv6Mask = "N/A";
	static std::string w_selectedMacAddr = "N/A";
	static std::string w_selectedMTU = "N/A";
	static std::string w_selectedDNS = "N/A";
	static std::string w_selectedLSpeed = "N/A";

	//Sniffing thread
	static std::thread w_captureThread;

	// 0. Main DNS 1. MTU 2. Link Speed 3. MAC
	static std::vector<std::string> w_selectedExtraInfo;

	static pcap_if* w_selected = nullptr;

	static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
			
		std::unique_ptr<Packet> pkt = std::make_unique<Packet>(pkthdr, packet, w_selected);
		if (pkt->IsSent()) {
			w_bytesSent += pkthdr->len;
		}
		else
		{
			w_bytesRecv += pkthdr->len;
		}
		
		std::unique_lock<std::mutex> lock(w_sNIM->m_pktMux);
		int pcount = w_sNIM->GetPackets().size();

		w_sNIM->GetPackets().emplace(pcount++, std::move(pkt));
	}

	static void PlotSent() {
		static double t = 0;
		static ScrollingBuffer buffer;

		t += ImGui::GetIO().DeltaTime;

		uint32_t bytesSent = w_bytesSent.exchange(0);

		buffer.AddPoint(t, bytesSent / 1000); 


		if (ImPlot::BeginPlot((w_selectedInterfaceName).c_str(), ImVec2(-1, 140))) {
			ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoTickLabels | ImPlotAxisFlags_NoGridLines | ImPlotAxisFlags_NoTickMarks, ImPlotAxisFlags_NoGridLines);
			ImPlot::SetupAxisLimits(ImAxis_X1, t - 5, t, ImGuiCond_Always);
			ImPlot::SetupAxisLimits(ImAxis_Y1, -1, 800); 

			ImPlot::PlotLine("Sent KB", &buffer.Data[0].x, &buffer.Data[0].y, buffer.Data.size(), 0, buffer.Offset, 2 * sizeof(uint32_t));

			ImPlot::EndPlot();
		}
	}

	

	static void PlotRecv() {
		static double t = 0;
		static ScrollingBuffer buffer;

		t += ImGui::GetIO().DeltaTime;

		uint32_t bytesRecv = w_bytesRecv.exchange(0);

		buffer.AddPoint(t, bytesRecv / 1000);

		if (ImPlot::BeginPlot((w_selectedInterfaceName).c_str(), ImVec2(-1, 140))) {
			ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoTickLabels | ImPlotAxisFlags_NoGridLines | ImPlotAxisFlags_NoTickMarks, ImPlotAxisFlags_NoGridLines);
			ImPlot::SetupAxisLimits(ImAxis_X1, t - 5, t, ImGuiCond_Always);
			ImPlot::SetupAxisLimits(ImAxis_Y1, -1, 800); 

			ImPlot::PlotLine("Recv KB", &buffer.Data[0].x, &buffer.Data[0].y, buffer.Data.size(), 0, buffer.Offset, 2 * sizeof(uint32_t));

			ImPlot::EndPlot();
		}
	}

	static void Draw(int menuBarHeight) {
		

		ImGui::BeginChild("Child1", ImVec2(350, 565 - menuBarHeight), true);

		ImGui::TextColored(ImVec4(0,1,0,0.7), "Select available network inteface");
		if (ImGui::BeginCombo("##Interface", w_selectedInterfaceName.c_str())) {

			for (int i = 0; i < w_interfaceKeys.size(); i++) {
				bool is_selected = (w_selectedInterfaceName == w_interfaceKeys[i]);
				if (ImGui::Selectable(w_interfaceKeys[i].c_str(), is_selected)) {
					
					//This will close the previous capture if there was one
					w_isCapturing = false;
					if (w_captureThread.joinable()) {
						w_captureThread.join();
					}

					w_isCapturing = true;
					w_captureThread = std::thread([&] {

						w_Logger->log(INFO, "THREAD FOR " + std::string(w_selected->description));

						auto handle = pcap_open_live(w_selected->name, BUFSIZ, 1, 1000, NetworkInterfaceManager::s_errbuf);

						while (w_isCapturing) {
							pcap_dispatch(handle, 0, packetHandler, NULL);
						}
						pcap_breakloop(handle);
						pcap_close(handle);

						std::unique_lock<std::mutex> lock(w_sNIM->m_pktMux);

						w_sNIM->GetPackets().clear();

						w_Logger->log(INFO, "ENDED THREAD FOR " + std::string(w_selected->description));


						});

					w_selectedInterfaceName = w_interfaceKeys[i];

					auto w_selectedIter = w_sNIM->GetInterfaces().find(w_selectedInterfaceName);


					if (w_selectedIter != w_sNIM->GetInterfaces().end()) {

						w_selected = w_selectedIter->second;

						w_selectedExtraInfo = Utils::GetAdapterExtraInfo(Utils::Split(w_selected->name, '_')[1].c_str());

						if (!w_selectedExtraInfo.empty()) {
							
							w_selectedDNS = w_selectedExtraInfo[0];

							auto it = dnsLookupTable.find(w_selectedDNS);
							
							if (it != dnsLookupTable.end())
								w_selectedDNS += " " + it->second;

							w_selectedMTU = w_selectedExtraInfo[1];
							w_selectedLSpeed = w_selectedExtraInfo[2];
							w_selectedMacAddr = w_selectedExtraInfo[3];
						}

						if (w_selected->addresses) {

							for (pcap_addr* d = w_selected->addresses; d; d = d->next) {
								auto str = Utils::SockaddrToPair(d->addr);

								switch (str.first)
								{
								case AF_INET: w_selectedIPv4 = str.second; break;
								case AF_INET6: w_selectedIPv6 = str.second; break;

								}

								auto strBrd = Utils::SockaddrToPair(d->broadaddr);

								switch (strBrd.first)
								{
								case AF_INET: w_selectedIPv4Brd = strBrd.second; break;
								case AF_INET6: w_selectedIPv6Brd = strBrd.second; break;

								}

								auto strMask = Utils::SockaddrToPair(d->netmask);

								switch (strMask.first)
								{
								case AF_INET: w_selectedIPv4Mask = strMask.second; break;
								case AF_INET6: w_selectedIPv6Mask = strMask.second; break;

								}
							}
							
							

						}
						else
						{
							w_selectedIPv4 = "N/A";
							w_selectedIPv6 = "N/A";
							w_selectedIPv4Brd = "N/A";
							w_selectedIPv6Brd = "N/A";
							w_selectedIPv4Mask = "N/A";
							w_selectedIPv6Mask = "N/A";
							w_selectedExtraInfo.clear();
						}


					}
					else
					{
						w_selected = nullptr;
					}
				}
			}



			ImGui::EndCombo();
		}



		if (w_selected) {
			ImGui::Text("Dev Name: %s", Utils::Split(w_selected->name, '_')[1].c_str());
			ImGui::Text("Desc: %s", w_selected->description);
			ImGui::Text("IPv4: %s", w_selectedIPv4.c_str());
			ImGui::Text("IPv6: %s", w_selectedIPv6.c_str());
			ImGui::Text("Subnet Mask IPv4: %s", w_selectedIPv4Mask.c_str());
			ImGui::Text("Subnet Mask IPv6: %s", w_selectedIPv6Mask.c_str());
			ImGui::Text("BRD IPv4: %s", w_selectedIPv4Brd.c_str());
			ImGui::Text("BRD IPv6: %s", w_selectedIPv6Brd.c_str());	

			ImGui::Text("MAC: %s", w_selectedMacAddr.c_str());
			ImGui::Text("MTU: %s", w_selectedMTU.c_str());

			ImGui::Text("Main DNS: %s", w_selectedDNS.c_str());
			ImGui::Text("Link Speed: %s Mbps", w_selectedLSpeed.c_str());
		}


		if (w_selected && w_showPlots) {
			PlotSent();
			PlotRecv();
		}
		else
		{
			w_bytesRecv = w_bytesSent = 0;
		}

		ImGui::EndChild();
	}

}