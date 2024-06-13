#pragma once

#include "App.h"
#include <pcap.h>
#include <vector>
#include "../NetworkInterfaceManager/NetworkInterfaceManager.h"
#include "../Utils/Utils.h"
#include <mutex>
#include "../Packet/Packet.h"
#include "HexViewer.h"
#include "SelectorWindow.h"
#include "TableWindow.h"

namespace InspectorWindow {
    static void Draw(Packet*& p, int menuBarHeight, bool& showSniffer) {
        ImGui::Begin("Inspector", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground);

        ImGui::BeginChild("Window", ImVec2(350 + 675 + ImGui::GetStyle().WindowPadding.x, 565 - menuBarHeight), true);

        ImGui::BeginChild("Info", ImVec2(350 + 675 - ImGui::GetStyle().WindowPadding.x, (565 - menuBarHeight) / 2), true);

        if (p->GetLoopbackNull()) {
            if (ImGui::TreeNode("NullLoopback"))
            {
                ImGui::Text("Family: 0x%08X", p->GetLoopbackNull()->family);
                ImGui::TreePop();
            }
        }

        if (p->GetEthHeader()) {
            if (ImGui::TreeNode("Ethernet Frame"))
            {

                ImGui::Text("Source MAC: %s", macAddrToString(p->GetEthHeader()->src_mac).c_str());
                ImGui::Text("Dest MAC: %s", macAddrToString(p->GetEthHeader()->dest_mac).c_str());
                ImGui::Text("Family: 0x%04X", p->GetEthHeader()->ether_type);

                ImGui::TreePop();
            }
        }

        if (p->GetIpv4Header()) {
            if (ImGui::TreeNode("IP Version 4"))
            {
                ImGui::Text("Version: 0x%01X", (p->GetIpv4Header()->version_ihl) >> 4);
                ImGui::Text("IHL: 0x%01X", (p->GetIpv4Header()->version_ihl) & 0x0f);
                ImGui::Text("DSCP/ECN 0x%02X", p->GetIpv4Header()->type_of_service);
                ImGui::Text("Total Length: %d bytes", ntohs(p->GetIpv4Header()->total_length));
                ImGui::Text("Identification: 0x%04X", ntohs(p->GetIpv4Header()->identification));
                ImGui::Text("Flags/Fragment Offset: 0x%04X", ntohs(p->GetIpv4Header()->flags_fragment_offset));
                ImGui::Text("TTL: %d", p->GetIpv4Header()->ttl);
                ImGui::Text("Protocol: 0x%01X", p->GetIpv4Header()->protocol);
                ImGui::Text("Header Checksum: 0x%02X", ntohs(p->GetIpv4Header()->header_checksum));
                ImGui::Text("Source IP: %s", p->GetIpSrc());
                ImGui::Text("Dest IP: %s", p->GetIpDest());

                ImGui::TreePop();
            }
        }

        if (p->GetIpv6Header()) {
            if (ImGui::TreeNode("IP Version 6")) {
                ImGui::Text("Version: 0x%01X", ntohl(p->GetIpv6Header()->ver_tc_fl) >> 28);
                ImGui::Text("V/TC/FL: 0x%08X", ntohl(p->GetIpv6Header()->ver_tc_fl));
                ImGui::Text("Payload length: 0x%04X", ntohs(p->GetIpv6Header()->payload_len));
                ImGui::Text("Next Header: 0x%02X", p->GetIpv6Header()->next_header);
                ImGui::Text("Source IP: %s", p->GetIpSrc());
                ImGui::Text("Dest IP: %s", p->GetIpDest());

                ImGui::TreePop();

            }

        }

        if (p->GetUdpHeader()) {
            if (ImGui::TreeNode("User Datagram Protocol")) {
                ImGui::Text("Source Port: %d", ntohs(p->GetUdpHeader()->src_port));
                ImGui::Text("Dest Port: %d", ntohs(p->GetUdpHeader()->dest_port));
                ImGui::Text("Length: %d bytes", ntohs(p->GetUdpHeader()->length));
                ImGui::Text("Checksum: 0x%04X", ntohs(p->GetUdpHeader()->checksum));

                ImGui::TreePop();
            }
        }

        if (p->GetTcpHeader()) {
            if (ImGui::TreeNode("Transmission Control Protocol")) {
                ImGui::Text("Source Port: %d", ntohs(p->GetTcpHeader()->src_port));
                ImGui::Text("Dest Port: %d", ntohs(p->GetTcpHeader()->dest_port));
                ImGui::Text("SEQ Num: %u", ntohl(static_cast<unsigned int>(p->GetTcpHeader()->seq_num)));
                ImGui::Text("ACK Num: %u", ntohl(static_cast<unsigned int>(p->GetTcpHeader()->ack_num)));
                ImGui::Text("Data Offset/Reserved: 0x%02X", p->GetTcpHeader()->data_offset);
                ImGui::Text("Flags: 0x%02X", p->GetTcpHeader()->flags);
                ImGui::Text("Window Size: %d bytes", ntohs(p->GetTcpHeader()->window_size));
                ImGui::Text("Checksum: 0x%04X", ntohs(p->GetTcpHeader()->checksum));
                ImGui::Text("Urgent Pointer: 0x%04X", ntohs(p->GetTcpHeader()->urgent_ptr));

                ImGui::TreePop();

            }
        }

        ImGui::EndChild();

        ImGui::BeginChild("HexView", ImVec2(350 + 675 - ImGui::GetStyle().WindowPadding.x, (565 - menuBarHeight) / 2.38), true);

        HexViewer::Draw(p);

        ImGui::EndChild();

        if (ImGui::Button("Back to sniffer")) {
            showSniffer = true;
            p = nullptr;
        }

        ImGui::EndChild();
	}
}