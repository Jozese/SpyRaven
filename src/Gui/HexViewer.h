#pragma once

#include "App.h"
#include <pcap.h>
#include <vector>
#include "../NetworkInterfaceManager/NetworkInterfaceManager.h"
#include "../Utils/Utils.h"
#include <mutex>
#include <iomanip>
#include "../Packet/Packet.h"

namespace HexViewer {
    static std::string formatHex(uint8_t value) {
        std::ostringstream oss;
        oss << std::setw(2) << std::setfill('0') << std::hex << (int)value;
        return oss.str();
    }

	static void Draw(Packet* p) {
        
        for (size_t row = 0; row < p->GetPacketSize(); row += 16) {
            ImGui::Text("%08X: ", (unsigned int)row);
            ImGui::SameLine();

            for (size_t col = 0; col < 16; col++) {
                size_t index = row + col;
                if (index < p->GetPacketSize()) {
                    ImGui::Text("%s", formatHex(p->GetPacket()[index]).c_str());
                }
                else {
                    ImGui::Text("  ");
                }
                if (col < 15) ImGui::SameLine();
            }

            ImGui::SameLine();
            ImGui::Text("|");
            ImGui::SameLine();

            for (size_t col = 0; col < 16; col++) {
                size_t index = row + col;
                if (index < p->GetPacketSize()) {
                    char c = std::isprint(p->GetPacket()[index]) ? p->GetPacket()[index] : '.';
                    ImGui::Text("%c", c);
                }
                else {
                    ImGui::Text(" ");
                }
                if (col < 15) ImGui::SameLine();
            }
        }
	}
}