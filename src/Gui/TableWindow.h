#pragma once
#include "App.h"
#include "../NetworkInterfaceManager/NetworkInterfaceManager.h"

namespace TableWindow {
	static NetworkInterfaceManager* w_sNIM = nullptr;
    static int selectedRow;
    static bool resumeScrolling = false;

	static  void Draw(int menuBarHeight, bool& showSniffer) {
        ImGui::BeginChild("Child2", ImVec2(675, 565 - menuBarHeight), true);


        if (ImGui::BeginTable("SelectableTable", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("No", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Dest", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Protocol");
            ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthStretch);

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;

            std::unique_lock<std::mutex> lock(w_sNIM->m_pktMux);

            clipper.Begin(w_sNIM->GetPackets().size());

            while (clipper.Step() && !w_sNIM->GetPackets().empty())
            {

                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    ImGui::TableNextRow();
                    std::string itemid = "##" + std::to_string(i);

                    auto it = w_sNIM->GetPackets().find(i);
                    if (it != w_sNIM->GetPackets().end()) {
                        for (int j = 0; j < 6; j++) {

                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%d", i);
                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("%d", it->second->GetTimestamp());
                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("%s", it->second->GetIpSrc());
                            ImGui::TableSetColumnIndex(3);
                            ImGui::Text("%s", it->second->GetIpDest());
                            ImGui::TableSetColumnIndex(4);
                            ImGui::Text("%s", it->second->GetProtocol());
                            ImGui::TableSetColumnIndex(5);
                            ImGui::Text("%d", it->second->GetPacketSize());

                        }
                    }

                    ImGui::SameLine();

                    if (ImGui::Selectable(itemid.c_str(), i == selectedRow, ImGuiSelectableFlags_SpanAllColumns)) {
                        selectedRow = i;                     
                        ImGui::OpenPopup("ItemOptionsPopup");
                    }

                    if (selectedRow == i && ImGui::BeginPopup("ItemOptionsPopup")) {
                        ImGui::Text("Packet No. %d", i);
                        if (ImGui::MenuItem("Send to inspector")) {
                            showSniffer = false;

                        }
                        ImGui::EndPopup();
                    }
                    
                }
            }

            ImGui::EndTable();
        }
        ImGui::EndChild();
	}

}