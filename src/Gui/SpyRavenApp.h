#pragma once

#include "App.h"
#include "../NetworkInterfaceManager/NetworkInterfaceManager.h"
#include "../Packet/Packet.h"

#include "SelectorWindow.h"
#include "TableWindow.h"
#include "HexViewer.h"
#include "InspectorWindow.h"

class NetworkInterfaceManager;

class SpyRavenApp : public App {
public:
	SpyRavenApp();
	~SpyRavenApp() final;

private:
	NetworkInterfaceManager m_manager;

private:
	bool Setup() final;
	void Update() final;
	void Styles() final;
private:
	int m_curWinHeight;
	int m_curWinWidth;
	bool showSniffer = true;

	Packet* m_selected = nullptr;
};