#pragma once

#define GLEW_STATIC

#define DEF_WIN_HEIGHT 580 
#define DEF_WIN_WIDTH 1050

#include <GL/glew.h>
#include <GLFW/glfw3.h>

#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_opengl3.h>
#include <imgui/implot.h>

//#include <imgui/imgui_impl_opengl3_loader.h>

#include <Logger/Logger.h>

#include <format>
#include <memory>

static void glfw_error_callback(int error, const char* description)
{
	fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

static void TextCentered(std::string text) {
	auto windowWidth = ImGui::GetWindowSize().x;
	auto textWidth = ImGui::CalcTextSize(text.c_str()).x;

	ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
	ImGui::Text(text.c_str());
}

class App {
public:
	virtual ~App();
	App();
public:
		void Run();
public:
		virtual bool Setup() = 0;
		virtual void Update() = 0;
		virtual void Styles() = 0;
public:
	inline std::shared_ptr<Logger> GetLogger() const { return m_ptrLogger; }

protected:
	std::shared_ptr<Logger> m_ptrLogger;

protected:
	GLFWwindow* m_window = nullptr;
	ImVec4 m_clearColor {0.10f, 0.10f, 0.10f, 1.0f};

protected:
	ImGuiIO* m_io = nullptr;
	ImGuiStyle* m_styles = nullptr;
};

