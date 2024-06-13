#include "App.h"

App::App() {

	m_ptrLogger = std::make_shared<Logger>();

	if (!glewInit()) {
		m_ptrLogger->log(ERROR_, "GLEW could not init successfully");
		exit(EXIT_FAILURE);
	}

	m_ptrLogger->log(DEBUG, "GLEW init");

	if (!glfwInit()) {
		m_ptrLogger->log(ERROR_, "GLFW could not init successfully");
		exit(EXIT_FAILURE);
	}

	m_ptrLogger->log(DEBUG, "GLFW init");

	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
	glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
	glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
	glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);

	m_window = glfwCreateWindow(DEF_WIN_WIDTH, DEF_WIN_HEIGHT, "SpyRaven", nullptr, nullptr);

	if (!m_window) {
		m_ptrLogger->log(ERROR_, "Error while creating GLFW window");
		exit(EXIT_FAILURE);
	}

	m_ptrLogger->log(DEBUG, std::format("Creating GLFW window. Size: {} x {}", DEF_WIN_WIDTH, DEF_WIN_HEIGHT));

	glfwMakeContextCurrent(m_window);
	glfwSwapInterval(1); //vsync

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImPlot::CreateContext();

	ImGui::StyleColorsDark();

	m_io = &ImGui::GetIO();
	m_styles = &ImGui::GetStyle();

	ImGui_ImplGlfw_InitForOpenGL(m_window, true);
	ImGui_ImplOpenGL3_Init("#version 330");

}

void App::Run() {

	Setup();

	while (!glfwWindowShouldClose(m_window))
	{
		glfwPollEvents();

		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();


		Update();

		ImGui::Render();
		glClearColor(m_clearColor.x, m_clearColor.y, m_clearColor.z, m_clearColor.w);
		glClear(GL_COLOR_BUFFER_BIT);
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
		

		glfwSwapBuffers(m_window);
	}


}

App::~App() {
	
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwDestroyWindow(m_window);
	glfwTerminate();

}