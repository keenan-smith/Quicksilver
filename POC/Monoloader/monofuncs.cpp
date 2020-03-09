#include "monofuncs.h"
#include "logger.h"
mono_security_set_t setMonoSecurity;
mono_domain_get_t getMonoDomain;
mono_get_root_domain_t getRootMonoDomain;
mono_domain_assembly_open_t openAssembly;
mono_assembly_get_image_t getAssemblyImageName;
mono_class_from_name_t getClassFromName;
mono_class_get_method_from_name_t getClassMethodFromName;
mono_runtime_invoke_t invokeRuntime;
mono_thread_attach_t monoAttachToThread;
mono_image_open_from_data_full mono_image_open_from_data_full_;
mono_assembly_load_from_full mono_assembly_load_from_full_;


void MonoInit(HMODULE hMono)
{
	DebugLog("Initializing mono funcs...");
	setMonoSecurity = (mono_security_set_t)GetProcAddress(hMono, "mono_security_set_mode");
	DebugLog("setMonoSecurity: 0x%X", (uintptr_t)setMonoSecurity);
	getMonoDomain = (mono_domain_get_t)GetProcAddress(hMono, "mono_domain_get");
	DebugLog("getMonoDomain: 0x%X", (uintptr_t)getMonoDomain);
	getRootMonoDomain = (mono_get_root_domain_t)GetProcAddress(hMono, "mono_get_root_domain");
	DebugLog("getRootMonoDomain: 0x%X", (uintptr_t)getRootMonoDomain);
	openAssembly = (mono_domain_assembly_open_t)GetProcAddress(hMono, "mono_domain_assembly_open");
	DebugLog("openAssembly: 0x%X", (uintptr_t)openAssembly);
	getAssemblyImageName = (mono_assembly_get_image_t)GetProcAddress(hMono, "mono_assembly_get_image");
	DebugLog("getAssemblyImageName: 0x%X", (uintptr_t)getAssemblyImageName);
	getClassFromName = (mono_class_from_name_t)GetProcAddress(hMono, "mono_class_from_name");
	DebugLog("getClassFromName: 0x%X", (uintptr_t)getClassFromName);
	getClassMethodFromName = (mono_class_get_method_from_name_t)GetProcAddress(hMono, "mono_class_get_method_from_name");
	DebugLog("getClassMethodFromName: 0x%X", (uintptr_t)getClassMethodFromName);
	invokeRuntime = (mono_runtime_invoke_t)GetProcAddress(hMono, "mono_runtime_invoke");
	DebugLog("invokeRuntime: 0x%X", (uintptr_t)invokeRuntime);
	monoAttachToThread = (mono_thread_attach_t)GetProcAddress(hMono, "mono_thread_attach");
	DebugLog("monoAttachToThread: 0x%X", (uintptr_t)monoAttachToThread);
	mono_image_open_from_data_full_ = (mono_image_open_from_data_full)GetProcAddress(hMono, "mono_image_open_from_data_full");
	DebugLog("mono_image_open_from_data_full_: 0x%X", (uintptr_t)mono_image_open_from_data_full_);
	mono_assembly_load_from_full_ = (mono_assembly_load_from_full)GetProcAddress(hMono, "mono_assembly_load_from_full");
	DebugLog("mono_assembly_load_from_full_: 0x%X", (uintptr_t)mono_assembly_load_from_full_);
}

void MonoInject(HMODULE hMono, void* file_data, DWORD file_size, const char* _namespace, const char* _class, const char* method)
{
	MonoInit(hMono);

	DebugLog("Getting mono root domain...");

	void* rootDomain = getRootMonoDomain();

	if (!rootDomain)
	{
		MessageBoxA(NULL, "Error 0x01, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}

	DebugLog("Attaching thread to root domain...");
	monoAttachToThread(rootDomain);
	DebugLog("Setting mono security...");
	setMonoSecurity(MONO_SECURITY_MODE_NONE);
	DebugLog("Opening mono image from data...");

	int status;
	void* image = mono_image_open_from_data_full_(file_data, file_size, 1, &status, 0);
	if (image == nullptr)
	{
		MessageBoxA(NULL, "Error 0x02, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}
	DebugLog("Opening mono assembly from image...");
	void* assembly = mono_assembly_load_from_full_(image, "System.IO", &status, 0);
	if (assembly == nullptr)
	{
		MessageBoxA(NULL, "Error 0x03, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}
	DebugLog("Getting class method...");
	void* pMethod = getClassMethodFromName(getClassFromName(image, _namespace, _class), method, 0);

	if (pMethod == NULL)
	{
		MessageBoxA(NULL, "Error 0x04, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}
	DebugLog("Invoking runtime...");

	Sleep(15000);

	invokeRuntime(pMethod, NULL, NULL, NULL);
}
