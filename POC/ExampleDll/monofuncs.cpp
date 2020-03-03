#include "monofuncs.h"
void MonoInit(HMODULE hMono)
{
	setMonoSecurity = (mono_security_set_t)GetProcAddress(hMono, "mono_security_set_mode");
	getMonoDomain = (mono_domain_get_t)GetProcAddress(hMono, "mono_domain_get");
	getRootMonoDomain = (mono_get_root_domain_t)GetProcAddress(hMono, "mono_get_root_domain");
	openAssembly = (mono_domain_assembly_open_t)GetProcAddress(hMono, "mono_domain_assembly_open");
	getAssemblyImageName = (mono_assembly_get_image_t)GetProcAddress(hMono, "mono_assembly_get_image");
	getClassFromName = (mono_class_from_name_t)GetProcAddress(hMono, "mono_class_from_name");
	getClassMethodFromName = (mono_class_get_method_from_name_t)GetProcAddress(hMono, "mono_class_get_method_from_name");
	invokeRuntime = (mono_runtime_invoke_t)GetProcAddress(hMono, "mono_runtime_invoke");
	monoAttachToThread = (mono_thread_attach_t)GetProcAddress(hMono, "mono_thread_attach");
	mono_image_open_from_data_full_ = (mono_image_open_from_data_full)GetProcAddress(hMono, "mono_image_open_from_data_full");
	mono_assembly_load_from_full_ = (mono_assembly_load_from_full)GetProcAddress(hMono, "mono_assembly_load_from_full");
}

void MonoInject(HMODULE hMono, void* file_data, DWORD file_size, const char* _namespace, const char* _class, const char* method)
{
	MonoInit(hMono);

	void* rootDomain = getRootMonoDomain();

	if (!rootDomain)
	{
		MessageBoxA(NULL, "Error 0x01, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}

	monoAttachToThread(rootDomain);
	setMonoSecurity(MONO_SECURITY_MODE_NONE);

	int status;
	void* image = mono_image_open_from_data_full_(file_data, file_size, 1, &status, 0);
	if (image == nullptr)
	{
		MessageBoxA(NULL, "Error 0x02, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}
	void* assembly = mono_assembly_load_from_full_(image, "System.IO", &status, 0);
	if (assembly == nullptr)
	{
		MessageBoxA(NULL, "Error 0x03, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}
	void* pMethod = getClassMethodFromName(getClassFromName(image, _namespace, _class), method, 0);

	if (pMethod == NULL)
	{
		MessageBoxA(NULL, "Error 0x04, restart unturned.", "Error", NULL);
		exit(-1);
		return;
	}

	Sleep(15000);

	invokeRuntime(pMethod, NULL, NULL, NULL);
}
