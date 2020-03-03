#pragma once
#ifndef _MONO_FUNCTIONS_
#define _MONO_FUNCTIONS_

#include <Windows.h>
#include <stdint.h>

typedef enum {
	MONO_SECURITY_MODE_NONE,
	MONO_SECURITY_MODE_CORE_CLR,
	MONO_SECURITY_MODE_CAS,
	MONO_SECURITY_MODE_SMCS_HACK
} MonoSecurityMode;

typedef void(*mono_security_set_t) (MonoSecurityMode a_security);
typedef void* (*mono_domain_get_t) (void);
typedef void* (*mono_get_root_domain_t) (void);
typedef void* (*mono_assembly_load_from_full_t) (void* a_image, void** a_fname, void** a_status, bool a_refonly);
typedef void* (*mono_domain_assembly_open_t)(void* a_domain, const char* a_file);
typedef void* (*mono_assembly_get_image_t) (void* a_assembly);
typedef void* (*mono_class_from_name_t) (void* a_image, const char* a_name_space, const char* a_name);
typedef void* (*mono_class_get_method_from_name_t) (void* a_klass, const char* a_name, void* a_param_count);
typedef void* (*mono_runtime_invoke_t) (void* a_method, void* a_obj, void** a_params, void* a_exc);
typedef void* (*mono_thread_attach_t) (void* a_domain);
typedef void* (__cdecl* mono_image_open_from_data_full) (void* data, uint32_t data_len, int need_copy, int* status, int refonly);
typedef void* (__cdecl* mono_assembly_load_from_full) (void* image, const char* fname, int* status, int refonly);

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


void MonoInit(HMODULE hMono);
void MonoInject(HMODULE hMono, void* file_data, DWORD file_size, const char* _namespace, const char* _class, const char* method);

#endif _MONO_FUNCTIONS_