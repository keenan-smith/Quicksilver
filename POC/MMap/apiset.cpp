#include "apiset.h"
#include <string>
#include <winternl.h>
std::string get_dll_name_from_api_set_map(const std::string& api_set)
{
	std::wstring wapi_set(api_set.begin(), api_set.end());
	auto peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	auto apiSetMap = static_cast<PAPI_SET_NAMESPACE>(peb->Reserved9[0]);
	auto apiSetMapAsNumber = reinterpret_cast<ULONG_PTR>(apiSetMap);
	auto nsEntry = reinterpret_cast<PAPI_SET_NAMESPACE_ENTRY>((apiSetMap->EntryOffset + apiSetMapAsNumber));
	for (ULONG i = 0; i < apiSetMap->Count; i++) {
		UNICODE_STRING nameString, valueString;
		nameString.MaximumLength = static_cast<USHORT>(nsEntry->NameLength);
		nameString.Length = static_cast<USHORT>(nsEntry->NameLength);
		nameString.Buffer = reinterpret_cast<PWCHAR>(apiSetMapAsNumber + nsEntry->NameOffset);
		std::wstring name = std::wstring(nameString.Buffer, nameString.Length / sizeof(WCHAR)) + L".dll";
		if (_wcsicmp(wapi_set.c_str(), name.c_str()) == 0) {
			auto valueEntry = reinterpret_cast<PAPI_SET_VALUE_ENTRY>(apiSetMapAsNumber + nsEntry->ValueOffset);
			if (nsEntry->ValueCount == 0)
				return "";
			valueString.Buffer = reinterpret_cast<PWCHAR>(apiSetMapAsNumber + valueEntry->ValueOffset);
			valueString.MaximumLength = static_cast<USHORT>(valueEntry->ValueLength);
			valueString.Length = static_cast<USHORT>(valueEntry->ValueLength);
			auto value = std::wstring(valueString.Buffer, valueString.Length / sizeof(WCHAR));
			//note: there might be more than one value, but we will just return the first one..
			return std::string(value.begin(), value.end());
		}
		nsEntry++;
	}
}