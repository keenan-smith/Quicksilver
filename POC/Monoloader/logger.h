#pragma once
#include <string>
extern bool DebugModeEnabled;

template <typename... Args>
void DebugLog(std::string data, Args... args) {
	if (DebugModeEnabled) {
		printf("[Monoloader]: ");
		printf(data.c_str(), args...);
		printf("\n");
	}
}