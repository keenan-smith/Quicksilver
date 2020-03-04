#pragma once
#include <string>
bool DebugModeEnabled = true;

template <typename... Args>
void DebugLog(std::string data, Args... args) {
	if (DebugModeEnabled) {
		printf(data.c_str(), args...);
		printf("\n");
	}
}