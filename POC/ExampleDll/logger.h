#pragma once
#include <string>
bool DebugModeEnabled = true;

template <typename... Args>
void DebugLog(const char* data, Args... args) {
	if (DebugModeEnabled) {
		printf("[Monoloader]: ");
		printf(data, args...);
		printf("\n");
	}
}