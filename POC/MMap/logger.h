#pragma once
#include <string>

template <typename... Args>
void LOGENTRY(std::string data, Args... args) {
	printf(data.c_str(), args...);
	printf("\n");
}