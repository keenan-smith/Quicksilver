#pragma once
#include <string>

template <typename... Args>
void LOG(std::string data, Args... args) {
	printf(data.c_str(), args...);
	printf("\n");
}

template <typename... Args>
void LOG_ERROR(std::string data, Args... args) {
	printf(data.c_str(), args...);
	printf("\n");
}