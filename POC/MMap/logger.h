#pragma once
#include <string>
#define LOGENTRY(a) logger::LOG_ENTRY(a)
static class logger
{
public:
	static void LOG_ENTRY(std::string data);
};

