#pragma once

#include <ctime>
#include <string>
#include <iostream>

std::string GetMutexName()
{
	time_t now;
	time(&now);
	struct tm ptm;
	gmtime_s(&ptm, &now);
	int seed1 = ptm.tm_yday + ptm.tm_wday + ptm.tm_year + ptm.tm_mon + ptm.tm_mday + ptm.tm_hour;
	std::string mutexname = std::to_string(seed1);
	return mutexname;
}
