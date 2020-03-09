#include "hwid.h"
#include <Windows.h>
#include <intrin.h>
#include "logger.h"
std::string getPSN()
{

	int cpuinfo[4] = { -1 };
	__cpuid(cpuinfo, 0);

	std::string str = "";

	for (int i = 0; i < 3; i++)
	{
		DebugLog("cpuinfo: %d", cpuinfo[i]);
		str += std::to_string(cpuinfo[i]);
	}

	return str;

}

std::string getHDDSN()
{

	DWORD sn;
	GetVolumeInformationA("C:\\", NULL, NULL, &sn, NULL, NULL, NULL, NULL);

	return std::to_string(sn);

}

std::string getOSID()
{

	char name[MAX_COMPUTERNAME_LENGTH + 1] = {};
	DWORD len = sizeof name;

	GetComputerNameA(name, &len);

	std::string str = "";
	for (int i = 0; i < strlen(name); ++i)
	{
		char* tmp = new char[256];
		_itoa((int)name[i], tmp, 16);
		str += tmp;
		delete[] tmp;
	}

	return str;

}

std::string getID()
{

	std::string str = "";

	str += getPSN().c_str();
	str += "-";
	str += getHDDSN().c_str();
	str += "-";
	str += getOSID().c_str();

	return str;

}
//
///* Begin stolen shit functions */

__forceinline bool is_base64(BYTE c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

__forceinline std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {

	std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;

}
__forceinline std::vector<BYTE> base64_decode(std::string const& encoded_string) {

	std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	BYTE char_array_4[4], char_array_3[3];
	std::vector<BYTE> ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret.push_back(char_array_3[i]);
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
	}

	return ret;
}

__forceinline std::string hashString(std::string string)
{
	std::size_t intHash = std::hash<std::string>{} (string);
	std::string intString = std::to_string(intHash);
	char buffer[1000];
	strcpy(buffer, intString.c_str());
	std::string hash = base64_encode(((unsigned const char*)buffer), strlen(intString.c_str()));
	return hash;
}

std::string decrypt(std::string toDecrypt) {
	std::string buffer = toDecrypt;

	for (uint64_t i = 0; i < toDecrypt.size(); i++)
	{
		buffer[i] = toDecrypt[i] - 1;
	}

	return buffer;
}
