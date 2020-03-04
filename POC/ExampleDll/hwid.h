#pragma once
#include <string>
#include <vector>

std::string getPSN();
std::string getHDDSN();
std::string getOSID();
std::string getID();

std::string base64_encode(const unsigned char* bytes_to_encode, unsigned int int_len);
std::vector<unsigned char> base64_decode(const std::string& encoded_string);
std::string hashString(std::string string);
std::string decrypt(std::string toDecrypt);