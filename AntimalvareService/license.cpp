#include <sstream>
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <string>
#include "Header.h"
#include <filesystem>
#include "/Users/user/source/repos/SuperKeygen64/SuperKeygen64/base64-master/include/base64.hpp"
#pragma comment(lib, "iphlpapi.lib")
uint16_t hashMacAddress(PIP_ADAPTER_INFO info) {
	uint16_t hash = 0;
	for (uint32_t i = 0; i < info->AddressLength; i++) {
		hash += (info->Address[i] << ((i & 1) * 8));
	}
	return hash;
}

void getMacHash(uint16_t& mac1, uint16_t& mac2) {
	IP_ADAPTER_INFO AdapterInfo[32];
	DWORD dwBufLen = sizeof(AdapterInfo);

	DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
	if (dwStatus != ERROR_SUCCESS)
		return; // no adapters.

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	mac1 = hashMacAddress(pAdapterInfo);
	if (pAdapterInfo->Next)
		mac2 = hashMacAddress(pAdapterInfo->Next);

	// sort the mac addresses. We don't want to invalidate
	// both macs if they just change order.
	if (mac1 > mac2) {
		uint16_t tmp = mac2;
		mac2 = mac1;
		mac1 = tmp;
	}

}


uint16_t getCpuHash() {
	int cpuinfo[4] = { 0, 0, 0, 0 };
	__cpuid(cpuinfo, 0);
	uint16_t hash = 0;
	uint16_t* ptr = (uint16_t*)(&cpuinfo[0]);
	for (uint32_t i = 0; i < 8; i++)
		hash += ptr[i];

	return hash;
}
std::string generateHash(const std::string& bytes) {
	static char chars[] = "0123456789ABCDEF";
	std::stringstream stream;

	auto size = bytes.size();
	for (uint32_t i = 0; i < size; ++i) {
		unsigned char ch = ~((unsigned char)((uint16_t)bytes[i] +
			(uint16_t)bytes[(i + 1) % size] +
			(uint16_t)bytes[(i + 2) % size] +
			(uint16_t)bytes[(i + 3) % size])) * (i + 1);

		stream << chars[(ch >> 4) & 0x0F] << chars[ch & 0x0F];
	}

	return stream.str();
}


static std::string* cachedHash = nullptr;

std::string machineHash() {
	static const uint32_t TargetLength = 64;
	uint16_t mac1;
	uint16_t mac2;
	if (cachedHash != nullptr) {
		return *cachedHash;
	}
	getMacHash(mac1, mac2);
	std::stringstream stream;
	
	stream << mac1;
	stream << mac2;
	stream << getCpuHash();

	auto string = stream.str();

	while (string.size() < TargetLength) {
		string = string + string;
	}

	if (string.size() > TargetLength) {
		string = string.substr(0, TargetLength);
	}

	return generateHash(string);
}
std::string xor_operation(std::string inpString)
{

	const char* encryptionKey = "whendoestheblackmoonhowl";
	std::string outString;
	int keylen = strlen(encryptionKey);
	for (int i = 0; i < inpString.length(); i++)
	{
		outString += inpString[i] ^ encryptionKey[i % keylen];
	}
	return outString;
}

BOOL LicenseCheck()
{
	std::string encryptedKey;
	std::string decryptedInfo;
	time_t tmp = time(nullptr);
	tm CurrentTime;
	localtime_s(&CurrentTime, &tmp);
	std::ifstream licenseKey("C:\\Users\\user\\source\\repos\\SuperKeygen64\\SuperKeygen64\\key.txt");
	if (licenseKey.is_open())
	{
		while (std::getline(licenseKey, encryptedKey))
		{
			if ((encryptedKey.length() & 3) != 0)
				return FALSE;
			decryptedInfo = base64::from_base64(xor_operation(base64::from_base64(encryptedKey)));
		}
		json decryptedInfoJ = json::parse(decryptedInfo);
		if ((decryptedInfoJ["hwid"] == machineHash()) && (std::difftime(tmp, decryptedInfoJ["startDay"]) <= decryptedInfoJ["expirationTime"]))
		{
			return TRUE;
		}
		else return FALSE;
	}
	return FALSE;
}
