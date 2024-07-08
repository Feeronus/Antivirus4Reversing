﻿#include "Header.h"
#include <mutex>
#include "/Users/user/source/repos/SuperKeygen64/SuperKeygen64/base64-master/include/base64.hpp"

#define serviceName __TEXT("AntiBobry")
//#define BUFSIZE 512
uint16_t mac1;
uint16_t mac2;
SERVICE_STATUS ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE hServiceStatusHandle = NULL;
HANDLE hServiceEvent = NULL;
std::wofstream errorLog;
std::vector<HANDLE> uiHandlesVector;
std::mutex uiMutex;
std::u16string signatureFilePath = u"C:\\Users\\user\\source\\repos\\update-main\\AntimalvareService\\av3.bin";
AvBasesLoader basesLoader = AvBasesLoader();
auto bases = basesLoader.LoadBases(signatureFilePath);
ScanEngine scanEngine(bases);
void WINAPI SvcMain(DWORD argc, TCHAR** argv);
DWORD WINAPI SvcCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID dwEventData, LPVOID dwContent);
void StartUiProcessInSession(DWORD wtsSession);
void SvcReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
VOID SvcInstall();
VOID SvcInit(DWORD argc, LPTSTR* argv);
VOID SvcStop();
VOID SvcDelete();
bool Check(BOOL);
void getMacHash(uint16_t& mac1, uint16_t& mac2);
uint16_t getCpuHash();
std::string machineHash();
BOOL LicenseCheck();
Tstring GetUserID(HANDLE userToken);
SECURITY_ATTRIBUTES GetSecurityAttributes(const Tstring& sdd1);
BOOL Read(HANDLE handle, uint8_t* data, uint64_t lenght, DWORD& bytesRead);
BOOL Write(HANDLE handle, uint8_t* data, uint64_t lenght);
void ScanDirectory(const std::wstring& directoryPath, ScanEngine& scanEngine, uint8_t* resultBuffer);
int _tmain(int argc, TCHAR* argv[])
{
	WriteLog(__TEXT("_tmain func Start..."));
	WriteLog(std::format(__TEXT("argc = {}"), argc));

	if (argc > 1) {
		if (lstrcmpi(argv[1], __TEXT("install")) == 0)
		{
			SvcInstall();
			return 0;
		}
		else if (lstrcmpi(argv[1], __TEXT("stop")) == 0)
		{
			SvcStop();
			return 0;
		}
		else if (lstrcmpi(argv[1], __TEXT("delete")) == 0)
		{
			SvcDelete();
			return 0;
		}
	}
	else
	{
		SERVICE_TABLE_ENTRY ServiceTable[2];
		ServiceTable[0].lpServiceName = (LPTSTR)serviceName;
		ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)SvcMain;
		ServiceTable[1].lpServiceName = NULL;
		ServiceTable[1].lpServiceProc = NULL;

		if (!StartServiceCtrlDispatcher(ServiceTable))
			WriteLog(std::format(__TEXT("Error: StartServiceCtrlDispatcher = {}"), GetLastError()));
	}

	return 0;
}


void WINAPI SvcMain(DWORD argc, TCHAR** argv)
{
	WriteLog(__TEXT("Service Starting at...."));
	BOOL bServiceStatus = FALSE;
	hServiceStatusHandle = RegisterServiceCtrlHandlerExW(serviceName, (LPHANDLER_FUNCTION_EX)SvcCtrlHandler, NULL);
	WriteLog(std::format(__TEXT("hServiceStatusHandle = {}"), (int)(void*)hServiceStatusHandle));
	if (hServiceStatusHandle == (SERVICE_STATUS_HANDLE)0)
	{
		WriteLog(std::format(__TEXT("Error: RegisterServiceCtrlHandler failed = {}"), GetLastError()));
		return;
	}
	else
	{
		WriteLog(__TEXT("RegisterServiceCtrlHandler success...."));
		WriteLog(machineHash().c_str());
	}


	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;

	SvcReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	bServiceStatus = SetServiceStatus(hServiceStatusHandle, &ServiceStatus);

	if (!Check(bServiceStatus))
	{
		WriteLog(std::format(__TEXT("Error: Service status initial setup failed = {}"), GetLastError()));
		return;
	}
	else 
		WriteLog(__TEXT("Service status initial setup success...."));
	
	WriteLog(L"try open signatureBases");
	if (bases == nullptr) {
		WriteLog(std::format(__TEXT("Error: Failed open signatureBases")));
	}
	PWTS_SESSION_INFOW wtsSessions;
	DWORD sessionsCount;
	if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &wtsSessions, &sessionsCount))
	{
		WriteLog(std::format(__TEXT("WTSEnumerateSessionsW returns TRUE, sessionsCount = {}"), sessionsCount));
		for (DWORD i = 0; i < sessionsCount; ++i)
		{

			if (wtsSessions[i].SessionId != 0 && wtsSessions[i].SessionId != 65536)
			{
				StartUiProcessInSession(wtsSessions[i].SessionId);
				WriteLog(std::format(__TEXT("Session ID = {}"), wtsSessions[i].SessionId));
			}
		}
	}
	else
	{
		SvcReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
		WriteLog(std::format(__TEXT("Error: Service status initial setup failed = {}"), GetLastError()));
		WriteLog(std::format(__TEXT("Error: WTSEnumerateSessionsW returns FALSE, error code = {}"), GetLastError()));
		return;
	}

	WTSFreeMemory(wtsSessions);
	SvcInit(argc, argv);
	while (ServiceStatus.dwCurrentState != SERVICE_STOPPED) {

		WriteLog(__TEXT("Service is running...."));
		if (WaitForSingleObject(hServiceEvent, 60000) != WAIT_TIMEOUT)
			SvcReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
	}
}

DWORD WINAPI SvcCtrlHandler(DWORD dwCtrl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContent)
{
	DWORD result = ERROR_CALL_NOT_IMPLEMENTED;

	switch (dwCtrl)
	{
	/*case SERVICE_CONTROL_STOP:
		WriteLog(__TEXT("Service have been Stopped at...."));
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		result = NO_ERROR;
		break;*/

	case SERVICE_CONTROL_SHUTDOWN:
		WriteLog(__TEXT("PC is going to SHUTDOWN stopping the Service...."));
		SvcReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
		result = NO_ERROR;
		break;

	case SERVICE_CONTROL_SESSIONCHANGE:
		if (dwEventType == WTS_SESSION_LOGON)
		{
			WTSSESSION_NOTIFICATION* sessionNotification = static_cast<WTSSESSION_NOTIFICATION*>(lpEventData);
			StartUiProcessInSession(sessionNotification->dwSessionId);
		}
		break;

	case SERVICE_CONTROL_INTERROGATE:
		result = NO_ERROR;
		break;
	}

	SvcReportStatus(ServiceStatus.dwCurrentState, result, 0);
	return result;
}


void StartUiProcessInSession(DWORD wtsSession) {

	std::thread clientThread([wtsSession]() {

		WriteLog(std::format(__TEXT("StartUiProcessInSession wtsSession = {}"), wtsSession));

		HANDLE userToken;
		if (WTSQueryUserToken(wtsSession, &userToken))
		{

			TCHAR commandLine[] = __TEXT("\"C:\\Users\\user\\source\\repos\\update-main\\AntimalvareService\\x64\\Debug\\Graphic.Ui.exe\"");
			WriteLog(__TEXT("Starting  \"C:\\Users\\user\\source\\repos\\update-main\\AntimalvareService\\x64\\Debug\\Graphic.Ui.exe"));
			TCHAR sdCommandLine[] = __TEXT("\"C:\\Users\\user\\source\\repos\\update-main\\AntimalvareService\\x64\\Debug\\Graphic.Ui.exe\" --secure-desktop");
			Tstring processSddl = std::format(__TEXT("O:SYG:SYD:(D;OICI;0x{:08X};;;WD)(A;OICI;0x{:08X};;;WD)"), PROCESS_TERMINATE, PROCESS_ALL_ACCESS);
			Tstring threadSddl = std::format(__TEXT("O:SYG:SYD:(D;OICI;0x{:08X};;;WD)(A;OICI;0x{:08X};;;WD)"), THREAD_TERMINATE, THREAD_ALL_ACCESS);

			PROCESS_INFORMATION pi{};
			STARTUPINFO si{};

			SECURITY_ATTRIBUTES processSecurityAttributes = GetSecurityAttributes(processSddl);
			SECURITY_ATTRIBUTES threadSecurityAttributes = GetSecurityAttributes(threadSddl);
			//25
			if (processSecurityAttributes.lpSecurityDescriptor != nullptr && threadSecurityAttributes.lpSecurityDescriptor != nullptr)
			{
				Tstring path{ std::format(__TEXT("\\\\.\\pipe\\AntimalwareServiceIPC\\{}"), wtsSession) };
				Tstring pipeSddl = std::format(__TEXT("O:SYG:SYD:(A;OICI;GA;;;{})"), GetUserID(userToken));

				WriteLog(std::format(__TEXT("path = {}"), path));
				WriteLog(std::format(__TEXT("pipeSddl = {}"), pipeSddl));

				WriteLog(__TEXT("Creating SA for pipe...."));

				SECURITY_ATTRIBUTES npsa = GetSecurityAttributes(pipeSddl);
				//SECURITY_ATTRIBUTES npsa;
				WriteLog(__TEXT("Creating pipe...."));

				HANDLE pipe = CreateNamedPipe(
					path.c_str(),
					PIPE_ACCESS_DUPLEX,
					PIPE_TYPE_MESSAGE |
					PIPE_READMODE_MESSAGE |
					PIPE_WAIT,
					1,
					BUFSIZ,
					BUFSIZ,
					0,
					&npsa
				);

				WriteLog(__TEXT("Creating process...."));

				if (CreateProcessAsUser(
					userToken,
					NULL,
					commandLine,
					&processSecurityAttributes,
					&threadSecurityAttributes,
					FALSE,
					0,
					NULL,
					NULL,
					&si,
					&pi))
				{

					WriteLog(__TEXT("Process created...."));
					{
						std::lock_guard<std::mutex> lock(uiMutex);
						uiHandlesVector.push_back(pi.hProcess);
					}
					ULONG clientProcessId;
					BOOL clientIndentified;
					WriteLog(__TEXT("Check1"));
					do
					{
						BOOL fConnected = ConnectNamedPipe(pipe, NULL) ?
							TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

						clientIndentified = GetNamedPipeClientProcessId(pipe, &clientProcessId);

						if (clientIndentified)
							if (clientProcessId == pi.dwProcessId)
								break;
							else
								DisconnectNamedPipe(pipe);


					} while (true);
					uint8_t buff[512];
					DWORD bytesRead = 0;
					std::u16string outPath = u"C:\\Users\\user\\source\\repos\\update-main\\AntimalvareService\\output.bin";
					FileStream out(outPath);
					while (Read(pipe, buff, 512, bytesRead))
					{
						uint8_t buff2[6] = {0};
						WriteLog(bytesRead);
						ImpersonateNamedPipeClient(pipe);
						RevertToSelf();
						DWORD exitCode;
						if (bytesRead >= 1 && buff[0] == 'Q')
						{
							PROCESS_INFORMATION sdpi{};
							STARTUPINFOW sdsi{};
							if (CreateProcessAsUserW(
								userToken,
								NULL,
								sdCommandLine,
								&processSecurityAttributes,
								&threadSecurityAttributes,
								FALSE,
								0,
								NULL,
								NULL,
								&sdsi,
								&sdpi))
							{
								
								if (WAIT_OBJECT_0 == WaitForSingleObject(sdpi.hProcess, INFINITE))
								{
									/*if (!LicenseCheck())
									{
										{
											std::lock_guard<std::mutex> lock(uiMutex);
											for (auto& handle : uiHandlesVector)
											{
												TerminateProcess(handle, 0);
											}
										}
										ServiceStatus.dwCurrentState = SERVICE_STOPPED;
										SvcReportStatus(ServiceStatus.dwCurrentState, NO_ERROR, 0);
										WriteLog(std::format(__TEXT("Error1: License not found or expired...")));
										return;
									}*/
									if (GetExitCodeProcess(sdpi.hProcess, &exitCode) && exitCode == 1)
									{
										if (!LicenseCheck())
											WriteLog(std::format(__TEXT("Error: License not found or expired...")));
										{
											std::lock_guard<std::mutex> lock(uiMutex);
											for (auto& handle : uiHandlesVector)
											{
												TerminateProcess(handle, 0);
											}
										}
										//TerminateProcess(GetCurrentProcess(), 0);
										ServiceStatus.dwCurrentState = SERVICE_STOPPED;
										SvcReportStatus(ServiceStatus.dwCurrentState, NO_ERROR, 0);
										return;
									}
								}
							}
						}
						if (bytesRead >= 1) {
							std::wstring filePathW(reinterpret_cast<wchar_t*>(buff));
							std::u16string filePathU(reinterpret_cast<char16_t*>(buff), 512);
							DWORD attributes = GetFileAttributes(reinterpret_cast<LPCWSTR>(filePathU.c_str()));
							if (attributes == INVALID_FILE_ATTRIBUTES) {
								DWORD error = GetLastError();
								WriteLog(std::format(TEXT("Ошибка при получении атрибутов файла или папки: {}"), error));
								buff2[0] = 'E'; // Error
							}
							else if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
								WriteLog(TEXT("Полученный путь является папкой."));
								ScanDirectory(filePathW, scanEngine, buff2);
							}
							else {
								WriteLog(TEXT("Полученный путь является файлом."));
								FileStream file(filePathU);
								std::shared_ptr<IRandomAccessStream> stream = std::make_shared<FileStream>(file);
								std::string malvareName;
								bool scanResult = scanEngine.Scan(stream, malvareName);
								if (scanResult) {
									buff2[0] = 'V';
									WriteLog("file have virus");
								}
								else {
									buff2[0] = 'N';
									WriteLog("file haven't virus");
								}
							}	
						}
						Write(pipe, buff2, 6);
					}
					WriteLog(__TEXT("Check3"));
					WriteLog(L"End writing.");
					
					CloseHandle(pipe);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);

				}
				else
					WriteLog(std::format(__TEXT("Error: Failed to create process = {}"), GetLastError()));

				auto sd = threadSecurityAttributes.lpSecurityDescriptor;
				threadSecurityAttributes.lpSecurityDescriptor = nullptr;
				LocalFree(sd);

				sd = processSecurityAttributes.lpSecurityDescriptor;
				processSecurityAttributes.lpSecurityDescriptor = nullptr;
				LocalFree(sd);
			}
		}
		else  WriteLog(std::format(__TEXT("Error: WTSQueryUserToken failed = {}"), GetLastError()));

		});
	clientThread.detach();
}

void SvcReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;
	BOOL bSetServiceStatus = FALSE;
	ServiceStatus.dwCurrentState = dwCurrentState;
	ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
	ServiceStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
	{
		ServiceStatus.dwControlsAccepted = 0;
	}
	else
	{
		ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	}

	if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
	{
		ServiceStatus.dwCheckPoint = 0;
	}
	else
	{
		ServiceStatus.dwCheckPoint = dwCheckPoint++;
	}

	bSetServiceStatus = SetServiceStatus(hServiceStatusHandle, &ServiceStatus);

	if (!Check(bSetServiceStatus))
	{
		WriteLog(std::format(__TEXT("Error: Service Status failed = {}"), GetLastError()));
	}

}

VOID SvcInstall()
{
	SC_HANDLE hOpenSCManager = NULL;
	SC_HANDLE hCreateService = NULL;

	TCHAR szPath[MAX_PATH];


	if (!GetModuleFileName(NULL, szPath, MAX_PATH))
	{
		WriteLog(std::format(__TEXT("Error: Cannot install service = {}"), GetLastError()));
		return;
	}

	// Get a handle to the SCM database. 

	hOpenSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (hOpenSCManager == NULL)
	{
		WriteLog(std::format(__TEXT("Error: OpenSCManager failed = {}"), GetLastError()));
		return;
	}
	else  
		WriteLog(__TEXT("OpenSCManager success...."));

	hCreateService = CreateService(
		hOpenSCManager,
		serviceName,
		serviceName,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		szPath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);

	if (hCreateService == NULL) {
		WriteLog(std::format(__TEXT("Error: CreateService failed = {}"), GetLastError()));
		CloseServiceHandle(hOpenSCManager);
		return;
	}
	else
	{
		WriteLog(__TEXT("CreateService success...."));
	}

	CloseServiceHandle(hCreateService);
	CloseServiceHandle(hOpenSCManager);
}

VOID SvcInit(DWORD argc, LPTSTR* argv)
{
	

	hServiceEvent = CreateEvent(
		NULL,    // default security attributes
		TRUE,    // manual reset event
		FALSE,   // not signaled
		NULL);   // no name

	if (hServiceEvent == NULL)
	{
		SvcReportStatus(SERVICE_STOPPED, GetLastError(), 0);
		return;
	}

	SvcReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

}


VOID SvcStop()
{

	SERVICE_STATUS_PROCESS SvcStatusProcess;

	SC_HANDLE hSCManager = NULL;
	SC_HANDLE hService = NULL;

	BOOL bQueryServiceStatus = TRUE;
	BOOL bControlService = TRUE;

	DWORD dwBytesNeeded;

	hSCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);

	if (hSCManager == NULL) {
		WriteLog(std::format(__TEXT("Error: OpenSCManager failed = {}"), GetLastError()));
		return;
	}
	WriteLog(__TEXT("OpenSCManager success...."));

	hService = OpenService(
		hSCManager,
		serviceName,
		SERVICE_ALL_ACCESS
	);

	if (hService == NULL) {
		WriteLog(std::format(__TEXT("Error: OpenService failed = {}"), GetLastError()));
		CloseServiceHandle(hSCManager);
		return;
	}
	WriteLog(__TEXT("OpenService success...."));

	bQueryServiceStatus = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);

	if (!bQueryServiceStatus)
	{
		WriteLog(std::format(__TEXT("Error: QueryServiceStatus failed = {}"), GetLastError()));
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return; // ???
	}

	bControlService = ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&SvcStatusProcess);

	if (!bControlService) {
		WriteLog(std::format(__TEXT("Error: ControlService failed = {}"), GetLastError()));
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return; // ???
	}

	while (SvcStatusProcess.dwCurrentState != SERVICE_STOPPED)
	{
		bQueryServiceStatus = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);
		//&&& ???
		if (!bQueryServiceStatus)
		{
			WriteLog(std::format(__TEXT("Error: ControlService failed = {}"), GetLastError()));
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return; // ???
		}

		if (SvcStatusProcess.dwCurrentState == SERVICE_STOPPED)
		{
			WriteLog(__TEXT("Service stopped successfuly...."));
			break;
		}
		else
		{
			WriteLog(std::format(__TEXT("Error: Service stopped failed = {}"), GetLastError()));
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
		}
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}


VOID SvcDelete()
{
	SC_HANDLE hSCManager = NULL;
	SC_HANDLE hService = NULL;

	BOOL bDeleteService = FALSE;

	hSCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);

	if (hSCManager == NULL) {
		WriteLog(std::format(__TEXT("Error: OpenSCManager failed = {}"), GetLastError()));
		return;
	}
	else 
		WriteLog(__TEXT("OpenSCManager success...."));

	hService = OpenService(
		hSCManager,
		serviceName,
		SERVICE_ALL_ACCESS
	);

	if (hService == NULL) {
		WriteLog(std::format(__TEXT("Error: OpenService failed = {}"), GetLastError()));
		CloseServiceHandle(hSCManager);
		return;
	}
	else
		WriteLog(__TEXT("OpenService success...."));


	bDeleteService = DeleteService(hService);

	if (!Check(bDeleteService))
	{
		WriteLog(std::format(__TEXT("Error: Delete service failed = {}"), GetLastError()));
	}
	else
	{
		WriteLog(__TEXT("Delete service success...."));
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}

BOOL WaitConnection(HANDLE& pipe) {

	BOOL fConnected = ConnectNamedPipe(pipe, NULL) ?
		TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

	return fConnected;
}

BOOL Write(HANDLE handle, uint8_t* data, uint64_t length) {

	DWORD cbWritten = 0;
	BOOL fSuccess = WriteFile(
		handle,
		data,
		length,
		&cbWritten,
		NULL
	);

	if (!fSuccess || length != cbWritten) return false;

	return true;
}

BOOL Read(HANDLE handle, uint8_t* data, uint64_t length, DWORD& bytesRead) {

	bytesRead = 0;
	BOOL fSuccess = ReadFile(
		handle,
		data,
		length,
		&bytesRead,
		NULL
	);

	if (!fSuccess || bytesRead == 0) return false;

	return true;
}

SECURITY_ATTRIBUTES GetSecurityAttributes(const Tstring& sddl) {

	SECURITY_ATTRIBUTES securityAttributes{};
	securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	securityAttributes.bInheritHandle = TRUE;

	PSECURITY_DESCRIPTOR psd = nullptr;

	if (ConvertStringSecurityDescriptorToSecurityDescriptor(sddl.c_str(), SDDL_REVISION_1, &psd, nullptr))
		securityAttributes.lpSecurityDescriptor = psd;
	else
		WriteLog(std::format(__TEXT("SDDL parse error: {}, sddl: {}"), GetLastError(), sddl));

	return securityAttributes;
}

Tstring GetUserID(HANDLE userToken) {

	Tstring userSid;
	DWORD err = 0;
	LPVOID pvInfo = NULL;
	DWORD cbSize = 0;
	if (!GetTokenInformation(userToken, TokenUser, NULL, 0, &cbSize))
	{
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER)
		{
			err = 0;
			pvInfo = LocalAlloc(LPTR, cbSize);

			if (!pvInfo)
				err = ERROR_OUTOFMEMORY;
			else if (!GetTokenInformation(userToken, TokenUser, pvInfo, cbSize, &cbSize))
				err = GetLastError();
			else
			{
				err = 0;
				const TOKEN_USER* pUser = (const TOKEN_USER*)pvInfo;
				LPTSTR userSidBuf;
				ConvertSidToStringSid(pUser->User.Sid, &userSidBuf);
				userSid.assign(userSidBuf);
				LocalFree(userSidBuf);
			}
		}
	}

	return userSid;
}

void ScanDirectory(const std::wstring& directoryPath, ScanEngine& scanEngine, uint8_t* resultBuffer) {

	WIN32_FIND_DATA findFileData; //Ñòðóêòóðà õðàíèò èíôîðìàöèþ î ôàéëàõ è ïàïêàõ

	HANDLE hFind = FindFirstFile((directoryPath + __TEXT("\\*")).c_str(), &findFileData); // ïåðâûé ôàéë èëè ïàïêà

	if (hFind == INVALID_HANDLE_VALUE) {
		WriteLog(__TEXT("Invalid directory handle."));
		return;
	}

	do {
		const std::wstring fileOrDirName = findFileData.cFileName; // èçâëåêàåì òåêóùåå èìÿ ôàéëà èëè ïàïêè

		if (fileOrDirName == __TEXT(".") || fileOrDirName == __TEXT("..")) {
			//Ïðîâåðêà íà ñïåöèàëüíûå ïàïêè "." è "..", êîòîðûå îáîçíà÷àþò òåêóùóþ è ðîäèòåëüñêóþ äèðåêòîðèè.
			// Åñëè ýòî îíè, òî ïðîïóñêàåì èòåðàöèþ öèêëà.
			continue;
		}

		const std::wstring fullPath = directoryPath + __TEXT("\\") + fileOrDirName; // ôîðìèðóåì ïðàâèëüíûé ïóòü ê ôàéëó èëè ïàïêå

		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			// Ðåêóðñèâíî ñêàíèðóåì âëîæåííóþ äèðåêòîðèþ
			ScanDirectory(fullPath, scanEngine, resultBuffer);
			if (resultBuffer[0] == 'V') {
				break; // Ïðåêðàùàåì ñêàíèðîâàíèå ïðè íàõîæäåíèè âèðóñà
			}
		}
		else {
			WriteLog(std::format(__TEXT("Scanning file: {}"), fullPath));
			std::u16string filePath(fullPath.begin(), fullPath.end());
			FileStream file(filePath);

			std::shared_ptr<IRandomAccessStream> stream = std::make_shared<FileStream>(file);
			std::string malwareName;

			bool scanResult = scanEngine.Scan(stream, malwareName);
			if (scanResult) {
				resultBuffer[0] = 'V';
				WriteLog(__TEXT("file has virus"));
				break; // Ïðåêðàùàåì ñêàíèðîâàíèå ïðè íàõîæäåíèè âèðóñà
			}
		}
	} while (FindNextFile(hFind, &findFileData) != 0); // ïðîäîëæàåì ïîêà åñòü ôàéëû èëè ïàïêè

	FindClose(hFind);

	if (resultBuffer[0] != 'V')
		resultBuffer[0] = 'N'; // Åñëè âèðóñ íå íàéäåí â ïàïêå

}
bool Check(BOOL statement)
{
	if (statement == FALSE)
	{
		return false;
	}
	return true;
}


