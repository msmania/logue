//
// logue.cpp
//
// base sample:
// http://msdn.microsoft.com/en-us/library/aa379608(v=vs.85).aspx
//

#include <windows.h>
#include <stdio.h>

#include "logue.h"

VOID RunAs(LPWSTR inUser, LPWSTR inPW, LPWSTR inCommand) {
	HANDLE CallerToken= NULL;
	HANDLE CalleeToken= NULL;
	HWINSTA WinstaOld= NULL;
	HWINSTA Winsta0= NULL;
	HDESK Desktop= NULL;
	PSID LogonSid= NULL;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LONG PrivCheck= 0;
	
	if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS , &CallerToken) ) {
		wprintf(L"OpenProcessToken failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
	
	CheckPrivilege(CallerToken, SE_INCREASE_QUOTA_NAME, &PrivCheck);
	if ( PrivCheck<0 )
		wprintf(L"CreateProcessAsUser requires %s.  Check the user's privileges.\n", SE_INCREASE_QUOTA_NAME);

	CheckPrivilege(CallerToken, SE_ASSIGNPRIMARYTOKEN_NAME, &PrivCheck);
	if ( PrivCheck<0 )
		wprintf(L"CreateProcessAsUser requires %s.  Check the user's privileges.\n", SE_ASSIGNPRIMARYTOKEN_NAME);
	
	if ( !LogonUser(inUser, NULL, inPW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &CalleeToken) ) {
		wprintf(L"LogonUser failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

#ifdef _GUI
	Winsta0= OpenWindowStation(L"winsta0", FALSE, READ_CONTROL|WRITE_DAC);
	if ( !Winsta0 ) {
		wprintf(L"OpenWindowStation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	WinstaOld= GetProcessWindowStation();
	if ( !SetProcessWindowStation(Winsta0) ) {
		wprintf(L"SetProcessWindowStation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
	Desktop= OpenDesktop(L"default", 0, FALSE,
		READ_CONTROL|WRITE_DAC|DESKTOP_WRITEOBJECTS|DESKTOP_READOBJECTS);
	SetProcessWindowStation(WinstaOld);
	if ( !Desktop ) {
		wprintf(L"OpenDesktop failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
	
	if ( !GetLogonSidFromToken(CalleeToken, &LogonSid) )
		goto Cleanup;
	
#ifdef _TRACING
	wprintf(L"PID      : 0x%x\n", GetCurrentProcessId());
	wprintf(L"HWINSTA  : 0x%x\n", Winsta0);
	wprintf(L"HDESK    : 0x%x\n", Desktop);
	wprintf(L"Logon SID: %p\n", LogonSid);
	wprintf(L"-----\n");
	getwchar();
#endif

	if ( !AddAceToWindowStation(Winsta0, LogonSid) ) {
		wprintf(L"AddAceToWindowStation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	if ( !AddAceToDesktop(Desktop, LogonSid) ) {
		wprintf(L"AddAceToDesktop failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
#endif
	
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb= sizeof(STARTUPINFO);

#ifdef _GUI
	si.lpDesktop= L"winsta0\\default";
#else
	si.lpDesktop= L"";
#endif
	
	if ( !ImpersonateLoggedOnUser(CalleeToken) ) {
		wprintf(L"ImpersonateLoggedOnUser failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	if ( !CreateProcessAsUser(CalleeToken, NULL, inCommand, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) ) {
		wprintf(L"CreateProcessAsUser failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
	
	WaitForSingleObject(pi.hProcess, INFINITE);
	
	RevertToSelf();

#ifdef _GUI
	RemoveAccessAllowedAcesBasedSID(Winsta0, LogonSid);
	RemoveAccessAllowedAcesBasedSID(Desktop, LogonSid);
#endif
	
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

Cleanup:
	if ( LogonSid ) HeapFree(GetProcessHeap(), 0, LogonSid);
	if ( Winsta0 ) CloseWindowStation(Winsta0);
	if ( Desktop ) CloseDesktop(Desktop);
	if ( CalleeToken ) CloseHandle(CalleeToken);
	if ( CallerToken ) CloseHandle(CallerToken);
}
