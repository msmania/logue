//
// logue.cpp
//

#include <windows.h>
#include <stdio.h>
#include "logue.h"

void RunAs(LPWSTR inUser, LPWSTR inPW, LPWSTR inCommand) {
	HANDLE CallerToken= NULL;
	HANDLE CalleeToken= NULL;
	HWINSTA Winsta0= NULL;
	HDESK Desktop= NULL;
	PSID Sid= NULL;
	
	if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &CallerToken) ) {
		wprintf(L"OpenProcessTokenWithSACL failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	//
	// ACCESS_SYSTEM_SECURITY is required to read SACL at DumpSecurityDescriptorFromUserObject
	// SE_SECURITY_NAME token is required to specify ACCESS_SYSTEM_SECURITY flag
	// otherwise, OpenProcessToken failed with ERROR_PRIVILEGE_NOT_HELD (0n1314)
	//
	// http://msdn.microsoft.com/en-us/library/aa446675(VS.85).aspx
	// http://msdn.microsoft.com/en-us/library/aa379321(v=VS.85).aspx
	//
	// 0x01000000 - ACCESS_SYSTEM_SECURITY
	// 0x000f01ff - TOKEN_ALL_ACCESS
	//
	EnablePrivilege(CallerToken, SE_SECURITY_NAME, TRUE);

	if ( !LogonUser(inUser, NULL, inPW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &CalleeToken) ) {
		wprintf(L"LogonUser failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
	
	//
	// SE_INCREASE_QUOTA_NAME and SE_ASSIGNPRIMARYTOKEN_NAME are required to call CreateProcessAsUser
	// http://msdn.microsoft.com/en-us/library/ms682429
	//
	EnablePrivilege(CalleeToken, SE_INCREASE_QUOTA_NAME, TRUE);
	EnablePrivilege(CalleeToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
	EnablePrivilege(CallerToken, SE_INCREASE_QUOTA_NAME, TRUE);
	EnablePrivilege(CallerToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);

	Winsta0= OpenWindowStation(L"winsta0", FALSE, READ_CONTROL|WRITE_DAC|ACCESS_SYSTEM_SECURITY);
	if ( !Winsta0 ) {
		wprintf(L"OpenWindowStation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	//wprintf(L"[Window Station]\n");
	//DumpSecurityDescriptorFromUserObject(Winsta0);
	
	Desktop= OpenDesktop(L"default", 0, FALSE,
		READ_CONTROL|WRITE_DAC|DESKTOP_WRITEOBJECTS|DESKTOP_READOBJECTS|ACCESS_SYSTEM_SECURITY);
	if ( !Desktop ) {
		wprintf(L"OpenDesktop failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	//wprintf(L"[Desktop]\n");
	//DumpSecurityDescriptorFromUserObject(Winsta0);
	
	//if ( !GetTokenSID(CalleeToken, &Sid) ) {
	//	wprintf(L"GetTokenSID failed - 0x%08x\n", GetLastError());
	//	goto Cleanup;
	//}

	//if ( !AddAceToWindowStation(Winsta0, Sid) ) {
	//	wprintf(L"AddAceToWindowStation failed - 0x%08x\n", GetLastError());
	//	goto Cleanup;
	//}

	//if ( !AddAceToDesktop(Desktop, Sid) ) {
	//	wprintf(L"AddAceToDesktop failed - 0x%08x\n", GetLastError());
	//	goto Cleanup;
	//}

	//if ( !ImpersonateLoggedOnUser(CalleeToken) ) {
	//	wprintf(L"ImpersonateLoggedOnUser failed - 0x%08x\n", GetLastError());
	//	goto Cleanup;
	//}

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb= sizeof(STARTUPINFO);
	si.lpDesktop= L"default\\winsta0";

	PROCESS_INFORMATION pi;
	if ( !CreateProcessAsUser(CalleeToken, NULL, inCommand, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) ) {
		wprintf(L"CreateProcessAsUser failed - 0x%08x\n", GetLastError());
		//EnumPrivileges(CallerToken);
		goto Cleanup;
	}

	// RevertToSelf();

	if ( pi.hProcess ) CloseHandle(pi.hProcess);
	if ( pi.hThread ) CloseHandle(pi.hThread);

Cleanup:
	if ( Sid ) HeapFree(GetProcessHeap(), 0, Sid);
	if ( Winsta0 ) CloseWindowStation(Winsta0);
	if ( Desktop ) CloseDesktop(Desktop);
	if ( CalleeToken ) CloseHandle(CalleeToken);

	if ( CallerToken ) {
		//EnablePrivilege(CallerToken, SE_SECURITY_NAME, FALSE);

		//EnablePrivilege(CalleeToken, SE_INCREASE_QUOTA_NAME, FALSE);
		//EnablePrivilege(CalleeToken, SE_ASSIGNPRIMARYTOKEN_NAME, FALSE);
		CloseHandle(CallerToken);
	}
}
