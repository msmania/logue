//
// priv.cpp
//

#include <windows.h>
#include <stdio.h>

#define MAX_PRIVNAME 32

struct PRIVILAGENAME_MAPPING {
	WCHAR Label[MAX_PRIVNAME];
	WCHAR Name[MAX_PRIVNAME];
};

const PRIVILAGENAME_MAPPING PrivilegeNameMapping[]= {
	{ L"SE_CREATE_TOKEN_NAME", SE_CREATE_TOKEN_NAME },
	{ L"SE_ASSIGNPRIMARYTOKEN_NAME", SE_ASSIGNPRIMARYTOKEN_NAME },
	{ L"SE_LOCK_MEMORY_NAME", SE_LOCK_MEMORY_NAME },
	{ L"SE_INCREASE_QUOTA_NAME", SE_INCREASE_QUOTA_NAME },
	{ L"SE_UNSOLICITED_INPUT_NAME", SE_UNSOLICITED_INPUT_NAME },
	{ L"SE_MACHINE_ACCOUNT_NAME", SE_MACHINE_ACCOUNT_NAME },
	{ L"SE_TCB_NAME", SE_TCB_NAME },
	{ L"SE_SECURITY_NAME", SE_SECURITY_NAME },
	{ L"SE_TAKE_OWNERSHIP_NAME", SE_TAKE_OWNERSHIP_NAME },
	{ L"SE_LOAD_DRIVER_NAME", SE_LOAD_DRIVER_NAME },
	{ L"SE_SYSTEM_PROFILE_NAME", SE_SYSTEM_PROFILE_NAME },
	{ L"SE_SYSTEMTIME_NAME", SE_SYSTEMTIME_NAME },
	{ L"SE_PROF_SINGLE_PROCESS_NAME", SE_PROF_SINGLE_PROCESS_NAME },
	{ L"SE_INC_BASE_PRIORITY_NAME", SE_INC_BASE_PRIORITY_NAME },
	{ L"SE_CREATE_PAGEFILE_NAME", SE_CREATE_PAGEFILE_NAME },
	{ L"SE_CREATE_PERMANENT_NAME", SE_CREATE_PERMANENT_NAME },
	{ L"SE_BACKUP_NAME", SE_BACKUP_NAME },
	{ L"SE_RESTORE_NAME", SE_RESTORE_NAME },
	{ L"SE_SHUTDOWN_NAME", SE_SHUTDOWN_NAME },
	{ L"SE_DEBUG_NAME", SE_DEBUG_NAME },
	{ L"SE_AUDIT_NAME", SE_AUDIT_NAME },
	{ L"SE_SYSTEM_ENVIRONMENT_NAME", SE_SYSTEM_ENVIRONMENT_NAME },
	{ L"SE_CHANGE_NOTIFY_NAME", SE_CHANGE_NOTIFY_NAME },
	{ L"SE_REMOTE_SHUTDOWN_NAME", SE_REMOTE_SHUTDOWN_NAME },
	{ L"SE_UNDOCK_NAME", SE_UNDOCK_NAME },
	{ L"SE_SYNC_AGENT_NAME", SE_SYNC_AGENT_NAME },
	{ L"SE_ENABLE_DELEGATION_NAME", SE_ENABLE_DELEGATION_NAME },
	{ L"SE_MANAGE_VOLUME_NAME", SE_MANAGE_VOLUME_NAME },
	{ L"SE_IMPERSONATE_NAME", SE_IMPERSONATE_NAME },
	{ L"SE_CREATE_GLOBAL_NAME", SE_CREATE_GLOBAL_NAME },
	{ L"SE_TRUSTED_CREDMAN_ACCESS_NAME", SE_TRUSTED_CREDMAN_ACCESS_NAME },
	{ L"SE_RELABEL_NAME", SE_RELABEL_NAME },
	{ L"SE_INC_WORKING_SET_NAME", SE_INC_WORKING_SET_NAME },
	{ L"SE_TIME_ZONE_NAME", SE_TIME_ZONE_NAME },
	{ L"SE_CREATE_SYMBOLIC_LINK_NAME", SE_CREATE_SYMBOLIC_LINK_NAME },
	{ L"", L"" }
};

BOOL LookupPrivilegeValueEx(LPCWSTR SystemName, LPCWSTR PrivilegeName, PLUID Luid) {
	BOOL Ret= LookupPrivilegeValue(SystemName, PrivilegeName, Luid);
	if ( !Ret && GetLastError()==ERROR_NO_SUCH_PRIVILEGE ) {
		const PRIVILAGENAME_MAPPING *p;
		for ( p=PrivilegeNameMapping ; p->Label[0]!=0 ; ++p ) {
			if ( wcscmp(PrivilegeName, p->Label)==0 )
				return LookupPrivilegeValue(SystemName, p->Name, Luid);
		}
		SetLastError(ERROR_NO_SUCH_PRIVILEGE);
		Ret= FALSE;
	}
	return Ret;
}

VOID EnumPrivileges(HANDLE Token) {
	DWORD TokenLength= 0;
	PTOKEN_PRIVILEGES TokenPriv= NULL;

	if ( !GetTokenInformation(Token, TokenPrivileges, NULL, 0, &TokenLength) &&
			GetLastError()!=ERROR_INSUFFICIENT_BUFFER ) {
		wprintf(L"GetTokenInformation (size check) failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	TokenPriv= (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), 0, TokenLength);
	if ( !TokenPriv ) {
		wprintf(L"HeapAlloc failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	if ( !GetTokenInformation(Token, TokenPrivileges, TokenPriv, TokenLength, &TokenLength) ) {
		wprintf(L"GetTokenInformation failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}
	
	// LUID = Locally Unique Identifier
	wprintf(L"----------------------------------------\n");
	wprintf(L"   PrivilegeName, DisplayName (LUID)\n");
	wprintf(L"----------------------------------------\n");

	WCHAR DisplayName[256];
	WCHAR ProgramName[256];
	for ( DWORD i=0 ; i<TokenPriv->PrivilegeCount ; ++i ) {
		DWORD LanguageID= 0;
		DWORD PrivilegeLength= sizeof(ProgramName);
		LookupPrivilegeName(NULL, &TokenPriv->Privileges[i].Luid, ProgramName, &PrivilegeLength);

		PrivilegeLength= sizeof(DisplayName);
		LookupPrivilegeDisplayName(NULL, ProgramName, DisplayName, &PrivilegeLength, &LanguageID);

		BOOL b= TokenPriv->Privileges[i].Attributes&SE_PRIVILEGE_ENABLED;

		wprintf(L"%s, %s, %s (%I64d)\n",
			b ? L"O": L"X",
			ProgramName,
			DisplayName,
			TokenPriv->Privileges[i].Luid);
	}

cleanup:
	if ( TokenPriv ) HeapFree(GetProcessHeap(), 0, TokenPriv);

}

BOOL CheckPrivilege(HANDLE Token, LPCWSTR PrivilegeName, LPBOOL Privileged) {
	LUID luid;
	if ( !LookupPrivilegeValueEx(NULL, PrivilegeName, &luid) ){
		wprintf(L"LookupPrivilegeValue failed - 0x%08x\n", GetLastError());
		return FALSE;
	}

	PRIVILEGE_SET PrivilegeSet;
	PrivilegeSet.Control= 0;
	PrivilegeSet.PrivilegeCount= 1;
	PrivilegeSet.Privilege[0].Luid= luid;
	PrivilegeSet.Privilege[0].Attributes= 0; // not used

	if ( !PrivilegeCheck(Token, &PrivilegeSet, Privileged) ) {
		wprintf(L"PrivilegeCheck failed - 0x%08x\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
 
BOOL EnablePrivilege(HANDLE Token, LPWSTR PrivilegeName, BOOL Enabled) {
	LUID luid;
	if ( !LookupPrivilegeValueEx(NULL, PrivilegeName, &luid) ){
		wprintf(L"LookupPrivilegeValue failed - 0x%08x\n", GetLastError());
		return FALSE;
	}
	
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount= 1;
	tp.Privileges[0].Luid= luid;
	tp.Privileges[0].Attributes= Enabled ? SE_PRIVILEGE_ENABLED : 0; // not use SE_PRIVILEGE_REMOVED, just disable

	if ( !AdjustTokenPrivileges(Token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) ) {
		wprintf(L"AdjustTokenPrivileges failed - 0x%08x\n", GetLastError());
		return FALSE;
	}

	wprintf(L"# %s (%I64d) is temporarily %s.\n", PrivilegeName, luid,
		Enabled ? L"enabled" : L"disabled");

	return TRUE;
}
