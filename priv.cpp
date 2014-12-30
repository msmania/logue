//
// priv.cpp
//

#include <windows.h>
#include <stdio.h>

#include "logue.h"

#define MAX_PRIVNAME 32
#define MAX_PRIVSCAN 256

struct PRIVILAGENAME_MAPPING {
	WCHAR SymbolName[MAX_PRIVNAME];
	WCHAR PrivilegeName[MAX_PRIVNAME];
};

const PRIVILAGENAME_MAPPING PrivilegeNameMapping[]= {
	{ L"SE_CREATE_TOKEN_NAME", SE_CREATE_TOKEN_NAME },
	{ L"SE_ASSIGNPRIMARYTOKEN_NAME", SE_ASSIGNPRIMARYTOKEN_NAME },
	{ L"SE_LOCK_MEMORY_NAME", SE_LOCK_MEMORY_NAME },
	{ L"SE_INCREASE_QUOTA_NAME", SE_INCREASE_QUOTA_NAME },
	{ L"SE_UNSOLICITED_INPUT_NAME", SE_UNSOLICITED_INPUT_NAME }, // no LUID?
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

BOOL LookupPrivilegeName(LPCWSTR SystemName, CONST PLUID Luid, LPCWSTR *SymbolName,
						LPWSTR PrivilegeName, LPDWORD PrivilegeNameLength,
						LPWSTR DisplayName, LPDWORD DisplayNameLength, BOOL NoErrMsg) {
	BOOL Ret= FALSE;
	DWORD LanguageId;
	int Index= -1;

	Ret= LookupPrivilegeName(NULL, Luid, PrivilegeName, PrivilegeNameLength);
	if ( !Ret ) {
		if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER && !NoErrMsg )
			wprintf(L"LookupPrivilegeName failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	Ret= LookupPrivilegeDisplayName(NULL, PrivilegeName, DisplayName, DisplayNameLength, &LanguageId);
	if ( !Ret ) {
		if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER && !NoErrMsg )
			wprintf(L"LookupPrivilegeDisplayName failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	Ret= FALSE;
	const PRIVILAGENAME_MAPPING *p=PrivilegeNameMapping;
	for ( Index=0 ; p->SymbolName[0]!=0 ; ++p, ++Index ) {
		if ( wcscmp(PrivilegeName, p->PrivilegeName)==0 ) {
			Ret= TRUE;
			break;
		}
	}

	if ( Ret )
		*SymbolName= PrivilegeNameMapping[Index].SymbolName;
	else if ( NoErrMsg )
		wprintf(L"%s not found\n", PrivilegeName);

cleanup:
	return Ret;
}

BOOL LookupPrivilegeValueEx(LPCWSTR SystemName, LPCWSTR Name, PLUID Luid) {
	BOOL Ret= LookupPrivilegeValue(SystemName, Name, Luid);
	if ( !Ret && GetLastError()==ERROR_NO_SUCH_PRIVILEGE ) {
		const PRIVILAGENAME_MAPPING *p;
		for ( p=PrivilegeNameMapping ; p->SymbolName[0]!=0 ; ++p ) {
			if ( wcscmp(Name, p->SymbolName)==0 )
				return LookupPrivilegeValue(SystemName, p->PrivilegeName, Luid);
		}
		SetLastError(ERROR_NO_SUCH_PRIVILEGE);
		Ret= FALSE;
	}
	return Ret;
}

VOID EnumPrivileges(HANDLE Token) {
	BOOL Ret= FALSE;
	DWORD TokenLength= 0;
	PTOKEN_PRIVILEGES TokenPriv= NULL;
	DWORD PrivilegeNameLength= 256;
	DWORD DisplayNameLength= 256;
	PWCHAR PrivilegeName= NULL;
	PWCHAR DisplayName= NULL;
	LPCWCHAR SymbolName= NULL;
	
	// LUID = Locally Unique Identifier
	wprintf(L"-------------------------------------------------------------------------------------------------------\n");
	wprintf(L"   LUID                Symbol                           PrivilegeName                    DisplayName\n");
	wprintf(L"-------------------------------------------------------------------------------------------------------\n");

	if ( Token ) {
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

	}
	else {
		TokenPriv= (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), 0,
			sizeof(DWORD)+sizeof(LUID_AND_ATTRIBUTES)*MAX_PRIVSCAN);
		if ( !TokenPriv ) {
			wprintf(L"HeapAlloc failed - 0x%08x\n", GetLastError());
			goto cleanup;
		}
		
		TokenPriv->PrivilegeCount= MAX_PRIVSCAN;
		for (  LONGLONG i=0 ; i<MAX_PRIVSCAN ; ++i ) {
			TokenPriv->Privileges[i].Luid= *(PLUID)&i;
			TokenPriv->Privileges[i].Attributes= 0;
		}
	}
	
	for ( DWORD i=0 ; i<TokenPriv->PrivilegeCount ; ++i ) {
		do {
			if ( PrivilegeName ) delete [] PrivilegeName;
			if ( DisplayName ) delete [] DisplayName;

			PrivilegeName= new WCHAR[PrivilegeNameLength];
			DisplayName= new WCHAR[DisplayNameLength];

			Ret= LookupPrivilegeName(NULL, &TokenPriv->Privileges[i].Luid, &SymbolName,
					PrivilegeName, &PrivilegeNameLength,
					DisplayName, &DisplayNameLength,
					Token==NULL);
		} while( !Ret && GetLastError()==ERROR_INSUFFICIENT_BUFFER );

		if ( Ret ) {
			wprintf(L"%s 0x%08x`%08x %-32s %-32s %s\n",
				Token ? TokenPriv->Privileges[i].Attributes&SE_PRIVILEGE_ENABLED ? L" O": L" X" : L"  ",
				TokenPriv->Privileges[i].Luid.HighPart,
				TokenPriv->Privileges[i].Luid.LowPart,
				SymbolName,
				PrivilegeName,
				DisplayName);
		}
	}

cleanup:
	if ( PrivilegeName ) delete [] PrivilegeName;
	if ( DisplayName ) delete [] DisplayName;
	if ( TokenPriv ) HeapFree(GetProcessHeap(), 0, TokenPriv);
}


// >0 Enabled
// =0 Disabled
// <0 Not assigned
BOOL CheckPrivilege(HANDLE Token, LPCWSTR PrivilegeName, LPLONG Privileged) {
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

	BOOL Check;
	if ( !PrivilegeCheck(Token, &PrivilegeSet, &Check) ) {
		wprintf(L"PrivilegeCheck failed - 0x%08x\n", GetLastError());
		return FALSE;
	}
	
	if ( Check )
		*Privileged= 1;
	else {
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount= 1;
		tp.Privileges[0].Luid= luid;
		tp.Privileges[0].Attributes= 0;

		if ( !AdjustTokenPrivileges(Token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) ) {
			wprintf(L"AdjustTokenPrivileges failed - 0x%08x\n", GetLastError());
			return FALSE;
		}

		*Privileged= (GetLastError()==ERROR_NOT_ALL_ASSIGNED) ? -1 : 0;
	}

	return TRUE;
}
 
BOOL EnablePrivilege(HANDLE Token, LPWSTR Name, BOOL Enabled) {
	LUID luid;
	if ( !LookupPrivilegeValueEx(NULL, Name, &luid) ) {
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
	
	if ( GetLastError()==ERROR_NOT_ALL_ASSIGNED ) {
		wprintf(L"The process token does not have %s (%I64d).\n", Name, luid);
		return FALSE;
	}

	wprintf(L"%s (%I64d) is temporarily %s.\n", Name, luid,
		Enabled ? L"enabled" : L"disabled");

	return TRUE;
}
