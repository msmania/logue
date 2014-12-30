//
// main.cpp
//

#include <stdio.h>
#include <locale.h>
#include <Windows.h>

#include "logue.h"

/*

Usage: logue -runas <user> <password> <command>
       logue -priv Enum
	   logue -priv Check <privilege>
	   logue -priv Enable <privilege>
	   logue -priv Disable <privilege>

Example:
    logue domain\user password "c:\windows\system32\notepad.exe c:\temp\temp.txt"
    logue -priv check SeSecurityPrivilege

Privilege: http://msdn.microsoft.com/en-us/library/bb530716.aspx

*/

void RunAs(LPWSTR, LPWSTR, LPWSTR);

void ShowUsage() {
	wprintf(L"\nUsage: logue -runas <user> <password> <command>\n");
	wprintf(L"       logue -priv Enum\n       logue -priv Check <privilege>\n");
	wprintf(L"       logue -priv Enable <privilege>\n");
	wprintf(L"       logue -priv Disable <privilege>\n\nExample:\n");
	wprintf(L"    logue domain\\user password ");
	wprintf(L"\"c:\\windows\\system32\\notepad.exe c:\\temp\\temp.txt\"\n");
	wprintf(L"    logue -priv check SeSecurityPrivilege\n\n");
	wprintf(L"Privilege: http://msdn.microsoft.com/en-us/library/bb530716.aspx\n\n");
}

#define MAX_COMMAND 16

static wchar_t upperstr[MAX_COMMAND+1];
const wchar_t *ToUpper(const wchar_t *s) {
	for ( int i=0 ; i<MAX_COMMAND+1 ; ++i ) {
		upperstr[i]= toupper(s[i]);
		if ( s[i]==0 )
			return upperstr;
	}
	upperstr[MAX_COMMAND]= 0;
	return upperstr;
}

int wmain(int argc, wchar_t *argv[]) {
	_wsetlocale(LC_ALL, L"");
	
	if ( argc<3 ) {
		ShowUsage();
		return ERROR_INVALID_PARAMETER;
	}

	LPCWSTR Command= ToUpper(argv[1]);
	if ( wcscmp(Command, L"-RUNAS")==0 ) {
		if ( argc<5 ) {
			ShowUsage();
			return ERROR_INVALID_PARAMETER;
		}

		RunAs(argv[2], argv[3], argv[4]);

		return 0;
	}
	else if ( wcscmp(Command, L"-PRIV")==0 ) {
		HANDLE Token= NULL;
		if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS , &Token) ) {
			wprintf(L"Failed to get Token - 0x%08x\n", GetLastError());
			return 0;
		}

		Command= ToUpper(argv[2]);
		if ( wcscmp(Command, L"ENUM")==0 ) {
			EnumPrivileges(Token);
		}
		else if ( argc>=4 && wcscmp(Command, L"CHECK")==0 ) {
			BOOL Ret= FALSE;
			if ( CheckPrivilege(Token, argv[3], &Ret) )
				wprintf(L"%s is %s.\n", argv[3], Ret ? L"ENABLED" : L"DISABLED");
		}
		else if ( argc>=4 && wcscmp(Command, L"ENABLE")==0 )
			EnablePrivilege(Token, argv[3], TRUE);
		else if ( argc>=4 && wcscmp(Command, L"DISABLE")==0 )
			EnablePrivilege(Token, argv[3], FALSE);
		else {
			wprintf(L"Bad command - %s\n", argv[1]);
			return ERROR_BAD_COMMAND;
		}

		if ( Token ) CloseHandle(Token);
	}
	else {
		ShowUsage();
		wprintf(L"Unknown command - %s\n", argv[1]);
		return ERROR_INVALID_PARAMETER;
	}
	
	return 0;
}
