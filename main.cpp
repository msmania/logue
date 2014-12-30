//
// main.cpp
//

#include <iostream>
#include <stdio.h>
#include <locale.h>
#include <Windows.h>

#include "logue.h"

using namespace std;

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

void ShowUsage() {
	wcout << L"\nUsage: logue -runas <user> <password> <command>" << endl;
	wcout << L"       logue -priv All" << endl;
	wcout << L"       logue -priv Enum" << endl;
	wcout << L"       logue -priv Check <privilege>" << endl;
	wcout << L"       logue -priv Enable <privilege>" << endl;
	wcout << L"       logue -priv Disable <privilege>" << endl << endl;
	wcout << L"Example:" << endl;
	wcout << L"    logue -runas domain\\user password \"c:\\windows\\system32\\notepad.exe c:\\temp\\temp.txt\"" << endl;
	wcout << L"    logue -priv check SeSecurityPrivilege" << endl << endl;
	wcout << L"Privilege: http://msdn.microsoft.com/en-us/library/bb530716.aspx" << endl << endl;
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
	}
	else if ( wcscmp(Command, L"-PRIV")==0 ) {
		HANDLE Token= NULL;
		if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS , &Token) ) {
			wprintf(L"OpenProcessToken failed - 0x%08x\n", GetLastError());
			return 0;
		}

		Command= ToUpper(argv[2]);
		if ( wcscmp(Command, L"ENUM")==0 )
			EnumPrivileges(Token);
		else if ( wcscmp(Command, L"ALL")==0 )
			EnumPrivileges(NULL);
		else if ( argc>=4 && wcscmp(Command, L"CHECK")==0 ) {
			LONG Ret= 0;
			if ( CheckPrivilege(Token, argv[3], &Ret) )
				wprintf(L"%s is %s.\n", argv[3],
					Ret>0 ? L"ENABLED" :
					Ret<0 ? L"NOT ASSIGNED" : L"DISABLED");
		}
		else if ( argc>=4 && wcscmp(Command, L"ENABLE")==0 ) {
			if ( EnablePrivilege(Token, argv[3], TRUE) )
				EnumPrivileges(Token);
		}
		else if ( argc>=4 && wcscmp(Command, L"DISABLE")==0 ) {
			if ( EnablePrivilege(Token, argv[3], FALSE) )
				EnumPrivileges(Token);
		}
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
