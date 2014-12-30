//
// main.cpp
//

#include <windows.h>
#include <ntsecapi.h>

static BOOL ConvertNameToSid(LPTSTR, PSID *);

int WINAPI wWinMain(HINSTANCE hinst, HINSTANCE hinstPrev, LPWSTR lpszCmdLine, int nCmdShow)
{
	PSID                  pSid;
	NTSTATUS              ns;
	LSA_HANDLE            hpolicy;
	LSA_UNICODE_STRING    lsaString[2];
	LSA_OBJECT_ATTRIBUTES objectAttributes = {0};

	objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

	ns = LsaOpenPolicy(NULL, &objectAttributes, POLICY_ALL_ACCESS, &hpolicy);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		MessageBox(NULL, TEXT("LsaOpenPolicy failed."), NULL, MB_ICONWARNING);
		return 0;
	}

	ConvertNameToSid(TEXT("Administrators"), &pSid);

	lsaString[0].Buffer        = SE_ASSIGNPRIMARYTOKEN_NAME;
	lsaString[0].Length        = (USHORT)(lstrlen(lsaString[0].Buffer) * sizeof(WCHAR));
	lsaString[0].MaximumLength = lsaString[0].Length + sizeof(WCHAR);

	lsaString[1].Buffer        = SE_INCREASE_QUOTA_NAME;
	lsaString[1].Length        = (USHORT)(lstrlen(lsaString[1].Buffer) * sizeof(WCHAR));
	lsaString[1].MaximumLength = lsaString[1].Length + sizeof(WCHAR);

	ns = LsaAddAccountRights(hpolicy, pSid, lsaString, 2);
	if (LsaNtStatusToWinError(ns) == ERROR_SUCCESS)
		MessageBox(NULL, TEXT("AddPriv succeeded."), TEXT("OK"), MB_OK);
	else
		MessageBox(NULL, TEXT("AddPriv failed."), NULL, MB_ICONWARNING);

	HeapFree(GetProcessHeap(), 0, pSid);

	LsaClose(hpolicy);

	return 0;
}

static BOOL ConvertNameToSid(LPTSTR lpszName, PSID *ppsid)
{
	TCHAR        szDomain[256];
	DWORD        dwSidLen    = 0;
	DWORD        dwDomainLen = sizeof(szDomain);
	SID_NAME_USE snu;
	
	LookupAccountName(NULL, lpszName, NULL, &dwSidLen, szDomain, &dwDomainLen, &snu);

	*ppsid = (PSID)HeapAlloc(GetProcessHeap(), 0, dwSidLen);

	return LookupAccountName(NULL, lpszName, *ppsid, &dwSidLen, szDomain, &dwDomainLen, &snu);
}
