//
// logue.h
//

#pragma once

BOOL DumpSecurityDescriptorFromUserObject(HANDLE);

BOOL GetTokenSID(HANDLE, PSID*);
VOID FreeLogonSID(PSID*);

BOOL AddAceToWindowStation(HWINSTA, PSID);
BOOL AddAceToDesktop(HDESK, PSID);
BOOL RemoveAceFromWindowStation(HWINSTA, PSID);
BOOL RemoveAceFromDesktop(HDESK, PSID);

VOID EnumPrivileges(HANDLE);
BOOL CheckPrivilege(HANDLE, LPCWSTR, LPBOOL);
BOOL EnablePrivilege(HANDLE, LPWSTR, BOOL);
