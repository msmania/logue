//
// logue.h
//

#pragma once

//#define _GUI
//#define _TRACING

VOID EnumPrivileges(HANDLE Token);
BOOL EnablePrivilege(HANDLE Token, LPWSTR Name, BOOL Enabled);
BOOL CheckPrivilege(HANDLE Token, LPCWSTR PrivilegeName, LPLONG Privileged);

BOOL GetLogonSidFromToken(HANDLE Token, PSID *outSid);
BOOL AddAceToWindowStation(HWINSTA Winsta, PSID Sid);
BOOL AddAceToDesktop(HDESK Desktop, PSID Sid);
BOOL RemoveAccessAllowedAcesBasedSID(HANDLE Object, PSID Sid);

VOID RunAs(LPWSTR inUser, LPWSTR inPW, LPWSTR inCommand);
