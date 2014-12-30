//
// dacl.cpp
//

#include <Windows.h>
#include <Sddl.h>
#include <stdio.h>

#include "logue.h"

// add ACCESS_ALLOWED_ACEs of the specified SID to the object's DACL
BOOL AddAccessAllowedAceBasedSID(HANDLE Object, PSID Sid, DWORD AceCount,
								CONST DWORD AceFlags[], CONST DWORD AccessMasks[]) {
	BOOL Ret= FALSE;
	SECURITY_INFORMATION DaclInfo= DACL_SECURITY_INFORMATION;
	PACL Acl= NULL; // no need to free
	PACL AclNew= NULL;
	PSECURITY_DESCRIPTOR Sd= NULL;
	PSECURITY_DESCRIPTOR SdNew= NULL;
	DWORD SdSize= 0;
	DWORD SdSizeNeeded= 0;
	ACL_SIZE_INFORMATION AclSizeInfo;
	DWORD AclSize= 0;
	BOOL DaclPresent;
	BOOL DaclDefaulted;

	//
	// Obtain DACL from the object.
	// http://msdn.microsoft.com/en-us/library/aa379573
	//
	if ( !GetUserObjectSecurity(Object, &DaclInfo, Sd, 0, &SdSizeNeeded) ) {
		if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER )
			goto cleanup;
			
		Sd= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SdSizeNeeded);
		if ( Sd==NULL ) goto cleanup;

		SdSize= SdSizeNeeded;
		if ( !GetUserObjectSecurity(Object, &DaclInfo, Sd, SdSize, &SdSizeNeeded) )
			goto cleanup;
	}

	// Obtain the DACL from the security descriptor.
	if ( !GetSecurityDescriptorDacl(Sd, &DaclPresent, &Acl, &DaclDefaulted) )
		goto cleanup;

	// Initialize.
	ZeroMemory(&AclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
	AclSizeInfo.AclBytesInUse = sizeof(ACL);
	if ( Acl ) {
		if (!GetAclInformation(Acl, (LPVOID)&AclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation) )
			goto cleanup;
	}

	// Create a new ACL
	// (original ACL + new ACCESS_ALLOWED_ACEs)
	AclSize= AclSizeInfo.AclBytesInUse +
		AceCount * (sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(Sid) - sizeof(DWORD));
	AclNew= (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AclSize);
	if ( AclNew==NULL ) goto cleanup;

	if ( !InitializeAcl(AclNew, AclSize, ACL_REVISION) )
		goto cleanup;

	// If DACL is present, copy all the ACEs to a new DACL.
	if ( DaclPresent && AclSizeInfo.AceCount ) {
		for ( DWORD i=0; i < AclSizeInfo.AceCount; ++i ) {
			PVOID Ace= NULL;
			if ( !GetAce(Acl, i, &Ace) ) goto cleanup;

			if (!AddAce(AclNew, ACL_REVISION, MAXDWORD, Ace, ((PACE_HEADER)Ace)->AceSize) )
				goto cleanup;
		}
	}

	// Add new ACEs of specified SID to the DACL
	for ( DWORD i=0 ; i<AceCount ; ++i ) {
		if (!AddAccessAllowedAceEx(AclNew, ACL_REVISION, AceFlags[i], AccessMasks[i], Sid) )
			goto cleanup;
	}

	// Create a new security descriptor.
	// SECURITY_DESCRIPTOR_MIN_LENGTH is enough because SetSecurityDescriptorDacl creates absolute security descriptor
	SdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if ( SdNew==NULL ) goto cleanup;

	if ( !InitializeSecurityDescriptor(SdNew, SECURITY_DESCRIPTOR_REVISION) )
		goto cleanup;

	// Set new DACL to the new security descriptor.
	// (this security descriptor becomes an absolute SD)
	if ( !SetSecurityDescriptorDacl(SdNew, TRUE, AclNew, FALSE) )
		goto cleanup;
	
#ifdef _TRACING
	wprintf(L"Original SD: %p\n", Sd);
	wprintf(L"New SD     : %p\n", SdNew);
	wprintf(L"-->\n");
	getwchar();
#endif

	// Set the new security descriptor for the desktop object.
	if (!SetUserObjectSecurity(Object, &DaclInfo, SdNew))
		goto cleanup;

	Ret= TRUE;

cleanup:
	if ( AclNew ) HeapFree(GetProcessHeap(), 0, AclNew);
	if ( Sd ) HeapFree(GetProcessHeap(), 0, Sd);
	if ( SdNew ) HeapFree(GetProcessHeap(), 0, SdNew);

	return Ret;
}

// add ACCESS_ALLOWED_ACEs of the specified SID to the object's DACL
BOOL RemoveAccessAllowedAcesBasedSID(HANDLE Object, PSID Sid) {
	BOOL Ret= FALSE;
	SECURITY_INFORMATION DaclInfo= DACL_SECURITY_INFORMATION;
	PACL Acl= NULL; // no need to free
	PACL AclNew= NULL;
	PSECURITY_DESCRIPTOR Sd= NULL;
	PSECURITY_DESCRIPTOR SdNew= NULL;
	DWORD SdSize= 0;
	DWORD SdSizeNeeded= 0;
	ACL_SIZE_INFORMATION AclSizeInfo;
	DWORD AclSize= 0;
	BOOL DaclPresent;
	BOOL DaclDefaulted;

	//
	// Obtain DACL from the object.
	// http://msdn.microsoft.com/en-us/library/aa379573
	//
	if ( !GetUserObjectSecurity(Object, &DaclInfo, Sd, 0, &SdSizeNeeded) ) {
		if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER )
			goto cleanup;
			
		Sd= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SdSizeNeeded);
		if ( Sd==NULL ) goto cleanup;

		SdSize= SdSizeNeeded;
		if ( !GetUserObjectSecurity(Object, &DaclInfo, Sd, SdSize, &SdSizeNeeded) )
			goto cleanup;
	}

	// Obtain the DACL from the security descriptor.
	if ( !GetSecurityDescriptorDacl(Sd, &DaclPresent, &Acl, &DaclDefaulted) )
		goto cleanup;

	if ( !DaclPresent || !Acl || Acl->AceCount==0 ) {
		// nothing to do for Null DACL or Empty DACL
		// http://technet.microsoft.com/ja-jp/query/aa379286
		Ret= TRUE;
		goto cleanup;
	}

	// Initialize.
	ZeroMemory(&AclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
	if (!GetAclInformation(Acl, (LPVOID)&AclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation) )
		goto cleanup;

	// Create an ACL copy
	AclSize= AclSizeInfo.AclBytesInUse;
	AclNew= (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AclSize);
	if ( AclNew==NULL ) goto cleanup;

	if ( !InitializeAcl(AclNew, AclSize, ACL_REVISION) )
		goto cleanup;
	
	// do not copy ACCESS_ALLOWED_ACEs of the specified SID
	if ( DaclPresent && AclSizeInfo.AceCount ) {
		for ( DWORD i=0; i < AclSizeInfo.AceCount; ++i ) {
			PVOID Ace= NULL;
			if ( !GetAce(Acl, i, &Ace) ) goto cleanup;
			
			if ( ((PACE_HEADER)Ace)->AceType==ACCESS_ALLOWED_ACE_TYPE &&
					EqualSid(Sid, &((ACCESS_ALLOWED_ACE*)Ace)->SidStart) )
				continue;

			if (!AddAce(AclNew, ACL_REVISION, MAXDWORD, Ace, ((PACE_HEADER)Ace)->AceSize) )
				goto cleanup;
		}
	}
	
	// Create a new security descriptor.
	// SECURITY_DESCRIPTOR_MIN_LENGTH is enough because SetSecurityDescriptorDacl creates absolute security descriptor
	SdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if ( SdNew==NULL ) goto cleanup;

	if ( !InitializeSecurityDescriptor(SdNew, SECURITY_DESCRIPTOR_REVISION) )
		goto cleanup;

	// Set new DACL to the new security descriptor.
	// (this security descriptor becomes an absolute SD)
	if ( !SetSecurityDescriptorDacl(SdNew, TRUE, AclNew, FALSE) )
		goto cleanup;
	
#ifdef _TRACING
	wprintf(L"Original SD: %p\n", Sd);
	wprintf(L"New SD     : %p\n", SdNew);
	wprintf(L"-->\n");
	getwchar();
#endif

	// Set the new security descriptor for the desktop object.
	if (!SetUserObjectSecurity(Object, &DaclInfo, SdNew))
		goto cleanup;

	Ret= TRUE;

cleanup:
	if ( AclNew ) HeapFree(GetProcessHeap(), 0, AclNew);
	if ( Sd ) HeapFree(GetProcessHeap(), 0, Sd);
	if ( SdNew ) HeapFree(GetProcessHeap(), 0, SdNew);

	return Ret;
}

BOOL AddAceToDesktop(HDESK Desktop, PSID Sid) {
	CONST DWORD AccessMasks[1] = {
		DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
		DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
		DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |
		STANDARD_RIGHTS_REQUIRED
	};

	DWORD AceFlags[1] = {0};

	return AddAccessAllowedAceBasedSID(Desktop, Sid, 1, AceFlags, AccessMasks);
}

BOOL AddAceToWindowStation(HWINSTA Winsta, PSID Sid) {
	CONST DWORD AccessMasks[2] = {
		GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL,
		WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | WINSTA_ACCESSCLIPBOARD |
		WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES | WINSTA_ACCESSGLOBALATOMS |
		WINSTA_EXITWINDOWS | WINSTA_ENUMERATE | WINSTA_READSCREEN |
		STANDARD_RIGHTS_REQUIRED};

	CONST DWORD AceFlags[2] = {
		CONTAINER_INHERIT_ACE|INHERIT_ONLY_ACE|OBJECT_INHERIT_ACE,
		NO_PROPAGATE_INHERIT_ACE
	};	

	return AddAccessAllowedAceBasedSID(Winsta, Sid, 2, AceFlags, AccessMasks);
}

BOOL GetLogonSidFromToken(HANDLE Token, PSID *outSid) {
	BOOL Ret= FALSE;
	DWORD TokenGroupLength= 0;
	DWORD SidLength= 0;
	PTOKEN_GROUPS TokenGroup= NULL;
	LPWSTR SidString= NULL;

	if ( !GetTokenInformation(Token, TokenGroups, (LPVOID)TokenGroup, 0, &TokenGroupLength) &&
			GetLastError()!=ERROR_INSUFFICIENT_BUFFER ) {
		wprintf(L"GetTokenInformation (1st chance) failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	TokenGroup= (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TokenGroupLength);
	if ( !TokenGroup ) {
		wprintf(L"HeapAlloc failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	if ( !GetTokenInformation(Token, TokenGroups, (LPVOID)TokenGroup, TokenGroupLength, &TokenGroupLength) ) {
		wprintf(L"GetTokenInformation failed (2nd chance) - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	//
	// SE_GROUP_LOGON_ID
	// The SID is a logon SID that identifies the logon session associated with an access token.
	// http://technet.microsoft.com/en-us/library/aa379624
	//
	for ( DWORD i=0 ; i<TokenGroup->GroupCount ; ++i ) {
		if ( SidString ) LocalFree(SidString);
		ConvertSidToStringSid(TokenGroup->Groups[i].Sid, &SidString);
		wprintf(L"SID: %s", SidString);

		if ( (TokenGroup->Groups[i].Attributes&SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID ) {
			SidLength= GetLengthSid(TokenGroup->Groups[i].Sid);

			*outSid= (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SidLength);
			if ( *outSid==NULL ) {

				wprintf(L"HeapAlloc failed - 0x%08x\n", GetLastError());
				goto Cleanup;
			}

			if ( !CopySid(SidLength, *outSid, TokenGroup->Groups[i].Sid) ) {
				wprintf(L"CopySid failed - 0x%08x\n", GetLastError());
				HeapFree(GetProcessHeap(), 0, (LPVOID)*outSid);
				goto Cleanup;
			}

			wprintf(L" (Logon)\n");
			break;
		}
		else
			wprintf(L"\n");
	}
	
	Ret= TRUE;

Cleanup:
	if ( SidString ) LocalFree(SidString);
	if ( TokenGroup ) HeapFree(GetProcessHeap(), 0, TokenGroup);
	return Ret;
}
