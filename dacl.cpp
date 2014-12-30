//
// dacl.cpp
//

#include <Windows.h>
#include <Sddl.h>
#include <stdio.h>
#include "logue.h"


#define DESKTOP_ALL \
	(DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | \
	 DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | \
	 DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP | \
	 STANDARD_RIGHTS_REQUIRED)

#define WINSTA_ALL ( \
	WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | WINSTA_ACCESSCLIPBOARD | \
	WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES | WINSTA_ACCESSGLOBALATOMS | \
	WINSTA_EXITWINDOWS | WINSTA_ENUMERATE | WINSTA_READSCREEN | \
	STANDARD_RIGHTS_REQUIRED)

#define GENERIC_ACCESS (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)

BOOL DumpSecurityDescriptorFromUserObject(HANDLE Object) {
	BOOL Ret= FALSE;
	PSECURITY_DESCRIPTOR Sd= NULL;
	LPWSTR Sddl= NULL;
	DWORD SdLength= 0;

	SECURITY_INFORMATION SecInfo=
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
		//DACL_SECURITY_INFORMATION;

	if ( !GetUserObjectSecurity(Object, &SecInfo, NULL, SdLength, &SdLength) && GetLastError()!=ERROR_INSUFFICIENT_BUFFER ) {
		wprintf(L"GetUserObjectSecurity (size-check) failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	Sd= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, SdLength);
	if ( !Sd ) {
		wprintf(L"HeapAlloc failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}
	
	if ( !GetUserObjectSecurity(Object, &SecInfo, Sd, SdLength, &SdLength) ) {
		wprintf(L"GetUserObjectSecurity failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	if ( !ConvertSecurityDescriptorToStringSecurityDescriptor(Sd, SDDL_REVISION_1, SecInfo, &Sddl, NULL) ) {
		wprintf(L"ConvertSecurityDescriptorToStringSecurityDescriptor failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	wprintf(L"SDDL => %s\n", Sddl);

	Ret= TRUE;

cleanup:
	if ( Sddl ) LocalFree(Sddl);
	if ( Sd ) HeapFree(GetProcessHeap(), 0, Sd);
	
	return Ret;
}

BOOL AddAceToWindowStation(HWINSTA hwinsta, PSID psid) {
	BOOL ret= FALSE;
	
	PSECURITY_DESCRIPTOR psd= NULL;
	PSECURITY_DESCRIPTOR psdNew= NULL;
	ACCESS_ALLOWED_ACE *pace= NULL;
	PACL pNewAcl= NULL;

	__try {
		// Obtain the DACL for the window station.
		DWORD dwSidSize= 0;
		DWORD dwSdSizeNeeded= 0;
		SECURITY_INFORMATION si= DACL_SECURITY_INFORMATION;
		if ( !GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize, &dwSdSizeNeeded) ) {
			if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER )
				__leave;

			psd= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
			if (psd == NULL)
				__leave;

			psdNew= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
			if (psdNew == NULL)
				__leave;

			dwSidSize= dwSdSizeNeeded;
			if ( !GetUserObjectSecurity(hwinsta, &si, psd, dwSdSizeNeeded, &dwSdSizeNeeded) )
				__leave;
		}

		// Create a new DACL.
		if ( !InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION) )
			__leave;

		// Get the DACL from the security descriptor.
		BOOL bDaclExist;
		BOOL bDaclPresent;
		PACL pacl;
		if ( !GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist) )
			__leave;

		// Initialize the ACL.
		ACL_SIZE_INFORMATION aclSizeInfo;
		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse= sizeof(ACL);

		// Call only if the DACL is not NULL.
		if ( pacl ) {
			// get the file ACL size info
			if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation) )
				__leave;
		}

		// Allocate memory for the new ACL.
		DWORD dwNewAclSize= aclSizeInfo.AclBytesInUse +
			2 * (sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
		pNewAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
		if (pNewAcl == NULL)
			__leave;

		// Initialize the new DACL.
		if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
			__leave;

		// If DACL is present, copy it to a new DACL.
		if (bDaclPresent && aclSizeInfo.AceCount) {
			for ( DWORD i=0; i < aclSizeInfo.AceCount; ++i ) {
				PVOID pTempAce= NULL;
				if ( !GetAce(pacl, i, &pTempAce) )
					__leave;

				if ( !AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize) )
					__leave;
			}
		}

		// Add the first ACE to the window station.
		pace = (ACCESS_ALLOWED_ACE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
		if (pace == NULL)
			__leave;

		pace->Header.AceType= ACCESS_ALLOWED_ACE_TYPE;
		pace->Header.AceFlags= CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
		pace->Header.AceSize= (WORD)GetLengthSid(psid) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD);
		pace->Mask= GENERIC_ACCESS;

		if ( !CopySid(GetLengthSid(psid), &pace->SidStart, psid) )
			__leave;

		if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize) )
			__leave;

		// Add the second ACE to the window station.
		pace->Header.AceFlags= NO_PROPAGATE_INHERIT_ACE;
		pace->Mask= WINSTA_ALL;

		if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize) )
			__leave;

		// Set a new DACL for the security descriptor.
		if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE) )
			__leave;

		// Set the new security descriptor for the window station.
		if (!SetUserObjectSecurity(hwinsta, &si, psdNew))
			__leave;

		// Indicate success.
		ret= TRUE;
	}
	__finally {
		// Free the allocated buffers.
		if (pace != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pace);

		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}

	return ret;
}

BOOL AddAceToDesktop(HDESK hdesk, PSID psid) {
	BOOL ret= FALSE;

	PACL pacl= NULL;
	PACL pNewAcl= NULL;
	PSECURITY_DESCRIPTOR psd= NULL;
	PSECURITY_DESCRIPTOR psdNew= NULL;

	__try {
		// Obtain the security descriptor for the desktop object.
		DWORD dwSidSize = 0;
		DWORD dwSdSizeNeeded= 0;
		SECURITY_INFORMATION si= DACL_SECURITY_INFORMATION;
		if ( !GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded) ) {
			if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER )
				__leave;
			
			psd= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
			if (psd == NULL)
				__leave;

			psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
			if ( psdNew==NULL )
				__leave;

			dwSidSize= dwSdSizeNeeded;
			if ( !GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded) )
				__leave;
		}

		// Create a new security descriptor.
		if ( !InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION) )
			__leave;
	
		// Obtain the DACL from the security descriptor.
		BOOL bDaclExist;
		BOOL bDaclPresent;
		if ( !GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist) )
			__leave;

		// Initialize.
		ACL_SIZE_INFORMATION aclSizeInfo;
		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);
		if (pacl != NULL) {
			if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation) )
				__leave;
		}

		// Allocate buffer for the new ACL.
		DWORD dwNewAclSize= aclSizeInfo.AclBytesInUse +
			sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD);
		pNewAcl= (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
		if ( pNewAcl==NULL )
			__leave;

		// Initialize the new ACL.
		if ( !InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION) )
			__leave;

		// If DACL is present, copy it to a new DACL.
		if ( bDaclPresent && aclSizeInfo.AceCount ) {
			for ( DWORD i=0; i < aclSizeInfo.AceCount; ++i ) {
				PVOID pTempAce= NULL;
				if (!GetAce(pacl, i, &pTempAce))
					__leave;

				if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize) )
					__leave;
			}
		}

		// Add ACE to the DACL.
		if (!AddAccessAllowedAce(pNewAcl, ACL_REVISION, DESKTOP_ALL, psid) )
			__leave;

		// Set new DACL to the new security descriptor.
		if ( !SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE) )
			__leave;

		// Set the new security descriptor for the desktop object.
		if (!SetUserObjectSecurity(hdesk, &si, psdNew))
			__leave;

		ret= TRUE;
	}
	__finally {
		if (pNewAcl!= NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}

	return ret;
}

BOOL GetTokenSID(HANDLE Token, PSID *outSid) {
	BOOL ret= FALSE;
	DWORD TokenGroupLength= 0;
	DWORD SidLength= 0;
	PTOKEN_GROUPS TokenGroup= NULL;

	if ( !GetTokenInformation(Token, TokenGroups, (LPVOID)TokenGroup, 0, &TokenGroupLength) &&
			GetLastError()!=ERROR_INSUFFICIENT_BUFFER ) {
		wprintf(L"GetTokenInformation (size check) failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	TokenGroup= (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TokenGroupLength);
	if ( !TokenGroup ) {
		wprintf(L"HeapAlloc failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	if ( !GetTokenInformation(Token, TokenGroups, (LPVOID)TokenGroup, TokenGroupLength, &TokenGroupLength) ) {
		wprintf(L"GetTokenInformation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	// Loop through the groups to find the logon SID.
	for ( DWORD i=0 ; i<TokenGroup->GroupCount ; ++i ) {
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
			break;
		}
	}

	ret= TRUE;

Cleanup: 
	if ( TokenGroup ) HeapFree(GetProcessHeap(), 0, TokenGroup);
	return ret;
}

VOID FreeLogonSID(PSID *ppsid) {
    HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
}

BOOL RemoveAceFromWindowStation(HWINSTA hwinsta, PSID psid) {
	BOOL ret= FALSE;

	PACL pacl= NULL;
	PACL pNewAcl;
	PSECURITY_DESCRIPTOR psd= NULL;
	PSECURITY_DESCRIPTOR psdNew= NULL;

	__try {
		// Obtain the DACL for the window station.
		DWORD dwSidSize = 0;
		DWORD dwSdSizeNeeded;
		SECURITY_INFORMATION si= DACL_SECURITY_INFORMATION;
		if ( !GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize, &dwSdSizeNeeded) ) {
			if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER )
				__leave;
			
			psd= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
			if ( psd==NULL )
				__leave;

			psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
			if ( psdNew==NULL )
				__leave;

			dwSidSize= dwSdSizeNeeded;
			if ( !GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize, &dwSdSizeNeeded) )
				__leave;
		}

		// Create a new DACL.
		if ( !InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION) )
			__leave;
		
		// Get the DACL from the security descriptor.
		BOOL bDaclExist;
		BOOL bDaclPresent;
		if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist) )
			__leave;

		// Initialize the ACL.
		ACL_SIZE_INFORMATION aclSizeInfo;
		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse= sizeof(ACL);

		if ( pacl!=NULL ) {
			// get the file ACL size info
			if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation) )
				__leave;
		}

		// Compute the size of the new ACL.
		DWORD dwNewAclSize= aclSizeInfo.AclBytesInUse +
			2 * (sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));

		// Allocate memory for the new ACL.
		pNewAcl= (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
		if ( pNewAcl==NULL )
			__leave;

		// Initialize the new DACL.
		if ( !InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION) )
			__leave;

		// If DACL is present, copy it to a new DACL.
		if ( bDaclPresent && aclSizeInfo.AceCount ) {
			for ( DWORD i=0 ; i<aclSizeInfo.AceCount ; i++ ) {
				ACCESS_ALLOWED_ACE *pTempAce;
				if (!GetAce(pacl, i, reinterpret_cast<void**>(&pTempAce)))
					__leave;

				if ( !EqualSid(psid, &pTempAce->SidStart) ) {
					if ( !AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize) )
						__leave;
				}
			}
		}

		// Set a new DACL for the security descriptor.
		if ( !SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE) )
			__leave;

		// Set the new security descriptor for the window station.
		if ( !SetUserObjectSecurity(hwinsta, &si, psdNew) )
			__leave;

		ret= TRUE;
	}
	__finally {
		if( pacl != NULL )
			HeapFree(GetProcessHeap(), 0, (LPVOID)pacl);

		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}

	return ret;
}

BOOL RemoveAceFromDesktop(HDESK hdesk, PSID psid) {
	BOOL ret= FALSE;

	PACL pacl= NULL;
	PACL pNewAcl= NULL;
	PSECURITY_DESCRIPTOR psd= NULL;
	PSECURITY_DESCRIPTOR psdNew= NULL;

	__try {
		// Obtain the security descriptor for the desktop object.
		DWORD dwSidSize= 0;
		DWORD dwSdSizeNeeded;
		SECURITY_INFORMATION si= DACL_SECURITY_INFORMATION;
		if ( !GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded) ) {
			if ( GetLastError()!=ERROR_INSUFFICIENT_BUFFER )
				__leave;

			psd= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded );
			if ( psd==NULL )
				__leave;

			psdNew= (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
			if ( psdNew==NULL)
				__leave;

			dwSidSize= dwSdSizeNeeded;
			if (!GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded) )
				__leave;
		}

		// Create a new security descriptor.
		if ( !InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION) )
			__leave;

		// Obtain the DACL from the security descriptor.
		BOOL bDaclExist;
		BOOL bDaclPresent;
		if ( !GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist) )
			__leave;

		ACL_SIZE_INFORMATION aclSizeInfo;
		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);

		if ( pacl!=NULL ) {
			// Determine the size of the ACL information.
			if ( !GetAclInformation(pacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation) )
				__leave;
		}

		// Compute the size of the new ACL.
		DWORD dwNewAclSize= aclSizeInfo.AclBytesInUse +
			sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD);

		// Allocate buffer for the new ACL.
		pNewAcl= (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
		if (pNewAcl == NULL)
			__leave;

		// Initialize the new ACL.
		if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
			__leave;

		// If DACL is present, copy it to a new DACL.
		if (bDaclPresent && aclSizeInfo.AceCount) {
			for ( DWORD i=0; i < aclSizeInfo.AceCount; i++) {
				ACCESS_ALLOWED_ACE*  pTempAce;
				if (!GetAce(pacl, i, reinterpret_cast<void**>(&pTempAce)))
					__leave;

				if ( !EqualSid(psid, &pTempAce->SidStart) ) {
					// Add the ACE to the new ACL.
					if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize) )
						__leave;
				}
			}
		}

		// Set new DACL to the new security descriptor.
		if ( !SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE) )
			__leave;

		// Set the new security descriptor for the desktop object.
		if ( !SetUserObjectSecurity(hdesk, &si, psdNew) )
			__leave;

		ret= TRUE;
	}
	__finally {
		if( pacl != NULL )
			HeapFree(GetProcessHeap(), 0, (LPVOID)pacl);

		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}

	return ret;
}
