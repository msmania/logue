//
// main.cpp
//

#include <windows.h>

/*

Usage: filehalt <file> <time>

file: file to access
time: halting time [sec]

*/

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
	int argc= 0;
	LPWSTR *argv= CommandLineToArgvW(GetCommandLine(), &argc);
	if ( argv==NULL || argc!=3 ) {
		// bad parameter
		goto err;
	}
	
	int halting= _wtoi(argv[2]);
	if ( halting<0 )
		halting= 0;

	HANDLE h= CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( h==INVALID_HANDLE_VALUE ) {
		if ( GetLastError()==ERROR_ALREADY_EXISTS ) {
			h= CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL,
				CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			if ( h==INVALID_HANDLE_VALUE ) {
				goto err;
			}
		}
		else {
			goto err;
		}
	}

	Sleep(halting*1000);

	CloseHandle(h);

	return 0;

err:
	if ( argv!=NULL )
		LocalFree(argv);

	return 1;
}
