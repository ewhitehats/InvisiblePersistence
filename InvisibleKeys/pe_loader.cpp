// kovter_inmemoryLoader.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <DbgHelp.h> 
#include <winternl.h>
#include <strsafe.h>

struct RELOCATION
{
	WORD    Offset : 12;
	WORD    Type : 4;
};
_IMAGE_BASE_RELOCATION *PE_fixupRelocations(char* newBase, IMAGE_NT_HEADERS *src, DWORD offset);

typedef BOOL(WINAPI *LOADER_FNDLLMAIN)(HINSTANCE hModule, DWORD dwReason, LPVOID); /* DllMain */

int main(int argc, char *argv[])
{
	HANDLE hDll = NULL;
	IMAGE_DOS_HEADER *dosHeader = NULL;
	IMAGE_NT_HEADERS *ntHeader = NULL;
	DWORD fileSize = 0;
	char *dllBuf = NULL;
	DWORD bytesRead = 0;
	char *base = NULL;

	printf("Usage: %s [dll or exe to load]\n", argv[0]);

	hDll = CreateFileA(argv[1],               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template

	if (hDll == INVALID_HANDLE_VALUE)
	{
		printf("Couldn't open the dll/ exe file from disk!\n");
		return 1;
	}

	fileSize = GetFileSize(hDll, NULL);
	printf("filesize 0x%X\n", fileSize);
	if (INVALID_FILE_SIZE == fileSize) {
		printf("Couldn't get the file size!\n");
		return 1;
	}

	dllBuf = (char*)malloc(fileSize);

	if (FALSE == ReadFile(hDll, dllBuf, fileSize, &bytesRead, NULL))
	{
		printf("Terminal failure: Unable to read from file.\n GetLastError=%08x\n", GetLastError());
		CloseHandle(hDll);
		return 1;
	}

	if (bytesRead != fileSize) {
		printf("Error! Only read %d bytes out of %d!\n", bytesRead, fileSize);
		return 1;
	}

	// now begin the loader portion
	dosHeader = (IMAGE_DOS_HEADER*)dllBuf;
	if (dosHeader->e_magic != 0x5A4D) { //MZ header
		printf("The first two bytes are not MZ!\n");
		return 1;
	}
	ntHeader = (IMAGE_NT_HEADERS *)(dllBuf + dosHeader->e_lfanew);
	if (ntHeader->Signature != 0x4550) { //PE header
		printf("The NT_IMAGE_HEADER does not start 'PE' (ntHeader->Signature  == 0x%X)!\n", ntHeader->Signature);
		return 1;
	}
	// Allocate twice the size of the loaded DLL
	base = (char*)VirtualAlloc(NULL, 2 * ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == base) {
		printf("Couldn't VirtualAlloc base!\n");
		return 1;
	}
	// copy module headers to new allocation
	memcpy(base, dllBuf, ntHeader->OptionalHeader.SizeOfHeaders);

	// copy fileSize as a DWORD right after the end of the image
	memcpy(&base[ntHeader->OptionalHeader.SizeOfImage], &fileSize, sizeof(DWORD));

	// copy PE file right after that
	memcpy(&base[ntHeader->OptionalHeader.SizeOfImage + 4], dllBuf, fileSize);

	// load the sections
	WORD numSections = ntHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER secHeader = (PIMAGE_SECTION_HEADER)(sizeof(*ntHeader) + (DWORD)ntHeader);
	while (numSections > 0) {
		memcpy(&base[secHeader->VirtualAddress], dllBuf + secHeader->PointerToRawData, secHeader->SizeOfRawData);
		secHeader++;
		numSections--;
	}
	// Check if the preferred image base matches the allocation address we got above... most likely it does not
	// Add the offset to the actual base to the relocations
	DWORD imageBase = ntHeader->OptionalHeader.ImageBase;
	if ((CHAR *)imageBase != base)
	{
		PE_fixupRelocations(base, ntHeader, (DWORD)(base - imageBase));
		ntHeader->OptionalHeader.ImageBase = (DWORD)base;
		memcpy(&base[dosHeader->e_lfanew], ntHeader, 248);
	}


	// fix up imports
	//IMAGE_IMPORT_DESCRIPTOR* = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_THUNK_DATA pThunk = NULL;
	IMAGE_IMPORT_DESCRIPTOR *pDescriptor = NULL;
	HMODULE hLib = NULL;
	DWORD szLibraryName_offset = 0;
	PIMAGE_THUNK_DATA pAddrThunkl = NULL;
	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		pDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)&base[ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress];
		while (1)
		{
			szLibraryName_offset = pDescriptor->Name;
			if (!szLibraryName_offset)
				break;
			HMODULE hLib = LoadLibraryA(&base[szLibraryName_offset]);
			if (hLib)
			{
				if (pDescriptor->OriginalFirstThunk)
					pThunk = (PIMAGE_THUNK_DATA)&base[pDescriptor->Characteristics];
				else
					pThunk = (PIMAGE_THUNK_DATA)&base[pDescriptor->FirstThunk];
				pAddrThunkl = (PIMAGE_THUNK_DATA)&base[pDescriptor->FirstThunk];
				while (pThunk->u1.AddressOfData)
				{
					PIMAGE_IMPORT_BY_NAME ordinal = (PIMAGE_IMPORT_BY_NAME)pThunk->u1.Ordinal;
					if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
					{
						LPCSTR Ordinal = (LPCSTR)IMAGE_ORDINAL(pAddrThunkl->u1.Ordinal);
						pAddrThunkl->u1.Function = (DWORD)GetProcAddress(hLib, Ordinal);

					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)(base + pThunk->u1.AddressOfData);
						pAddrThunkl->u1.Function = (DWORD)GetProcAddress(hLib, pImport->Name);
					}
					++pThunk;
					++pAddrThunkl;
				}
				++pDescriptor;
			}
		}
	}
	LOADER_FNDLLMAIN pEntryPoint = (LOADER_FNDLLMAIN)&base[ntHeader->OptionalHeader.AddressOfEntryPoint];
	printf("Calling entry point\n");
	pEntryPoint((HINSTANCE)base, 1, 0);
	Sleep(0xFFFFFFFF);
	return 0;
}

_IMAGE_BASE_RELOCATION *PE_fixupRelocations(char* newBase, IMAGE_NT_HEADERS *src, DWORD offset) {
	_IMAGE_BASE_RELOCATION *result;
	char *pageRVA;
	_IMAGE_BASE_RELOCATION *pRelocTable;

	result = (_IMAGE_BASE_RELOCATION *)src;
	if (src->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		pRelocTable = (_IMAGE_BASE_RELOCATION *)(newBase + src->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (1)
		{
			result = pRelocTable;
			if (!pRelocTable->VirtualAddress)
				break;
			// first relocation starts agter IMAGE_BASE_RELOCATION header
			RELOCATION* pReloc = (RELOCATION*)(pRelocTable + 1);
			pageRVA = (char*)(newBase + pRelocTable->VirtualAddress);

			CONST DWORD CountRelocs = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCATION);
			for (DWORD dwCount = 0; dwCount < CountRelocs; ++dwCount) {
				if (pReloc[dwCount].Type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)&pageRVA[pReloc[dwCount].Offset & 0xFFF] += offset;
			}
			pRelocTable = (_IMAGE_BASE_RELOCATION *)((char *)pRelocTable + pRelocTable->SizeOfBlock);
		}
	}
	return result;
}
