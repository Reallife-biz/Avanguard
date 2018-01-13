#include "stdafx.h"
#include "ModulesUtils.h"

HMODULE GetModuleBase(PVOID Pointer) {
	HMODULE hModule;
	BOOL Status = GetModuleHandleEx(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)Pointer,
		&hModule
	);
	return Status ? hModule : NULL;
}

std::wstring GetModuleName(HMODULE hModule) {
	if (hModule == NULL) return std::wstring();
	WCHAR Buffer[32768];
	DWORD Length = GetModuleFileName(hModule, Buffer, sizeof(Buffer));
	if (Length == 0) return std::wstring();
	return Buffer;
}

std::wstring GetModuleName(PVOID Address) {
	HMODULE hModule = GetModuleBase(Address);
	if (hModule == NULL) return std::wstring();
	WCHAR Buffer[32768];
	DWORD Length = GetModuleFileName(hModule, Buffer, sizeof(Buffer));
	if (Length == 0) return std::wstring();
	return Buffer;
}

void EnumerateModules(EnumerateModulesCallback Callback) {
	if (Callback == NULL) return;

	NTDEFINES::PPEB Peb = GetPEB();
	NTDEFINES::PPEB_LDR_DATA LdrData = (NTDEFINES::PPEB_LDR_DATA)Peb->Ldr;

	NTDEFINES::PLDR_MODULE ListEntry = (NTDEFINES::PLDR_MODULE)LdrData->InLoadOrderModuleList.Flink;
	while (ListEntry && ListEntry->BaseAddress) {
		Callback(ListEntry);
		ListEntry = (NTDEFINES::PLDR_MODULE)ListEntry->InLoadOrderModuleList.Flink;
	}
}