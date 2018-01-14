#include "stdafx.h"
#include "AvnApi.h"

#include "AvnDefinitions.h"
#include "WinTrusted.h"
#include "ModulesCallbacks.h"
#include "MemoryCallbacks.h"

AVN_API AvnApi;
static CRITICAL_SECTION CriticalSection;

VOID WINAPI AvnLock() {
	EnterCriticalSection(&CriticalSection);
}

VOID WINAPI AvnUnlock() {
	LeaveCriticalSection(&CriticalSection);
}

VOID WINAPI AvnRehashModule(HMODULE hModule) {
	ValidModulesStorage.RecalcModuleHash(hModule);
}

BOOL WINAPI AvnIsModuleValid(HMODULE hModule) {
	return ValidModulesStorage.IsCodeSectionsValid(hModule);
}

BOOL WINAPI AvnIsFileProtected(LPCWSTR FilePath) {
	return SfcIsFileProtected(NULL, FilePath);
}

BOOL WINAPI AvnIsFileSigned(LPCWSTR FilePath, BOOL CheckRevocation) {
	return IsFileSigned(FilePath, CheckRevocation);
}

BOOL WINAPI AvnVerifyEmbeddedSignature(LPCWSTR FilePath) {
	return VerifyEmbeddedSignature(FilePath);
}

BOOL WINAPI AvnIsAddressAllowed(PVOID Address, BOOL IncludeJitMemory) {
	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };
	VirtualQuery(Address, &MemoryInfo, sizeof(MemoryInfo));
	if ((MemoryInfo.Protect & EXECUTABLE_MEMORY) == 0) return TRUE;

	HMODULE hModule = GetModuleBase(Address);
	if (hModule == NULL) {
#ifdef MEMORY_FILTER
		if (!IncludeJitMemory) return FALSE;
		return VMStorage.IsMemoryInMap(Address);
#else
		return FALSE;
#endif
	}
	return ValidModulesStorage.IsModuleInStorage(hModule);
}

VOID AvnInitializeApi() {
	InitializeCriticalSection(&CriticalSection);
	AvnApi.AvnLock = AvnLock;
	AvnApi.AvnUnlock = AvnUnlock;
	AvnApi.AvnRehashModule = AvnRehashModule;
	AvnApi.AvnIsModuleValid = AvnIsModuleValid;
	AvnApi.AvnIsFileProtected = AvnIsFileProtected;
	AvnApi.AvnIsFileSigned = AvnIsFileSigned;
	AvnApi.AvnVerifyEmbeddedSignature = AvnVerifyEmbeddedSignature;
	AvnApi.AvnIsAddressAllowed = AvnIsAddressAllowed;
}