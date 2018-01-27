#include "stdafx.h"
#include "AvnApi.h"

#include "AvnDefinitions.h"
#include "WinTrusted.h"
#include "ModulesCallbacks.h"
#include "MemoryCallbacks.h"
#include "HWIDsUtils.h"
#include "ThreatElimination.h"

AVN_API AvnApi;
static CRITICAL_SECTION CriticalSection;

extern BOOL AvnStartDefence();
extern VOID AvnStopDefence();
extern BOOL IsAvnStarted;
extern BOOL IsAvnStaticLoaded;

BOOL WINAPI AvnStart() {
	return AvnStartDefence();
}

VOID WINAPI AvnStop() {
	AvnStopDefence();
}

BOOL WINAPI AvnIsStarted() {
	return IsAvnStarted;
}

BOOL WINAPI AvnIsStaticLoaded() {
	return IsAvnStaticLoaded;
}

VOID WINAPI AvnRegisterThreatNotifier(OPTIONAL _AvnThreatNotifier Notifier) {
	SetupNotificationRoutine(Notifier);
}

VOID WINAPI AvnEliminateThreat(AVN_THREAT Threat, OPTIONAL PVOID Data) {
	EliminateThreat(Threat, Data);
}

VOID WINAPI AvnLock() {
	EnterCriticalSection(&CriticalSection);
}

VOID WINAPI AvnUnlock() {
	LeaveCriticalSection(&CriticalSection);
}

VOID WINAPI AvnRehashModule(HMODULE hModule) {
#ifdef MODULES_FILTER
	ValidModulesStorage.RecalcModuleHash(hModule);
#else
	return;
#endif
}

BOOL WINAPI AvnIsModuleValid(HMODULE hModule) {
#ifdef MODULES_FILTER
	return ValidModulesStorage.IsCodeSectionsValid(hModule);
#else
	return TRUE;
#endif
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

UINT64 WINAPI AvnGetHWID() {
	return GetHWID();
}

UINT64 WINAPI AvnHash(PVOID Data, ULONG Size) {
	return t1ha(Data, Size, 0x1EE7C0DEC0FFEE);
}

VOID AvnInitializeApi() {
	InitializeCriticalSectionAndSpinCount(&CriticalSection, 0xC0000000);
	AvnApi.AvnStart						= AvnStart;
	AvnApi.AvnStop						= AvnStop;
	AvnApi.AvnIsStarted					= AvnIsStarted;
	AvnApi.AvnIsStaticLoaded			= AvnIsStaticLoaded;
	AvnApi.AvnRegisterThreatNotifier	= AvnRegisterThreatNotifier;
	AvnApi.AvnEliminateThreat			= AvnEliminateThreat;
	AvnApi.AvnLock						= AvnLock;
	AvnApi.AvnUnlock					= AvnUnlock;
	AvnApi.AvnRehashModule				= AvnRehashModule;
	AvnApi.AvnIsModuleValid				= AvnIsModuleValid;
	AvnApi.AvnIsFileProtected			= AvnIsFileProtected;
	AvnApi.AvnIsFileSigned				= AvnIsFileSigned;
	AvnApi.AvnVerifyEmbeddedSignature	= AvnVerifyEmbeddedSignature;
	AvnApi.AvnIsAddressAllowed			= AvnIsAddressAllowed;
	AvnApi.AvnGetHWID					= AvnGetHWID;
	AvnApi.AvnHash						= AvnHash;
}