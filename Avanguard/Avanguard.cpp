#include "stdafx.h"

#include <functional>

#include "AvnDefinitions.h"
#include "ThreadsFilter.h"
#include "ModulesFilter.h"
#include "PEAnalyzer.h"
#include "ModulesCallbacks.h"
#include "ModulesStorage.h"
#include "MemoryCallbacks.h"
#include "CheckHook.h"
#include "ProcessAPI.h"
#include "PebTeb.h"
#include "Mitigations.h"
#include "AppInitDlls.h"
#include "WinTrusted.h"
#include "ApcDispatcher.h"
#include "DACL.h"
#include "ModulesUtils.h"
#include "ContextFilter.h"

#include "HoShiMin's API\\StringsAPI.h"
#include "HoShiMin's API\\ColoredConsole.h"
#include "HoShiMin's API\\DisasmHelper.h"
#include "HoShiMin's API\\HookHelper.h"

#include <time.h>
#include <intrin.h>

#include "AvnApi.h"
extern AVN_API AvnApi;
extern VOID AvnInitializeApi();
extern "C" __declspec(dllexport) const PAVN_API Stub = &AvnApi;

#ifdef DEBUG_OUTPUT
static HANDLE hLog = CreateFile(L"AvnLog.log", FILE_WRITE_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

void Log(const std::wstring& Text) {
	if (hLog == INVALID_HANDLE_VALUE) return;

	static BOOL Initialized = FALSE;
	static CRITICAL_SECTION CriticalSection;
	if (!Initialized) {
		InitializeCriticalSection(&CriticalSection);
		Initialized = TRUE;
	}

	std::wstring ToWrite = L"[PID: " + ValToWideStr(GetCurrentProcessId()) + L"] " + Text + L"\r\n";

	EnterCriticalSection(&CriticalSection);
	DWORD BytesWritten;
	WriteFile(hLog, ToWrite.c_str(), (DWORD)ToWrite.length() * sizeof(std::wstring::value_type), &BytesWritten, NULL);
	LeaveCriticalSection(&CriticalSection);
}

VOID DisassembleAndLog(PVOID Address, BYTE InstructionsCount) {
	disassemble([](void* Code, void* Address, unsigned int InstructionLength, char* Disassembly) -> void {
		std::wstring Bytes;
		for (unsigned int i = 0; i < InstructionLength; i++) {
			Bytes += ValToWideHex(*((PBYTE)Code + i), 2, FALSE);
			if (i != InstructionLength - 1) Bytes += L" ";
		}
		Bytes = FillRightWide(Bytes, 22, L' ');
		Log(L"\t\t" + ValToWideHex(Address, 16) + L"\t" + Bytes + L"\t" + AnsiToWide(Disassembly));
	}, Address, Address, InstructionsCount);
}
#else
#define Log(Argument) UNREFERENCED_PARAMETER(Argument)
#define DisassembleAndLog(Address, InstructionsCount)
#endif

#ifdef TIMERED_CHECKINGS
typedef NTSTATUS (NTAPI *_RtlCreateTimerQueue)(
	_Out_ PHANDLE TimerQueueHandle
);

typedef NTSTATUS (NTAPI *_RtlDeleteTimerQueue)(
	_In_ HANDLE TimerQueueHandle
);

typedef NTSTATUS (NTAPI *_RtlCreateTimer)(
	_In_ HANDLE 	TimerQueueHandle,
	_Out_ PHANDLE 	Handle,
	_In_ WAITORTIMERCALLBACKFUNC 	Function,
	_In_ PVOID 	Context,
	_In_ DWORD 	DueTime,
	_In_ DWORD 	Period,
	_In_ ULONG 	Flags
);


typedef NTSTATUS (NTAPI *_RtlDeleteTimer)(
	_In_ HANDLE TimerQueueHandle,
	_In_ HANDLE TimerHandle,
	_In_ HANDLE CompletionEvent
); 

const _RtlCreateTimerQueue RtlCreateTimerQueue = (_RtlCreateTimerQueue)GetProcAddress(hModules::hNtdll(), "RtlCreateTimerQueue");
const _RtlDeleteTimerQueue RtlDeleteTimerQueue = (_RtlDeleteTimerQueue)GetProcAddress(hModules::hNtdll(), "RtlDeleteTimerQueue");
const _RtlCreateTimer RtlCreateTimer = (_RtlCreateTimer)GetProcAddress(hModules::hNtdll(), "RtlCreateTimer");
const _RtlDeleteTimer RtlDeleteTimer = (_RtlDeleteTimer)GetProcAddress(hModules::hNtdll(), "RtlDeleteTimer");
#endif

#ifdef THREADS_FILTER
static PVOID RestrictedAddresses[] = {
	GetProcAddress(hModules::hNtdll(), "LdrLoadDll"),
	GetProcAddress(hModules::hKernel32(), "LoadLibraryA"),
	GetProcAddress(hModules::hKernel32(), "LoadLibraryW"),
	GetProcAddress(hModules::hKernel32(), "LoadLibraryExA"),
	GetProcAddress(hModules::hKernel32(), "LoadLibraryExW"),
	GetProcAddress(hModules::hKernelBase(), "LoadLibraryA"),
	GetProcAddress(hModules::hKernelBase(), "LoadLibraryW"),
	GetProcAddress(hModules::hKernelBase(), "LoadLibraryExA"),
	GetProcAddress(hModules::hKernelBase(), "LoadLibraryExW")
};

BOOL IsThreadAllowed(PVOID EntryPoint) {
	HMODULE hModule = GetModuleBase(EntryPoint);

	if (hModule != NULL) {
		if (hModule == hModules::hNtdll()		||
			hModule == hModules::hKernel32()	||
			hModule == hModules::hKernelBase()
		) {
			for (PVOID Address : RestrictedAddresses)
				if (Address == EntryPoint) return FALSE;
		}
#ifdef MODULES_FILTER
		return ValidModulesStorage.IsModuleInStorage(hModule);
#else
		return TRUE;
#endif
	} 
#ifdef MEMORY_FILTER
	else {
		return VMStorage.IsMemoryInMap(EntryPoint);
	}
#else
	return TRUE;
#endif
}

BOOL CALLBACK OnThreadCreated(
	PCONTEXT Context,
	BOOL ThreadIsLocal
) {
#ifdef _AMD64_
	PVOID EntryPoint = (PVOID)Context->Rcx;
#else
	PVOID EntryPoint = (PVOID)Context->Eax;
#endif

	if (!ThreadIsLocal && !(ThreadIsLocal = IsThreadAllowed(EntryPoint))) {
		Log(L"[x] Thread " + ValToWideStr(GetCurrentThreadId()) + L" is blocked!");
		__debugbreak();
	}

#ifdef MITIGATIONS
	Mitigations::SetThreadAllowedDynamicCode();
#endif
	return ThreadIsLocal;
}
#endif

#ifdef WINDOWS_HOOKS_FILTER
BOOL CALLBACK OnWindowsHookLoadLibrary(PUNICODE_STRING ModuleFileName) {
	static std::unordered_set<UINT64> BlockedLibs;
	
	std::wstring Path(ModuleFileName->Buffer);
	std::wstring Name(LowerCase(ExtractFileName(Path)));
	
	UINT64 NameHash = t1ha(Name.c_str(), Name.length() * sizeof(std::wstring::value_type), 0x1EE7C0DEC0FFEE);
	if (BlockedLibs.find(NameHash) != BlockedLibs.end()) return FALSE;
	
	Log(L"[!] Attempt to load " + Path + L" through the windows hooks!");

	BOOL IsFileAllowed = SfcIsFileProtected(NULL, ModuleFileName->Buffer);
	Log(IsFileAllowed ? (L"[v] Module " + Path + L" allowed!") : (L"[!] Module " + Path + L" not a system module!"));
	if (IsFileAllowed) return TRUE;

	if (!IsFileAllowed) {
		Log(L"[i] Checking the sign of " + Path + L"...");
		IsFileAllowed = IsFileSigned(ModuleFileName->Buffer, FALSE) || VerifyEmbeddedSignature(ModuleFileName->Buffer);
	}

	if (!IsFileAllowed) {
		Log(L"[i] Checking the path of " + Path + L"...");
		LowerCaseRef(Path);
		IsFileAllowed = (Path.find(L"system32") != std::wstring::npos) || (Path.find(L"syswow64") != std::wstring::npos);
	}

	if (!IsFileAllowed) BlockedLibs.emplace(NameHash);

	Log(IsFileAllowed ? (L"[v] Module " + Path + L" allowed!") : (L"[x] Module " + Path + L" is blocked!"));
	return IsFileAllowed;
}
#endif

#ifdef STACKTRACE_CHECK
BOOL CALLBACK OnUnknownTraceLoadLibrary(PVOID Address, PUNICODE_STRING ModuleFileName) {
	Log(L"[x] Unknown trace entry " + ValToWideHex(Address, 16) + L" on load module " + std::wstring(ModuleFileName->Buffer));
	__debugbreak();
	return FALSE;
}
#endif

#ifdef CONTEXT_FILTER
BOOL IsTraceValid() {
	const ULONG TraceSize = 30;
	PVOID Trace[TraceSize];
	ULONG Captured = CaptureStackBackTrace(0, TraceSize, Trace, NULL);
	for (unsigned int i = 0; i < Captured; i++) {
		HMODULE hModule = GetModuleBase(Trace[i]);
		if (hModule != NULL) {
			if (!ValidModulesStorage.IsModuleInStorage(hModule)) {
				Log(L"[x] Context manipulation from unknown module " + GetModuleName(hModule));
				return FALSE;
			}
		} else {
			if (!VMStorage.IsMemoryInMap(Trace[i])) {
				Log(L"[x] Context manipulation from unknown memory " + ValToWideHex(Trace[i], 16));
				return FALSE;
			}
		}
	}
	return TRUE;
}

NTSTATUS NTAPI PreNtContinue(IN PBOOL SkipOriginalCall, PCONTEXT Context, BOOL TestAlert) {
	if (!IsTraceValid()) {
		Log(L"[x] PreNtContinue detected unknown trace element!");
		__debugbreak();
		*SkipOriginalCall = TRUE;
		return STATUS_ACCESS_DENIED;
	}
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI PreSetContext(IN PBOOL SkipOriginalCall, HANDLE ThreadHandle, PCONTEXT Context) {
	if (!IsTraceValid()) {
		Log(L"[x] PreSetContext detected unknown trace element!");
		__debugbreak();
		*SkipOriginalCall = TRUE;
		return STATUS_ACCESS_DENIED;
	}
	return STATUS_SUCCESS;
}
#endif

BOOL IsModuleRestricted(LPCWSTR ModuleName) {
	const LPCWSTR RestrictedModules[] = {
		L"jvm.dll",
		L"java.dll",
		L"zip.dll",
		//L"opengl32.dll",
		//L"glu32.dll"
	};

	BOOL IsLibProtected = FALSE;
	for (const LPCWSTR RestrictedModule : RestrictedModules) {
		if (wcscmp(ModuleName, RestrictedModule) == 0) {
			IsLibProtected = TRUE;
			break;
		}
	}

	return IsLibProtected;
}

#ifdef TIMERED_CHECKINGS
VOID CALLBACK TimerCallback(PVOID Parameter, BOOLEAN TimerOrWaitFired) {
	AvnApi.AvnLock();
#ifdef FIND_CHANGED_MODULES
	ValidModulesStorage.FindChangedModules([](const MODULE_INFO& ModuleInfo) -> bool {
		if (IsModuleRestricted(ModuleInfo.Name.c_str())) {
			Log(L"[x] Critical module " + ModuleInfo.Name + L" was changed!");
			__debugbreak();
			return true;
		}
		
		HMODULE hTarget = (HMODULE)ModuleInfo.BaseAddress;
		BOOL ValidModulesHooked = TRUE;

		// Проверяем таблицы экспортов:
		PEAnalyzer pe(hTarget, FALSE);
		const EXPORTS_INFO& Exports = pe.GetExportsInfo();
		for (const auto& Export : Exports.Exports) {
			PVOID Source = Export.VA;
			PVOID Destination = FindHookDestination(Source);
			if (Destination == NULL) continue;
			HMODULE hModule = GetModuleBase(Destination);
			if (hModule != NULL) {
				if (!ValidModulesStorage.IsModuleInStorage(hModule)) {
					Log(
						L"[x] Unknown destination module: " +
						GetModuleName(hTarget) +
						L"!" +
						AnsiToWide(Export.Name) +
						L" -> " +
						GetModuleName(hModule) +
						L"!" +
						ValToWideHex(Destination, 16)
					);
					DisassembleAndLog(Destination, 16);
					ValidModulesHooked = FALSE;
				}
			} else if (!VMStorage.IsMemoryInMap(Destination)) {
				Log(
					L"[x] Unknown hook destination: " + 
					GetModuleName(hTarget) + 
					L"!" + 
					AnsiToWide(Export.Name) + 
					L" -> " +
					ValToWideHex(Destination, 16)
				);
				DisassembleAndLog(Destination, 16);
				ValidModulesHooked = FALSE;
			}
		}

		// Если перехватили доверенные модули:
		if (ValidModulesHooked)
			ValidModulesStorage.RecalcModuleHash(hTarget);
		else
			__debugbreak();

		return true;
	});
#endif

#ifdef FIND_UNKNOWN_MEMORY
	EnumerateMemoryRegions(GetCurrentProcess(), [](const PMEMORY_BASIC_INFORMATION MemoryInfo) -> bool {
		if (MemoryInfo->Protect & EXECUTABLE_MEMORY) {
			if (GetModuleBase(MemoryInfo->BaseAddress) == NULL && !VMStorage.IsMemoryInMap(MemoryInfo->BaseAddress)) {
				Log(L"[x] Unknown memory " + ValToWideHex(MemoryInfo->BaseAddress, 16));
				DisassembleAndLog(MemoryInfo->BaseAddress, 16);
				//__debugbreak();
			}
		}
		return true;
	});
#endif
	AvnApi.AvnUnlock();
}
#endif


#ifdef LICENSE_CHECK
BOOL CheckTimeExpired() {
	const unsigned char DaysCount = 10;
	const time_t SecsInDay = 24 * 60 * 60;
	const time_t Timestamp = 0x5A3B8008;
	
	time_t CurrentTime;
	time(&CurrentTime);
	
	return ((CurrentTime - Timestamp) > (DaysCount * SecsInDay));
}
#endif

static HANDLE TimerQueue;
static HANDLE TimerHandle;

typedef VOID(WINAPI *_EntryPoint)();
static _EntryPoint OrgnlEntryPoint = NULL;

VOID WINAPI HkdEntryPoint() {
#ifdef STRICT_DACLs
	DACL Dacl(GetCurrentProcess());
	ULONG AccessRights = 
		WRITE_DAC | WRITE_OWNER |
		PROCESS_CREATE_PROCESS	| PROCESS_CREATE_THREAD		|
		PROCESS_DUP_HANDLE		| PROCESS_QUERY_INFORMATION |
		PROCESS_SET_QUOTA		| PROCESS_SET_INFORMATION	|
		PROCESS_VM_OPERATION	| PROCESS_VM_READ | PROCESS_VM_WRITE |
		PROCESS_SUSPEND_RESUME;
	Dacl.Deny(sidCurrentUser, AccessRights);
	Dacl.Allow(sidEveryone, ~AccessRights & 0x1FFF);
	Dacl.Allow(sidSystem, PROCESS_ALL_ACCESS);
	Dacl.Allow(sidAdministrators, PROCESS_ALL_ACCESS);
	Dacl.Apply();
#endif

#ifdef TIMERED_CHECKINGS
	NTSTATUS Status;
	if (NT_SUCCESS(Status = RtlCreateTimerQueue(&TimerQueue))) {
		if (NT_SUCCESS(Status = RtlCreateTimer(
			TimerQueue,
			&TimerHandle,
			TimerCallback,
			NULL,
			1000,
			1000,
			WT_EXECUTELONGFUNCTION
		))) {
			Log(L"[v] Periodic check enabled");
		}
		else {
			Log(L"[x] Unable to create timer: " + ValToWideHex(Status, 8));
		}
	}
	else {
		Log(L"[x] Unable to create timer queue: " + ValToWideHex(Status, 8));
	}
#endif

	OrgnlEntryPoint();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPCONTEXT Context) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH: {
		Log(L"[v] Avn loaded successfully!");
		AvnInitializeApi();

#ifdef LICENSE_CHECK
		Log(L"[v] Checking license...");
		if (CheckTimeExpired()) {
			Log(L"[x] License expired! Good bye!");
			return TRUE;
		}
		Log(L"[v] License not expired");
#endif

		if (!IsWindows7OrGreater()) return TRUE; // For safety purposes, temporal
		Log(L"[v] Win7 or greater");

		hModules::_hCurrent = hModule;
		SwitchThreadsExecutionStatus(Suspend);

		Log(L"[i] All threads were stopped");

#if defined TIMERED_CHECKINGS || defined STRICT_DACLs
		PEAnalyzer pe(GetModuleHandle(NULL), FALSE);
		PVOID EntryPoint = pe.GetEntryPoint();
		MH_Initialize();
		MH_STATUS MhStatus = MH_CreateHook(EntryPoint, HkdEntryPoint, (LPVOID*)&OrgnlEntryPoint);
		if (MhStatus == MH_OK) MhStatus = MH_EnableHook(EntryPoint);
#endif

#ifdef THREADS_FILTER
		SetupThreadsFilter(NULL, OnThreadCreated);
		Log(L"[v] Threads filter setted up!");
#endif

#ifdef MITIGATIONS
		// Для корректной работы JIT необходимо включить фильтр потоков!
		Mitigations::SetProhibitDynamicCode(TRUE);
		Mitigations::SetThreadAllowedDynamicCode();
		Log(L"[v] Mitigations enabled!");
#endif

#ifdef SKIP_APP_INIT_DLLS
		//if (IsWindows8Point1OrGreater()) PebSetProcessProtected(TRUE, TRUE);
		AppInitDlls::DisableAppInitDlls();
		Log(L"[v] AppInitDlls intercepted!");
#endif

#ifdef MODULES_FILTER
		ModulesFilter::SetupFilterCallbacks(PreLoadModuleCallback);
		ModulesFilter::SetupNotificationCallbacks(DllNotificationRoutine);
		ModulesFilter::EnableModulesFilter();
		ModulesFilter::EnableDllNotification();
		Log(L"[v] Modules filters setted up!");

#ifdef WINDOWS_HOOKS_FILTER
		SetupWindowsHooksFilter(OnWindowsHookLoadLibrary);
		Log(L"[v] Windows hooks filter setted up!");
#endif
#ifdef STACKTRACE_CHECK
		SetupUnknownTraceLoadCallback(OnUnknownTraceLoadLibrary);
		Log(L"[v] Stacktrace check on loading modules enabled!");
#endif
#endif

#ifdef APC_FILTER
		ApcDispatcher::EnableApcFilter();
		ApcDispatcher::SetupApcCallback([](PVOID ApcProc, PVOID RetAddr) -> BOOL {
			BOOL IsApcAllowed = GetModuleBase(ApcProc) != NULL;
			Log(IsApcAllowed ? L"[i] Allowed APC queried" : L"[x] APC disallowed!");
			return IsApcAllowed;
		});
		Log(L"[v] APC filters setted up!");
#endif

#ifdef MEMORY_FILTER
		SetupMemoryCallbacks(
			PreNtAllocateVirtualMemory,
			PostNtAllocateVirtualMemory,
			PreNtProtectVirtualMemory,
			PostNtProtectVirtualMemory,
			PreNtFreeVirtualMemory,
			PostNtFreeVirtualMemory,
			PreNtMapViewOfSection,
			PostNtMapViewOfSection,
			PreNtUnmapViewOfSection,
			PostNtUnmapViewOfSection
		);
		Log(L"[v] Memory filter setted up!");
#endif

#ifdef CONTEXT_FILTER
		ContextFilter::SetupContextCallbacks(PreNtContinue, PreSetContext);
		ContextFilter::EnableContextFilter();
#endif

#ifdef MODULES_FILTER
		ValidModulesStorage.RecalcModulesHashes();
		Log(L"[v] Modules checksums recalculated!");
#endif

#ifdef MEMORY_FILTER
		VMStorage.ReloadMemoryRegions();
		Log(L"[v] Memory regions reloaded!");
#endif

		SwitchThreadsExecutionStatus(Resume);
		Log(L"[i] All threads were resumed");
		break;
	}

	case DLL_PROCESS_DETACH: {
#ifdef TIMERED_CHECKINGS
		RtlDeleteTimer(TimerQueue, TimerHandle, INVALID_HANDLE_VALUE);
		RtlDeleteTimerQueue(TimerQueue);
#endif

#ifdef CONTEXT_FILTER
		ContextFilter::DisableContextFilter();
#endif

#ifdef APC_FILTER
		ApcDispatcher::DisableApcFilter();
#endif
		
#ifdef MODULES_FILTER		
		ModulesFilter::DisableDllNotification();
		ModulesFilter::DisableModulesFilter();
#endif

#ifdef THREADS_FILTER
		RemoveThreadsFilter();
#endif
		
#ifdef MEMORY_FILTER
		RemoveMemoryCallbacks();
#endif

		Log(L"[v] Avn shutted down. Good bye!");
	}
	}

	return TRUE;
}

