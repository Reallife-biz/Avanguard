#include "stdafx.h"
#include "WinHooks.h"

BOOL WinHooks::Initialized = FALSE;
PVOID WinHooks::__ClientLoadLibrary = NULL;
std::vector<PVOID> WinHooks::KernelCallbacks;

BOOL WinHooks::Initialize() {
	if (Initialized) return TRUE;

	PVOID* KernelCallbackTable = (PVOID*)(GetPEB()->KernelCallbackTable);
	if (KernelCallbackTable == NULL) return FALSE;

#define MASK64 (SIZE_T)0xFFFFFFFF00000000LL
#define MASK32 (SIZE_T)0xFF000000LL
	SIZE_T Mask = ((SIZE_T)*KernelCallbackTable) & MASK64 ? MASK64 : MASK32;
	SIZE_T Signature = ((SIZE_T)(*KernelCallbackTable) & Mask);
#undef MASK64
#undef MASK32

	for (int i = 0; (((SIZE_T)KernelCallbackTable[i]) & Mask) == Signature; i++)
		KernelCallbacks.emplace_back(KernelCallbackTable[i]);
	std::sort(KernelCallbacks.begin(), KernelCallbacks.end());

	return Initialized = KernelCallbacks.size() > 0;
}

BOOL WinHooks::IsCalledFromWinHook() {
	if (!Initialized && !Initialize()) return FALSE;

	BOOL Status = FALSE;

	const int TracesCount = 50; // Max is USHRT_MAX

	PVOID Ptrs[TracesCount];
	USHORT Captured = CaptureStackBackTrace(0, TracesCount, Ptrs, NULL);

	if (__ClientLoadLibrary) {
		for (unsigned short i = 0; i < Captured; i++) if (Ptrs[i] == __ClientLoadLibrary) {
			Status = TRUE;
			goto AddressFound;
		}
	} else {
		for (unsigned short i = 0; i < Captured; i++) {
			PVOID Address = Ptrs[i];
			for (size_t j = 0; j < KernelCallbacks.size() - 1; j++) {
				if ((Address >= KernelCallbacks[j]) && (Address < KernelCallbacks[j + 1])) {
					Status = TRUE;
					__ClientLoadLibrary = Address;
					goto AddressFound;
				}
			}
		}
	}
AddressFound:
	return Status;
}