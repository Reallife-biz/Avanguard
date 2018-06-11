#include "stdafx.h"
#include "ThreatElimination.h"

static _AvnThreatNotifier _ThreatCallback = NULL;

typedef NTSTATUS (NTAPI *_NtContinue)(PCONTEXT Context, BOOL TestAlert);
static const _NtContinue NtContinue = (_NtContinue)hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtContinue"));

[[noreturn]]
VOID Meltdown() {
    __debugbreak();
    __fastfail(0);
    CONTEXT Context; // Stay uninitialized
    NtContinue(&Context, FALSE);
}

VOID EliminateThreat(AVN_THREAT Threat, OPTIONAL PVOID Data) {
    if (_ThreatCallback)
        if (_ThreatCallback(Threat, Data)) return;
#ifdef JAVA_BINDINGS
    if (CallJavaNotifier(Threat)) return;
#endif

    CONTEXT Context = { 0 };
    RtlCaptureContext(&Context);
#ifdef _AMD64_
    Context.Rip = (SIZE_T)Meltdown;
#else
    Context.Eip = (SIZE_T)Meltdown;
#endif
    NtContinue(&Context, FALSE);
}

VOID SetupNotificationRoutine(_AvnThreatNotifier ThreatCallback) {
    _ThreatCallback = ThreatCallback;
}