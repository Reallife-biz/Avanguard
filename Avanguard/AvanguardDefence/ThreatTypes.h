#pragma once

#include <Windows.h>

typedef enum _AVN_THREAT {
	avnUnknownThreat,
	avnRemoteThread,
	avnWindowsHooksInjection,
	avnUnknownTraceLoadLibrary,
	avnContextManipulation,
	avnCriticalModuleChanged,
	avnUnknownInterception,
	avnUnknownMemoryRegion,
	avnUnknownApcDestination
} AVN_THREAT, *PAVN_THREAT;

typedef BOOL(WINAPI *_AvnThreatNotifier)(
	AVN_THREAT Threat,
	OPTIONAL PVOID Data
);