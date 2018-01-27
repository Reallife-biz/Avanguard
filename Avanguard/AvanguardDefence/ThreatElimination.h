#pragma once

#include "JavaBindings.h"
#include "ThreatTypes.h"
#include "hModules.h"

VOID SetupNotificationRoutine(_AvnThreatNotifier ThreatCallback);

VOID EliminateThreat(AVN_THREAT Threat, OPTIONAL PVOID Data);