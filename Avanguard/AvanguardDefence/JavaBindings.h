#pragma once

#include "HWIDsUtils.h"
#include "ThreatTypes.h"

#include "jni.h"

#pragma comment(lib, "jvm.lib")

JNIEXPORT 
jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved);

BOOL IsJavaBinded();
BOOL CallJavaNotifier(AVN_THREAT Threat);