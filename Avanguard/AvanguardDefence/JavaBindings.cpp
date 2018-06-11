#include "stdafx.h"
#include "JavaBindings.h"

#ifdef JAVA_BINDINGS

static BOOL _IsJavaBinded = FALSE;

extern BOOL AvnStartDefence();
extern VOID AvnStopDefence();
extern BOOL IsAvnStarted;
extern BOOL IsAvnStaticLoaded;

extern VOID EliminateThreat(AVN_THREAT Threat, OPTIONAL PVOID Data);

static JavaVM* _vm = NULL;
static JNIEnv* _env = NULL;
static jclass _klass = NULL;
static jmethodID _notifier = NULL;

jboolean JNICALL avnStartDefence(JNIEnv* env, jclass klass) {
    return (jboolean)AvnStartDefence();
}

void JNICALL avnStopDefence(JNIEnv* env, jclass klass) {
    AvnStopDefence();
}

jboolean JNICALL avnIsStarted(JNIEnv* env, jclass klass) {
    return (jboolean)IsAvnStarted;
}

jboolean JNICALL avnIsStaticLoaded(JNIEnv* env, jclass klass) {
    return (jboolean)IsAvnStaticLoaded;
}

void JNICALL avnEliminateThreat(JNIEnv* env, jclass klass, jint threat) {
    EliminateThreat((AVN_THREAT)threat, NULL);
}

jlong JNICALL avnGetHWID(JNIEnv* env, jclass klass) {
    return (jlong)GetHWID();
}

jlong JNICALL avnGetHash(JNIEnv* env, jclass klass, jbyteArray data) {
    jsize length = env->GetArrayLength(data);
    jbyte* buffer = (jbyte*)new jbyte[length];
    env->GetByteArrayRegion(data, 0, length, buffer);
    jlong hash = (jlong)t1ha(buffer, length, 0x1EE7C0DEC0FFEE);
    delete[] buffer;
    return hash;
}

void JNICALL avnRegisterNotifier(JNIEnv* env, jclass klass, jobject callback) {
    if (callback == NULL) {
        _klass = NULL;
        _notifier = NULL;
        return;
    }
    _klass = env->GetObjectClass(callback);
    _notifier = env->GetMethodID(_klass, "call", "(I)Z");
}

jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    jint status;

    status = vm->GetEnv((void**)&env, JNI_VERSION_1_8);
    if (status != JNI_OK)
        if (status == JNI_EDETACHED) 
            status = vm->AttachCurrentThread((void**)&env, NULL);
        else
            return JNI_ERR;

    if (status != JNI_OK) return JNI_ERR;

    jclass binding = env->FindClass("ru/avanguard/AvnBind");
    const JNINativeMethod methods[] = {
        { "avnStartDefence"		, "()Z"		, (void*)avnStartDefence },
        { "avnStopDefence"		, "()V"		, (void*)avnStopDefence },
        { "avnIsStarted"		, "()Z"		, (void*)avnIsStarted },
        { "avnIsStaticLoaded"	, "()Z"		, (void*)avnIsStaticLoaded },
        { "avnEliminateThreat"	, "(I)V"	, (void*)avnEliminateThreat },
        { "avnGetHWID"			, "()J"		, (void*)avnGetHWID },
        { "avnGetHash"			, "([B)J"	, (void*)avnGetHash },
        { "avnRegisterThreatNotifier", "(Lru/avanguard/AvnBind$ThreatNotifier;)V", (void*)avnRegisterNotifier }
    };
    
    status = env->RegisterNatives(binding, methods, sizeof(methods) / sizeof(methods[0]));
    if (status != JNI_OK) return JNI_ERR;

    _vm = vm;
    _env = env;
    _IsJavaBinded = TRUE;
    return JNI_VERSION_1_8;
}

BOOL IsJavaBinded() {
    return _IsJavaBinded;
}

BOOL CallJavaNotifier(AVN_THREAT Threat) {
    if (_vm == NULL || _env == NULL || _klass == NULL || _notifier == NULL) return FALSE;

    jint status = _vm->AttachCurrentThread((void**)&_env, NULL);
    if (status != JNI_OK) return FALSE;

    return _env->CallBooleanMethod(_klass, _notifier, (int)Threat);
}

#endif