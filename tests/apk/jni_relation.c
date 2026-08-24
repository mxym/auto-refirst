#include <jni.h>

static jint native_add(JNIEnv *env, jclass type, jint value) {
    (void)env;
    (void)type;
    return value + 7;
}

#ifndef REGISTER_SIGNATURE
#define REGISTER_SIGNATURE "(I)I"
#endif

static const JNINativeMethod methods[] = {
    {"nativeAdd", REGISTER_SIGNATURE, (void *)native_add},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    (void)reserved;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass type = (*env)->FindClass(env, "com/example/JniRelationFixture");
    if (type == NULL) return JNI_ERR;
    if ((*env)->RegisterNatives(env, type, methods, 1) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}

#ifdef WRONG_EXPORT_SIGNATURE
#define NATIVE_ADD_EXPORT Java_com_example_JniRelationFixture_nativeAdd__J
#else
#define NATIVE_ADD_EXPORT Java_com_example_JniRelationFixture_nativeAdd
#endif

JNIEXPORT jint JNICALL NATIVE_ADD_EXPORT(JNIEnv *env, jclass type, jint value) {
    return native_add(env, type, value);
}
