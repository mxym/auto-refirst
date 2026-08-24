package com.example;

public final class JniRelationFixture {
    static {
        System.loadLibrary("jni_relation");
    }

    public static native int nativeAdd(int value);

    private JniRelationFixture() {}
}
