package com.unity3d.player;

import android.content.Context;
import android.graphics.Rect;
import android.hardware.Camera;

/* loaded from: classes.dex */
public class Camera2Wrapper implements e {
    private Context a;
    private c b = null;
    private final int c = 100;

    public Camera2Wrapper(Context context) {
        this.a = context;
        initCamera2Jni();
    }

    private static int a(float f) {
        return (int) Math.min(Math.max((f * 2000.0f) - 1000.0f, -900.0f), 900.0f);
    }

    private final native void deinitCamera2Jni();

    private final native void initCamera2Jni();

    private final native void nativeFrameReady(Object obj, Object obj2, Object obj3, int i, int i2, int i3);

    private final native void nativeSurfaceTextureReady(Object obj);

    public final void a() {
        deinitCamera2Jni();
        closeCamera2();
    }

    @Override // com.unity3d.player.e
    public final void a(Object obj) {
        nativeSurfaceTextureReady(obj);
    }

    @Override // com.unity3d.player.e
    public final void a(Object obj, Object obj2, Object obj3, int i, int i2, int i3) {
        nativeFrameReady(obj, obj2, obj3, i, i2, i3);
    }

    protected void closeCamera2() {
        c cVar = this.b;
        if (cVar != null) {
            cVar.b();
        }
        this.b = null;
    }

    protected int getCamera2Count() {
        return c.a(this.a);
    }

    protected int getCamera2FocalLengthEquivalent(int i) {
        return c.d(this.a, i);
    }

    protected int[] getCamera2Resolutions(int i) {
        return c.e(this.a, i);
    }

    protected int getCamera2SensorOrientation(int i) {
        return c.a(this.a, i);
    }

    protected Object getCameraFocusArea(float f, float f2) {
        int a = a(f);
        int a2 = a(1.0f - f2);
        return new Camera.Area(new Rect(a - 100, a2 - 100, a + 100, a2 + 100), 1000);
    }

    protected Rect getFrameSizeCamera2() {
        c cVar = this.b;
        return cVar != null ? cVar.a() : new Rect();
    }

    protected boolean initializeCamera2(int i, int i2, int i3, int i4, int i5) {
        if (this.b != null || UnityPlayer.currentActivity == null) {
            return false;
        }
        c cVar = new c(this);
        this.b = cVar;
        return cVar.a(this.a, i, i2, i3, i4, i5);
    }

    protected boolean isCamera2AutoFocusPointSupported(int i) {
        return c.c(this.a, i);
    }

    protected boolean isCamera2FrontFacing(int i) {
        return c.b(this.a, i);
    }

    protected void pauseCamera2() {
        c cVar = this.b;
        if (cVar != null) {
            cVar.d();
        }
    }

    protected boolean setAutoFocusPoint(float f, float f2) {
        c cVar = this.b;
        if (cVar != null) {
            return cVar.a(f, f2);
        }
        return false;
    }

    protected void startCamera2() {
        c cVar = this.b;
        if (cVar != null) {
            cVar.c();
        }
    }

    protected void stopCamera2() {
        c cVar = this.b;
        if (cVar != null) {
            cVar.e();
        }
    }
}