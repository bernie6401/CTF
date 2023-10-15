package com.unity3d.player;

import android.content.Context;
import android.database.ContentObserver;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Handler;
import android.provider.Settings;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class b {
    private final Context a;
    private final AudioManager b;
    private a c;

    /* loaded from: classes.dex */
    private class a extends ContentObserver {
        private final InterfaceC0003b b;
        private final AudioManager c;
        private final int d;
        private int e;

        public a(Handler handler, AudioManager audioManager, int i, InterfaceC0003b interfaceC0003b) {
            super(handler);
            this.c = audioManager;
            this.d = 3;
            this.b = interfaceC0003b;
            this.e = audioManager.getStreamVolume(3);
        }

        @Override // android.database.ContentObserver
        public final boolean deliverSelfNotifications() {
            return super.deliverSelfNotifications();
        }

        @Override // android.database.ContentObserver
        public final void onChange(boolean z, Uri uri) {
            int streamVolume;
            AudioManager audioManager = this.c;
            if (audioManager == null || this.b == null || (streamVolume = audioManager.getStreamVolume(this.d)) == this.e) {
                return;
            }
            this.e = streamVolume;
            this.b.onAudioVolumeChanged(streamVolume);
        }
    }

    /* renamed from: com.unity3d.player.b$b  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public interface InterfaceC0003b {
        void onAudioVolumeChanged(int i);
    }

    public b(Context context) {
        this.a = context;
        this.b = (AudioManager) context.getSystemService("audio");
    }

    public final void a() {
        if (this.c != null) {
            this.a.getContentResolver().unregisterContentObserver(this.c);
            this.c = null;
        }
    }

    public final void a(InterfaceC0003b interfaceC0003b) {
        this.c = new a(new Handler(), this.b, 3, interfaceC0003b);
        this.a.getContentResolver().registerContentObserver(Settings.System.CONTENT_URI, true, this.c);
    }
}