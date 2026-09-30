package dev.phonegate

import android.app.Application
import dev.phonegate.net.Notifications

class PhoneGateApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
    }
}
