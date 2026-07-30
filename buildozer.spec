[app]
title = PacketProxy
package.name = packetproxy
package.domain = org.packetproxy
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,ttf
version = 2.0.0
requirements = python3,kivy==2.3.0,kivymd==1.1.1
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,FOREGROUND_SERVICE,FOREGROUND_SERVICE_SPECIAL_USE,WAKE_LOCK,CHANGE_NETWORK_STATE
android.api = 31
android.minapi = 21
android.ndk = 25b
android.sdk = 34
android.arch = arm64-v8a
android.allow_backup = False
android.presplash_color = #1A1A2E
android.logcat_filters = *:S python:D
android.foreground_service_type = specialUse
p4a.branch = develop

[buildozer]
log_level = 2
