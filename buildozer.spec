[app]
title = PacketProxy
package.name = packetproxy
package.domain = org.packetproxy
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,ttf
version = 2.0.0
requirements = python3,kivy==2.2.1,kivymd==1.1.1
orientation = portrait
osx.python_version = 3
osx.kivy_version = 2.2.1
fullscreen = 0

# 权限 - 透明代理需要全网络权限
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,FOREGROUND_SERVICE,FOREGROUND_SERVICE_SPECIAL_USE,WAKE_LOCK,CHANGE_NETWORK_STATE

android.api = 31
android.minapi = 21
android.ndk = 25b
android.sdk = 34
android.arch = arm64-v8a
android.allow_backup = False
android.presplash_color = #1A1A2E

# 前台服务类型（Android 14+ 要求）
android.foreground_service_type = specialUse

# 允许应用使用 su（root 设备）
android.allow_iptables = True

# Logcat 过滤
android.logcat_filters = *:S python:D

p4a.branch = develop

[buildozer]
log_level = 2
warn_on_root = 1
