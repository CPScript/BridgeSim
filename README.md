Used in the [NFCman Project](https://github.com/CPScript/NFCman)

![image](https://github.com/user-attachments/assets/1dffb219-3d4d-4622-be8f-add001e7f73a)

![image](https://github.com/user-attachments/assets/6cf8e8a1-df55-4509-b209-35b0cfd69eb2)

![image](https://github.com/user-attachments/assets/5fe95499-88a6-46b7-b72e-b3eb0430b69b)

![image](https://github.com/user-attachments/assets/9f45bbb5-7082-427a-b07f-9b0d793a34dc)

UDB commands;
> Here's a simple list of **100 ADB commands** you can use to get started!

### **1. General Device Information**

1. `adb shell getprop` — Get system properties (e.g., device model, build info).
2. `adb shell cat /proc/cpuinfo` — Get detailed CPU info.
3. `adb shell cat /proc/meminfo` — View memory usage.
4. `adb shell cat /proc/version` — Get the device’s kernel version.
5. `adb shell cat /proc/loadavg` — View system load averages.
6. `adb shell cat /proc/uptime` — Get device uptime.
7. `adb shell df` — View disk usage and available storage.
8. `adb shell free` — Display memory usage statistics.
9. `adb shell top` — Show running processes and system stats.
10. `adb shell ps` — View processes running on the device.
11. `adb shell dumpsys activity` — Display information about running activities.
12. `adb shell dumpsys battery` — Get battery status and statistics.
13. `adb shell dumpsys wifi` — Display Wi-Fi status and information.
14. `adb shell dumpsys power` — Show power management stats.
15. `adb shell dumpsys window` — Show active window manager status.
16. `adb shell wm size` — Get screen resolution.
17. `adb shell wm density` — Get screen density.
18. `adb shell cat /sys/class/thermal/thermal_zone0/temp` — Get temperature data from thermal sensor.
19. `adb shell cat /sys/class/power_supply/battery/capacity` — Get battery percentage.

### **2. File and Directory Management**

20. `adb shell ls` — List files in the current directory.
21. `adb shell mkdir <directory>` — Create a directory.
22. `adb shell rm <file>` — Remove a file.
23. `adb shell rm -rf <directory>` — Remove a directory and its contents.
24. `adb shell cp <source> <destination>` — Copy a file from source to destination.
25. `adb shell mv <source> <destination>` — Move a file.
26. `adb shell cat <file>` — Display the contents of a file.
27. `adb shell chmod <permissions> <file>` — Change file permissions.
28. `adb shell chown <owner>:<group> <file>` — Change file owner and group.
29. `adb shell find /path -name <filename>` — Search for a file by name.
30. `adb shell ls -l` — List files with detailed information.
31. `adb shell touch <file>` — Create an empty file.
32. `adb shell stat <file>` — View file statistics.
33. `adb shell df -h` — Display human-readable disk usage.
34. `adb shell du -sh <directory>` — Display directory size in human-readable format.

### **3. App and Package Management**

35. `adb shell pm list packages` — List all installed packages.
36. `adb shell pm list packages -f` — List packages with their file paths.
37. `adb shell pm path <package>` — Get the installation path of a package.
38. `adb shell pm uninstall <package>` — Uninstall an app.
39. `adb shell pm uninstall --user 0 <package>` — Uninstall app for the current user.
40. `adb shell pm enable <package>` — Enable a disabled app.
41. `adb shell pm disable <package>` — Disable an app.
42. `adb shell am start -n <package>/<activity>` — Launch an app or activity.
43. `adb shell am start -a <action>` — Start an activity with an intent action.
44. `adb shell am force-stop <package>` — Force stop a specific app.
45. `adb shell am broadcast -a <action>` — Send a broadcast intent.
46. `adb shell am startservice <service>` — Start a service.
47. `adb shell am stopservice <service>` — Stop a service.
48. `adb shell pm clear <package>` — Clear app data (similar to factory reset for that app).
49. `adb shell settings list system` — List system settings.
50. `adb shell settings get <namespace> <key>` — Get a specific setting.
51. `adb shell settings put <namespace> <key> <value>` — Set a specific setting.

### **4. Network and Connectivity**

52. `adb shell ifconfig` — Display network interface configuration.
53. `adb shell ip addr show` — Show IP address information.
54. `adb shell ip link show` — Show network interfaces.
55. `adb shell ping <ip>` — Test network connectivity.
56. `adb shell netstat` — Show network connections.
57. `adb shell getprop net.wifi.interface` — Get Wi-Fi interface.
58. `adb shell netcfg` — Show network interfaces and their status.
59. `adb shell dumpsys connectivity` — Display network connection status.
60. `adb shell service call connectivity 33` — Enable/Disable Wi-Fi.
61. `adb shell service call connectivity 32` — Enable/Disable mobile data.
62. `adb shell service call connectivity 1` — Enable Bluetooth.
63. `adb shell service call bluetooth 3` — Disable Bluetooth.

### **5. Notifications and System Events**

64. `adb shell am broadcast -a android.intent.action.MASTER_CLEAR` — Perform a factory reset.
65. `adb shell am broadcast -a android.intent.action.SEND_NOTIFICATION` — Send a notification.
66. `adb shell input keyevent 26` — Toggle the power button (screen on/off).
67. `adb shell input keyevent 3` — Press the Home button.
68. `adb shell input keyevent 4` — Press the Back button.
69. `adb shell input keyevent 82` — Press the Menu button.
70. `adb shell input keyevent 24` — Volume Up.
71. `adb shell input keyevent 25` — Volume Down.
72. `adb shell input keyevent 66` — Enter (select).
73. `adb shell input text <text>` — Input text into an active text field.
74. `adb shell input swipe <x1> <y1> <x2> <y2>` — Simulate a swipe gesture.
75. `adb shell input tap <x> <y>` — Simulate a tap gesture.
76. `adb shell am startservice -a com.android.service.NotificationService` — Start notification service.
77. `adb shell am start -n com.android.settings/.Settings` — Open Settings app.

### **6. Debugging and Logs**

78. `adb logcat` — View the system logs.
79. `adb logcat -d` — Dump logs to the console.
80. `adb logcat -s <tag>` — Filter logs by tag.
81. `adb logcat -v time` — View logs with timestamp.
82. `adb shell dmesg` — Display kernel logs.
83. `adb logcat -c` — Clear the log buffer.
84. `adb logcat *:E` — Show only error logs.
85. `adb logcat -f <file>` — Write logs to a file.

### **7. Screen Capture and Recording**

86. `adb shell screencap /sdcard/screenshot.png` — Capture a screenshot.
87. `adb shell screenrecord /sdcard/video.mp4` — Record the screen (requires `Ctrl+C` to stop).
88. `adb pull /sdcard/screenshot.png <local-path>` — Pull a screenshot from the device to your computer.
89. `adb push <local-path> /sdcard/` — Push a file from your computer to the device.
90. `adb shell screencap -p > screenshot.png` — Save screenshot to a file directly from ADB.
91. `adb shell screenrecord --verbose /sdcard/recording.mp4` — Start recording screen with verbose output.

### **8. File and Data Management**

92. `adb push <local-file> /sdcard/` — Push a file from the host machine to the device.
93. `adb pull /sdcard/screenshot.png <local-path>` — Pull a file from the device to the host machine.
94. `adb shell mount` — Show mounted filesystems.
95. `adb shell mv <source> <destination>` — Move a file or directory.
96. `adb shell tar -xvf <archive-file>` — Extract files from a tar archive.
97. `adb shell tar -cvf <archive-file> <source>` — Create a tar archive of files.

### **9. Rebooting and Power Management**

98. `adb reboot` — Reboot the device.
99. `adb reboot recovery` — Reboot into recovery mode.
100. `adb reboot bootloader` — Reboot into bootloader mode.
