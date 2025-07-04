# BridgeSimple - Multi-Platform Mobile Device Analysis Framework [(Photos)](img/readme.md)
> Cross-platform Android & iOS device analysis and manipulation toolkit

---

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Android](https://img.shields.io/badge/Android-6.0%2B-green.svg)
![iOS](https://img.shields.io/badge/iOS-12.0%2B-blue.svg)
![Status](https://img.shields.io/badge/status-Active%20Development-brightgreen.svg)

## Overview

BridgeSimple is a comprehensive cross-platform mobile device analysis framework designed for security researchers, penetration testers, and mobile forensics specialists. Supporting both Android and iOS devices, this tool provides deep device introspection, security assessment, and advanced manipulation capabilities for legitimate security research and testing.

## IMPORTANT LEGAL DISCLAIMER

**This tool is designed exclusively for authorized security research, penetration testing, and forensic analysis. Users must:**

- **Only use on devices you own or have explicit written authorization to test**
- **Comply with all applicable local, state, and federal laws**
- **Respect privacy rights and terms of service**
- **Use responsibly for legitimate security research purposes only**

**Unauthorized access to devices or networks is illegal and prohibited. The authors accept no responsibility for misuse.**

## Platform Support

### 📱 Android Support (`android.py`)
Complete Android device analysis and manipulation framework with advanced capabilities.

### 🍎 iOS Support (`iphone.py`)
Comprehensive iOS device management and analysis using libimobiledevice tools.

## Key Features

### 🤖 Android Features
- **Comprehensive Vulnerability Scanner** - Automated security assessment with 8+ vulnerability categories
- **Security Bypass Suite** - SELinux, signature verification, certificate pinning, and root detection bypass
- **Privilege Escalation** - Multiple automated root exploitation techniques
- **Memory Analysis** - Process memory dumps and analysis capabilities
- **Advanced File Manager** - Complete filesystem navigation and manipulation
- **Process Manager** - Monitor, analyze, and control running processes
- **Screen Mirroring** - Real-time screen monitoring and recording
- **Input Simulation** - Touch, swipe, and key event automation
- **Remote APK Execution** - Install and execute applications remotely
- **Advanced Keylogger** - Input monitoring with export capabilities
- **Network Traffic Monitoring** - Capture and analyze network connections
- **NFC Stack Analysis** - Specialized NFC chipset and firmware analysis
- **Communications Analysis** - SMS/Call/Location monitoring and manipulation

### 🍎 iOS Features
- **Device Information Gathering** - Comprehensive device profiling and hardware details
- **Application Management** - IPA installation, uninstallation, and export capabilities
- **File System Access** - Limited media directory access and file management
- **Security Analysis** - Jailbreak detection and security feature assessment
- **System Monitoring** - Real-time device performance and battery monitoring
- **Crash Log Analysis** - Application crash report collection and analysis
- **Network Monitoring** - Connection analysis and network configuration
- **Device Backup/Restore** - Complete device state management
- **SSH Terminal Access** - Remote shell access for jailbroken devices
- **Sysdiagnose Generation** - System diagnostic report creation
- **Code Signing Analysis** - Application integrity verification
- **Keychain Analysis** - Secure storage assessment

### 🔄 Cross-Platform Features
- **Real-time System Monitoring** - Live performance metrics and resource usage
- **Device Backup/Restore** - Complete device state management
- **Evidence Collection** - Structured data export for forensic analysis
- **Report Generation** - Comprehensive analysis reporting
- **Advanced Configuration** - Custom exploit modules and analysis plugins

## Installation

### Prerequisites

#### Common Requirements
- **Python 3.7+** with required packages
- **Administrative privileges** (for advanced features)

#### Android Requirements
- **Android SDK Platform Tools** (ADB)
- **USB debugging enabled** on target device

#### iOS Requirements
- **libimobiledevice tools** (cross-platform)
- **iTunes or Apple Mobile Device Support** (for drivers)
- **Device pairing and trust relationship**

### Required Python Packages

```bash
pip install tkinter pillow psutil
```

### Platform-Specific Setup

#### Android Setup (ADB)
1. Download [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
2. Add ADB to your system PATH
3. Verify installation: `adb version`
4. Enable USB debugging on Android device

#### iOS Setup (libimobiledevice)

**macOS Installation:**
```bash
# Using Homebrew (recommended)
brew install libimobiledevice ideviceinstaller

# Using MacPorts
sudo port install libimobiledevice +universal
sudo port install ideviceinstaller +universal
```

**Ubuntu/Debian Installation:**
```bash
sudo apt update
sudo apt install libimobiledevice6 libimobiledevice-utils
sudo apt install ideviceinstaller ifuse
```

**Windows Installation:**
1. Download pre-compiled binaries from [libimobiledevice-win32](https://github.com/libimobiledevice-win32/imobiledevice-net/releases)
2. Extract to `C:\libimobiledevice`
3. Add `C:\libimobiledevice` to your system PATH
4. Install iTunes (for Apple Mobile Device Support drivers)

**Verify iOS Installation:**
```bash
idevice_id -l          # List connected devices
ideviceinfo -h         # Show help information
ideviceinstaller -h    # Show installer help
```

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/CPScript/BridgeSim
cd BridgeSim

# Install dependencies
pip install -r requirements.txt

# Run Android controller
python android.py

# Run iOS controller
python iphone.py
```

### **Both file systems should look like this**;

![image](https://github.com/user-attachments/assets/97c46bed-245e-45c5-a983-381ed2b4e272)

![image](https://github.com/user-attachments/assets/5e86f2d1-a70b-4cf9-a0e7-8b66577ea668)



## Quick Start

### Android Quick Start
1. **Connect Android Device**
   - Enable USB debugging in Developer Options
   - Connect via USB and authorize computer
   - Launch `python android.py`

2. **Device Selection**
   - Select device from dropdown menu
   - Click "Connect" to establish connection
   - Verify connection status in toolbar

3. **Choose Analysis Type**
   - **System Monitor**: Real-time device monitoring
   - **Security Manager**: Security assessment and bypass
   - **Reverse Engineering**: Automated analysis and memory dumps
   - **Remote Control**: Device interaction and screen mirroring

### iOS Quick Start
1. **Connect iOS Device**
   - Connect iPhone/iPad via USB
   - Trust computer when prompted on device
   - Launch `python iphone.py`

2. **Device Pairing**
   - Device should appear in dropdown automatically
   - Click "Connect" to establish connection
   - Verify connection in status bar

3. **Choose Analysis Type**
   - **System Monitor**: Device information and performance
   - **Security Analysis**: Jailbreak detection and security assessment
   - **App Manager**: IPA installation and management
   - **File Manager**: Media directory access

## Usage Examples

### Android Analysis
```bash
# Launch Android controller
python android.py

# Features available:
# - System monitoring and process analysis
# - Security bypass and privilege escalation
# - Memory dumping and binary analysis
# - Network traffic capture and analysis
# - NFC stack analysis and firmware management
```

### iOS Analysis
```bash
# Launch iOS controller
python iphone.py

# Features available:
# - Device information and hardware analysis
# - Application installation and management
# - Crash log collection and analysis
# - Security assessment and jailbreak detection
# - System diagnostic report generation
```

### Cross-Platform Workflow
```bash
# 1. Android reconnaissance
python android.py
# - Gather device information
# - Perform security assessment
# - Extract applications and data

# 2. iOS analysis
python iphone.py
# - Compare security implementations
# - Analyze application differences
# - Cross-reference findings
```

## Advanced Configuration

### Custom Android Exploit Modules
```python
# Add custom exploitation techniques
class CustomExploit(ExploitBase):
    def execute(self):
        # Android-specific implementation
        pass
```

### iOS Analysis Plugins
```python
# Extend iOS analysis capabilities
class iOSAnalyzer(AnalyzerBase):
    def analyze(self, device):
        # iOS-specific analysis logic
        pass
```

## Platform Comparison

| Feature | Android | iOS | Notes |
|---------|---------|-----|-------|
| Root/Jailbreak Detection | ✅ | ✅ | Different methods |
| App Installation | ✅ | ✅ | APK vs IPA |
| File System Access | ✅ | ⚠️ | iOS limited to media |
| Memory Analysis | ✅ | ⚠️ | iOS requires jailbreak |
| Network Monitoring | ✅ | ✅ | Different capabilities |
| Process Management | ✅ | ⚠️ | iOS requires jailbreak |
| Screen Mirroring | ✅ | ❌ | Android only |
| System Logs | ✅ | ✅ | Different access methods |
| Backup/Restore | ✅ | ✅ | Platform-specific formats |

**Legend:** ✅ Full Support | ⚠️ Limited/Requires Special Access | ❌ Not Available

## Troubleshooting

### Android Issues
- **Device not detected**: Check USB debugging and authorize computer
- **ADB timeout**: Verify ADB installation and USB connection
- **Permission errors**: Ensure proper device authorization

### iOS Issues
- **Device not detected**: Check device pairing and trust relationship
- **libimobiledevice errors**: Verify installation and PATH configuration
- **Connection timeouts**: Ensure device is unlocked and trusted

### Common Solutions
- Restart both device and application
- Check USB cable and connection
- Verify platform-specific dependencies
- Review system logs for detailed error information

## Security Considerations

### Responsible Use
- **Only test on authorized devices**
- **Follow coordinated vulnerability disclosure**
- **Respect user privacy and data protection laws**
- **Document all testing activities for accountability**

### Operational Security
- Use in isolated testing environments
- Monitor for unintended network traffic
- Secure storage of extracted data and dumps
- Regular updates for latest security patches
- Platform-specific security considerations

### Platform-Specific Notes

#### Android Security
- SELinux bypass capabilities require careful use
- Root access significantly changes device security posture
- Custom ROM analysis may require different approaches

#### iOS Security
- Jailbreak detection is probabilistic, not definitive
- File system access limited by iOS sandbox
- SSH access requires jailbroken device with OpenSSH

## Project Status

- **Current Version**: 4.0 Multi-Platform Edition
- **Development Status**: Active
- **Python Support**: 3.7+
- **Android Support**: 6.0+ (API 23+)
- **iOS Support**: 12.0+ (iOS 12+)
- **Last Updated**: 2025

## Acknowledgments

- Android Security Research Community
- iOS Security Research Community
- ADB and Android SDK teams
- libimobiledevice project and contributors
- Open source security tool developers
- Responsible disclosure security researchers

## File Structure

```
BridgeSim/
├── android.py          # Android device controller
├── iphone.py           # iOS device controller
├── README.md           # This documentation
├── requirements.txt    # Python dependencies
└── img/               # Documentation images
```

## Getting Help

- **Installation Issues**: Check platform-specific installation guides
- **Android Problems**: Verify ADB setup and device authorization
- **iOS Problems**: Check libimobiledevice installation and device pairing
- **Feature Requests**: Submit GitHub issues with detailed descriptions

---

**Remember: With great power comes great responsibility. Use these tools ethically and legally.**

**For platform-specific guidance:**
- Android: Use Help → Documentation in android.py
- iOS: Use Help → Installation Guide in iphone.py
