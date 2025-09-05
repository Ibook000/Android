# AntiWipe - KernelSU Protection Module

[![Build Status](https://github.com/yourusername/antiwipe-kpm/workflows/Build%20AntiWipe%20KPM%20Module/badge.svg)](https://github.com/yourusername/antiwipe-kpm/actions)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## 🛡️ Overview

AntiWipe is a KernelSU KPM (Kernel Patch Module) designed to protect Android devices against malicious wipe scripts that attempt to destroy data by overwriting storage partitions.

## 🚨 Threat Analysis

The malicious script this module protects against:
- Hides its operations using output redirection
- Creates toybox aliases to bypass monitoring
- Forcefully unmounts and overwrites storage partitions
- Targets critical system partitions
- Runs operations in parallel for maximum damage

## ✨ Features

### 1. **Partition Protection**
- Blocks write access to critical partitions
- Protected partitions include:
  - `persist`, `vm-persist`
  - `modem_a/b`, `modemst1/2`
  - `fsg`, `fsc`
  - `abl_a/b`, `featenabler_a/b`
  - `xbl_*` partitions
  - `vendor_boot_a/b`, `ocdt`

### 2. **Command Interception**
- Monitors execution of dangerous commands
- Intercepted commands: `dd`, `mkfs`, `format`, `wipe`
- Requires user confirmation before execution

### 3. **Device Protection**
- Prevents deletion of `/dev/input/*` devices
- Blocks unauthorized device node modifications

### 4. **User Confirmation System**
- Volume+ key: Confirm operation
- Volume- key: Deny operation
- 5-second timeout (auto-deny)

## 📦 Installation

### Method 1: Pre-built Releases
1. Download the appropriate ZIP from [Releases](https://github.com/yourusername/antiwipe-kpm/releases)
2. Open KernelSU Manager
3. Go to Modules section
4. Click "Install from storage"
5. Select the downloaded ZIP
6. Reboot your device

### Method 2: Build from Source
```bash
git clone https://github.com/yourusername/antiwipe-kpm.git
cd antiwipe-kpm
chmod +x build.sh
./build.sh