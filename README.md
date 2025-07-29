# 🕵️ Forensiq - Cross-Platform Forensic Investigation Tool

**Created by Tarun Sharma**
- Platform: Windows 🪟 | Linux 🐧
- Version: 1.0.0
- License: MIT

Forensiq is a powerful digital forensic toolkit designed to extract system, user, network, and application-level artifacts from **both Windows and Linux systems**. It generates a detailed, dark-themed HTML report and can optionally compress outputs and send them via Telegram.

---
<img width="1012" height="483" alt="Screenshot 2025-07-14 185034" src="https://github.com/user-attachments/assets/c3aa32ea-b76d-42d1-a0bd-8e046ca9635e" />

## 🧩 Key Features

✅ **User & Account Info**
- Current User
- Local User Accounts
- Admin Group Members
- Logon Sessions
- Profiles, Group Memberships

🖥️ **System & Software Info**
- OS & Hardware Information
- Installed Applications
- Hotfixes (Windows)
- Environment Variables

🌐 **Network Forensics**
- Network Interfaces & IP Config
- DNS Cache, ARP Cache, Routes
- TCP/UDP Connections & SMB Activity
- Wi-Fi SSIDs and Passwords (Windows)
- Firewall Rules & RDP History

🔐 **Security & Persistence**
- Startup Programs & Scheduled Tasks
- Services, Registry Persistence (Windows)
- Created/Deleted Users, Group Changes
- Logon Failures, Lockouts
- Credential Backups

📂 **File & Artifact Collection**
- USB, Webcam, and Device History
- Suspicious Executables in:
  - `Downloads/`, `AppData/`, `Temp/`, etc.
- All files created in last 180 days
- PowerShell History (500+ days)
- Log4j, IIS, and Tomcat logs (Windows)

🌐 **Browser Forensics**
- History from Chrome, Firefox, Edge, IE
- Malicious URL Matching

📦 **Reporting & Automation**
- Dark-Themed HTML Report with Expand/Collapse
- Compress all artifacts into `.zip`
- Send via Telegram (Optional)
- Modular Output Structure

---

## ⚙️ Requirements

- Python 3.8+
- OS: Windows 10+, Linux (Debian-based recommended)
- Admin/root permissions (for full data access)

### Install Dependencies:
```bash
pip install -r requirements.txt

```
## ⚠️ Disclaimer

This tool is for **educational and authorized forensic use only**. Use it responsibly. The author is not liable for misuse.

---

## 👨‍💻 Created By

**Tarun Sharma**  
For any questions, contributions, or improvements — feel free to reach out!
