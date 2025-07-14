# 🛡️ Forensiq - Advanced Forensic Intelligence Toolkit (Linux Edition)

**Created by**: Tarun Sharma  
**Version**: Linux Edition  
**License**: MIT  
**Status**: ✅ Active  
**Platform**: Linux (Tested on Kali, Ubuntu, Parrot OS)

---

## 🚀 Overview

**Forensiq** is a powerful all-in-one Linux forensic investigation and incident response toolkit. Designed for cybersecurity professionals, it collects a wide range of data for digital investigations and generates an interactive HTML report.

---

## 📦 Features

✅ User session logs  
✅ System info & kernel details  
✅ Network & firewall configuration  
✅ Running processes, services, and timers  
✅ USB, SATA, and block device info  
✅ Binary capabilities & SetUID findings  
✅ Persistence mechanisms (cron, init, systemd, motd)  
✅ Browser history (Firefox SQLite extraction)  
✅ WiFi SSIDs & passwords (Linux only)  
✅ Timeline of file modifications  
✅ RAM memory dump (strings from /dev/mem)  
✅ Web server access logs (Apache/Nginx)  
✅ Expandable/collapsible HTML report  
✅ Compressed ZIP output of all results

---

## 📂 Output Structure

After execution, the tool creates the following:

```
forensiq_output/
├── system_info.txt
├── firewall_rules.txt
├── firefox_history.txt
├── wifi_passwords.txt
├── ...
├── Forensiq_report.html
forensiq_report_<date>.zip
```

---

## ⚙️ Requirements

- Linux system with:
  - `bash`
  - `ps`, `ss`, `ip`, `systemctl`, `find`, `getcap`
  - `sqlite3` for Firefox history
  - `zip` for compression

> **Note**: Run the script with `sudo` for full system access.

---

## 🧪 Installation

Clone the repository and run the script:

```bash
git clone https://github.com/DeadpooHackes/Forensiq.git
cd Forensiq/linux
chmod +x forensiq.sh
sudo ./forensiq.sh
```

---

## 🌐 HTML Report Highlights

- ✅ Clickable headings (toggle visibility)
- ✅ Clean dark-themed interface
- ✅ Expand All / Collapse All buttons
- ✅ HTML rendered version of all collected `.txt` logs

---

## 📤 How to Use

```bash
# Unzip the output
unzip forensiq_report_<date>.zip

# Open the HTML report in your browser
xdg-open forensiq_output/Forensiq_report.html
```

---

## 🔐 WiFi Password Recovery (Linux)

The tool attempts to extract saved SSIDs and passwords from:

- `/etc/NetworkManager/system-connections/*.nmconnection`
- `/etc/wpa_supplicant.conf`
- Other common paths depending on distribution

---

## 💡 Use Cases

- Digital forensics
- Incident response
- Malware infection investigation
- Blue Team/CTF automation
- Security auditing in air-gapped Linux systems

---

## 📬 Contact & Credits

## **Created by Tarun Sharma**

## 📜 License

This project is licensed under the **MIT License**.  
See `LICENSE` file for full details.

---

> 💡 _Contributions and feedback are welcome. Let’s improve Linux forensic automation together!_
