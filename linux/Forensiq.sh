#!/bin/bash

# Forensiq Linux Forensic Tool by Tarun Sharma
# Full version with WiFi Password Dump + Professional HTML UI

OUTPUT_DIR="forensiq_output"
ZIP_FILE="forensiq_report_$(date +%F_%T).zip"
HTML_REPORT="$OUTPUT_DIR/Forensiq_report.html"

mkdir -p "$OUTPUT_DIR"

banner() {
cat << "EOF"

     ______                           _      
    / ____/___  ________  ____  _____(_)___ _
   / /_  / __ \/ ___/ _ \/ __ \/ ___/ / __ `/
  / __/ / /_/ / /  /  __/ / / (__  ) / /_/ / 
 /_/    \____/_/   \___/_/ /_/____/_/\__, /  
                                       /_/     

     >> FORENSIQ - Linux Forensic Intelligence Toolkit <<
                    Developed by Tarun Sharma

EOF
}

banner
echo "[+] Saving output to: $OUTPUT_DIR"

# -------- Basic Collection --------
echo "[+] Collecting user info..."
w > "$OUTPUT_DIR/current_user_sessions.txt"
getent passwd | awk -F: '($7 ~ /bash|sh/)' > "$OUTPUT_DIR/users_with_login_shells.txt"
find /home -name "authorized_keys" 2>/dev/null > "$OUTPUT_DIR/ssh_auth_keys.txt"
cp /etc/passwd "$OUTPUT_DIR/passwd_file.txt"
cp /etc/sudoers "$OUTPUT_DIR/sudoers_file.txt" 2>/dev/null

echo "[+] System and kernel info..."
hostnamectl > "$OUTPUT_DIR/system_info.txt"
uname -a > "$OUTPUT_DIR/kernel_info.txt"
lscpu > "$OUTPUT_DIR/cpu_info.txt"

lsblk > "$OUTPUT_DIR/block_devices.txt"
lsusb > "$OUTPUT_DIR/usb_controllers.txt"
lspci | grep -i sata > "$OUTPUT_DIR/sata_devices.txt"

echo "[+] Network and firewall info..."
ip route > "$OUTPUT_DIR/routing_table.txt"
ip a > "$OUTPUT_DIR/ip_info.txt"
iptables -L -v -n > "$OUTPUT_DIR/firewall_rules.txt" 2>/dev/null
cat /etc/hosts > "$OUTPUT_DIR/hosts_file.txt"
cat /etc/hosts.allow > "$OUTPUT_DIR/hosts_allow.txt" 2>/dev/null
cat /etc/resolv.conf > "$OUTPUT_DIR/hosts_resolv.txt"

# -------- WiFi Dump --------
echo "[+] Extracting saved WiFi passwords..."
WIFI_FILE="$OUTPUT_DIR/wifi_passwords.txt"
echo "🛡️ Saved WiFi SSIDs & Passwords:" > "$WIFI_FILE"
for file in /etc/NetworkManager/system-connections/*; do
  if [[ -f "$file" ]]; then
    ssid=$(grep -i '^ssid=' "$file" | cut -d'=' -f2)
    psk=$(grep -i '^psk=' "$file" | cut -d'=' -f2)
    [[ -z "$ssid" ]] && continue
    echo -e "\nSSID: $ssid" >> "$WIFI_FILE"
    [[ -n "$psk" ]] && echo "Password: $psk" >> "$WIFI_FILE" || echo "Password: Not Found" >> "$WIFI_FILE"
  fi
done

# -------- Process & Logs --------
echo "[+] Capturing running processes..."
ps aux > "$OUTPUT_DIR/processes.txt"
ss -tuln > "$OUTPUT_DIR/tcp_connections.txt"
systemctl list-units --type=service > "$OUTPUT_DIR/services.txt"
systemctl list-unit-files --state=enabled > "$OUTPUT_DIR/enabled_services.txt"
systemctl list-timers > "$OUTPUT_DIR/all_timers.txt"
crontab -l > "$OUTPUT_DIR/current_user_cron.txt" 2>/dev/null
ls /etc/cron* > "$OUTPUT_DIR/etc_cron_dirs.txt"

last -a > "$OUTPUT_DIR/last_logins.txt"
cat /var/log/auth.log > "$OUTPUT_DIR/auth_logs.txt" 2>/dev/null

getcap -r /usr/bin/ > "$OUTPUT_DIR/usr_bin_caps.txt" 2>/dev/null
find / -perm -4000 2>/dev/null > "$OUTPUT_DIR/setuid_files.txt"

# -------- Persistence --------
ls /etc/systemd/system/* > "$OUTPUT_DIR/persistence_systemd.txt"
ls /var/spool/cron/* 2>/dev/null > "$OUTPUT_DIR/spool_cron.txt"
ls /etc/init* > "$OUTPUT_DIR/persistence_init.txt"

# -------- Browser + Files --------
echo "[+] Extracting Firefox history..."
sqlite3 ~/.mozilla/firefox/*.default*/places.sqlite \
  "SELECT url, datetime(visit_date/1000000,'unixepoch') FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id ORDER BY visit_date DESC LIMIT 100;" \
  > "$OUTPUT_DIR/firefox_history.txt" 2>/dev/null

cat ~/.bashrc > "$OUTPUT_DIR/bash_profile.txt" 2>/dev/null
lsof 2>/dev/null > "$OUTPUT_DIR/open_files.txt"
lspci > "$OUTPUT_DIR/pci_devices.txt"

find / -type f -not -path "/run/user/*/gvfs/*" -not -path "/run/user/*/doc/*" \
  -printf '%T+ %p\n' 2>/dev/null | sort -r | head -n 100 > "$OUTPUT_DIR/timeline_logs.txt"

strings /dev/mem > "$OUTPUT_DIR/ram_capture.txt" 2>/dev/null

find / -type f \( -name "*.encrypted" -o -name "*.locky" -o -name "*.crypt" \) \
  -not -path "/run/user/*/gvfs/*" -not -path "/run/user/*/doc/*" 2>/dev/null \
  > "$OUTPUT_DIR/ransomware_extensions.txt"

cp /var/log/apache2/access.log "$OUTPUT_DIR/web_access_logs.txt" 2>/dev/null
cp /var/log/nginx/access.log "$OUTPUT_DIR/nginx_access_logs.txt" 2>/dev/null

# -------- HTML Report --------
echo "[+] Generating professional HTML report..."
echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Forensiq Linux Report</title>
<style>
body{margin:0;background:#0b0c20;color:#c5c6c7;font-family:'Segoe UI',sans-serif}
nav{position:fixed;top:0;width:100%;background:#1d2a45;padding:10px;white-space:nowrap;overflow-x:auto;z-index:1000;border-bottom:1px solid #45a29e}
nav a{color:#66fcf1;margin:0 15px;text-decoration:none;font-weight:bold}
.container{margin-top:70px;padding:20px}
h1{color:#66fcf1}
button{background:#45a29e;color:white;padding:10px 15px;border:none;border-radius:5px;margin:10px;font-weight:bold;cursor:pointer}
h2{margin-top:30px;cursor:pointer;background:#1f2833;padding:10px;border-radius:5px;color:#66fcf1}
pre{display:none;background:#1f2833;padding:15px;border-left:3px solid #45a29e;white-space:pre-wrap;border-radius:5px;overflow:auto}
footer{text-align:center;padding:10px;border-top:1px solid #45a29e;margin-top:50px}
</style>
<script>
function toggle(id){var el=document.getElementById(id);el.style.display=(el.style.display==='block')?'none':'block';}
function toggleAll(state){document.querySelectorAll('pre').forEach(el=>el.style.display=state?'block':'none');}
</script>
</head><body><nav>" > "$HTML_REPORT"

for f in "$OUTPUT_DIR"/*.txt; do
  name=$(basename "$f" .txt)
  echo "<a href='#$name'>$name</a>" >> "$HTML_REPORT"
done

echo "</nav><div class='container'><h1>🛡️ Forensiq Linux Report</h1>
<button onclick='toggleAll(true)'>Expand All</button>
<button onclick='toggleAll(false)'>Collapse All</button><hr>" >> "$HTML_REPORT"

for f in "$OUTPUT_DIR"/*.txt; do
  id=$(basename "$f" .txt)
  echo "<section><h2 onclick=\"toggle('$id')\">$id</h2><pre id=\"$id\">" >> "$HTML_REPORT"
  cat "$f" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' >> "$HTML_REPORT"
  echo "</pre></section>" >> "$HTML_REPORT"
done

echo "<footer>
  <p>🔧 Report Generated by <strong>Forensiq</strong> | Developer: Tarun Sharma</p>
  <p>🌐 GitHub: <a href='https://github.com/DeadpooHackes/Forensiq' target='_blank' style='color:#66fcf1;'>github.com/TarunSharma-OSS</a></p>
</footer></div></body></html>" >> "$HTML_REPORT"


# -------- Compress Report --------
echo "[+] Zipping report as $ZIP_FILE..."
zip -r "$ZIP_FILE" "$OUTPUT_DIR" > /dev/null
echo "[✔] Forensic collection complete: $ZIP_FILE"
