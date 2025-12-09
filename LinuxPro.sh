#!/bin/bash

#1.1 install the needed aplications

function INSTALL()
{
	# This command installs Nmap (for network scanning) and CMatrix (for visual effect, optional)
    # The 'sudo' prefix gives administrator permissions
    # The '-y' flag auto-confirms installation prompts
	sudo apt-get install nmap cmatrix -y
}
# 1.3 check if the network connection is anonymous : if not, alert the user exit

function ANON()
{
     # Get the current public IP address
    IP=$(curl -s ifconfig.co)

    # Lookup the country of this IP and clean the output
    CNTRY=$(geoiplookup $IP | awk '{print $4}' | tr -d ",")

    # If the country is Israel (IL), then it is not anonymous
    if [ "$CNTRY" == "IL" ]
    then
    # Print a message indicating the user is not anonymous and exit the script
        echo "[!!] You are not anonymous, exiting ..."
        exit 
          else
        # Otherwise, print that you are anonymous and show details
        echo "[*] You are anonymous  - spoofed Country:  $(geoiplookup $IP | awk '{print $4}' | sed 's/,//g')"
        echo "[*] IP: [$IP]  COUNTRY: [$CNTRY]"
    
    fi 
}

# Run Nmap scan on that input
nmap $RMTIP


# -------------------------
# function RMT() - remote info collection and remote command execution
# -------------------------

function RMT()
{
	 # Prompt user to enter remote host IP, username and password
    # - read -p displays a prompt and reads input into variable
    # - read -sp reads silently (no echo) for passwords
    
	read -p "Enter the IP address of the Remote server: " RMTIP
  read -p "Enter the username of the Remote server: " RMTUSR
  read -sp "Enter the password of the Remote server: " RMTPASS; echo
  
  # Echo the target for visual confirmation
    # It's helpful for logs / debugging to show which IP we will target
    
  echo "[+] The IP address of the Remote Server is: $RMTIP"

  # בדיקת SSH פתוח
  # Quick check: Run an nmap ping/port probe against port 22 on the remote host.
    # - -Pn : treat host as up (skip host discovery) — useful if ICMP is blocked
    # - -p22 : only scan port 22 (SSH) — fast check if SSH is listening
  nmap -Pn -p22 "$RMTIP"

  # פקודות לדוגמה על ה-Agent
  
  # Run 'uptime -p' on remote and append output to a local file named sysinfo.txt
    # sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTPIP" 'uptime -p' >> sysinfo.txt
  sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" 'uptime -p' >> sysinfo.txt
  
  # Run a remote curl to retrieve the agent's public IP (if agent can call out), append to sysinfo.txt
    # This runs curl on the remote side and writes the result back to local sysinfo.txt 
    sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" 'curl -s ifconfig.me' >> sysinfo.txt
    
    # Run geoiplookup remotely on the agent to get its country (extract with sed to clean output)
    # The command runs on the agent, returns the geoip output to the master, and appends it to sysinfo.txt
 sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" "geoiplookup \$(curl -s ifconfig.me) | sed 's/.*: //'" >> sysinfo.txt
	
	# Log event locally: save a record that we ran the remote system-info collection
    # Use >> to append to systeminfo.log
	echo "[*] $date running system info on the agent" >>systeminfo.log 
	
}


# ================================
# Function: collect_remote_info
# Purpose: Collect remote system information from the Agent machine
# ================================

function collect_remote_info() 
{
	# Create a timestamp variable with current date and time (YYYYMMDD_HHMMSS format)
	
  TSNOW=$(date +"%Y%m%d_%H%M%S")
  
  # Create a new directory under /logs with the current timestamp to store all log files
  mkdir -p logs/"$TSNOW"

# Add a section title to the log file
  echo "==== Remote System Info ($TSNOW) ====" > logs/"$TSNOW"/systeminfo.txt


# ------------------------------------------------------------
    #   Remote public IP
    #    We add a labeled header and then fetch the AGENT's public IP.
    #    - The header is appended with '>>' to keep previous content.
    #    - sshpass -p "$RMTPASS"  supplies the password non-interactively.
    #    - ssh -o StrictHostKeyChecking=no  avoids the host-key prompt,
    #      which is convenient for automation (note: weaker security).
    #    - "curl -s ifconfig.me" runs on the AGENT (due to ssh),
    #      returns the public IP as seen from the Internet, and
    #      stdout is piped back to the MASTER and appended to the file.
    #    - '-s' (silent) suppresses curl's progress meter for clean logs.
    # ------------------------------------------------------------
  echo "[Remote public IP]:" >> logs/"$TSNOW"/systeminfo.txt
  sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" "curl -s ifconfig.me" >> logs/"$TSNOW"/systeminfo.txt

  echo >> logs/"$TSNOW"/systeminfo.txt
  
  # ------------------------------------------------------------
    #    Remote country
    #    We resolve the AGENT's public IP to a country name.
    #    - We again append a labeled header first.
    #    - The command executed on the AGENT nests two commands:
    #         $(curl -s ifconfig.me)            -> returns the public IP
    #         geoiplookup <that IP>             -> maps IP to GeoIP record
    #      The whole string is quoted so the remote shell expands $().
    #    - sed 's/,//' removes commas that some GeoIP DBs include,
    #      so the resulting line is cleaner (e.g., "IL, Israel" -> "IL Israel").
    # ------------------------------------------------------------
  echo "[Remote country]:" >> logs/"$TSNOW"/systeminfo.txt
  sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" "geoiplookup \$(curl -s ifconfig.me) | sed 's/.*: //'" >> logs/"$TSNOW"/systeminfo.txt

  echo >> logs/"$TSNOW"/systeminfo.txt
  
 # ------------------------------------------------------------
    #   Remote uptime
    #    We ask the AGENT how long it's been up using 'uptime -p'.
    #    - '-p' = present in a pretty, human-readable format
    #             (e.g., 'up 8 hours, 3 minutes') without load averages.
    #    - Again, stdout of the remote command is written locally.
    # ------------------------------------------------------------
  echo "[Remote uptime]:" >> logs/"$TSNOW"/systeminfo.txt
  sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" "uptime -p" >> logs/"$TSNOW"/systeminfo.txt

# ------------------------------------------------------------
    #   Final console notice (not written to the file):
    #    Useful for the operator to quickly know where the file is.
    # ------------------------------------------------------------

  echo "[*] Saved remote info to logs/$TSNOW/systeminfo.txt"
}






# =====================================================================
# Function: EXTDATA
# Purpose : From the MASTER, run remote WHOIS (for a domain) and Nmap
#           (for an IP/IP-range) on the AGENT, save RAW outputs to .data
#           files, and write Windows-style event lines to .log files.
#
# Requires (must be set earlier): RMTIP, RMTUSR, RMTPASS
# Prompts the user for: DNM (domain), RIP (IP/range)
# Creates per-run folder: logs/<TS>   where TS=YYYYMMDD_HHMMSS
# Files produced:
#   logs/<TS>/whois.data   <-- full whois output (RAW content)
#   logs/<TS>/nmap.data    <-- full nmap output (RAW content)
#   logs/<TS>/whois.log    <-- event line only (what + when)
#   logs/<TS>/nmap.log     <-- event line only (what + when)
#   events.log             <-- global event feed (append-only)
# =====================================================================



function EXTDATA()
{
	# --- Collect user input for targets --------------------------------
    # Ask for a domain to investigate; store into variable DNM
	 read -p "Enter a domain to investigate: " DNM
	 
	 # Ask for a single IP or CIDR/range to scan; store into RIP
  read -p "Enter an ip or ip range to scan: " RIP

  # --- Build a unique per-run directory under ./logs ------------------
    # TS contains a sortable wall-clock timestamp 
  TS="$(date +'%Y%m%d_%H%M%S')"
  # LOGDIR points to the subfolder for this run
  LOGDIR="logs/$TS"
  # Create the folder tree if missing; no error if it already exists
  mkdir -p "$LOGDIR"
  
  
  
  # --- EXECUTION on the AGENT: generate RAW DATA files ----------------
    # WHOIS: run remotely on the AGENT and capture RAW output locally.
    # - sshpass: supply password non-interactively (convenient for labs)
    # - StrictHostKeyChecking=no: skip host-key prompt (automation-friendly)
    # - 'whois "$DNM"': actually runs on the AGENT; stdout streams back
    # - '> "$LOGDIR/whois.data"': create/overwrite RAW file with whois body
  
  # --- הרצות על ה-agent ושמירה לקבצי DATA (תוכן מלא) ---
  sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" \
    "whois '$DNM'" > "$LOGDIR/whois.data"


# Nmap: run remotely on the AGENT against the target IP/range.
    # -Pn: treat host as up (skip ICMP discovery) – useful if ping is blocked
    # -sS: SYN scan (stealthy and fast for TCP)
    # -T4: faster timing template (balance speed/accuracy)
    # Quote $RIP to survive spaces/newlines; save RAW body to nmap.data

  sshpass -p "$RMTPASS" ssh -o StrictHostKeyChecking=no "$RMTUSR@$RMTIP" \
    "nmap -Pn -sS -T4 '$RIP'" > "$LOGDIR/nmap.data"

  # --- Windows-style EVENTS (metadata only, no RAW content) -----------
    # Get a human-readable timestamp for the event lines
  DATE_NOW="$(date '+%Y-%m-%d %H:%M:%S')"
  
  
  # Write one-line events into per-tool logs (overwrite to keep 1 line/run)
    # These files contain ONLY the fact of execution (what/when/target),
    # not the data that was collected
  echo "[$DATE_NOW] whois executed (domain=$DNM)" > "$LOGDIR/whois.log"
  echo "[$DATE_NOW] nmap executed (target=$RIP)"  > "$LOGDIR/nmap.log"

 # --- Console summary (operator feedback) ----------------------------
    # Inform the operator where RAW and EVENT files were saved
  echo "[*] Saved DATA: $LOGDIR/whois.data , $LOGDIR/nmap.data"
  echo "[*] Saved LOG : $LOGDIR/whois.log  , $LOGDIR/nmap.log"


# --- Global event feed (append-only history across runs) ------------
    # Useful for auditing: list when/what ran and where RAW resides
  echo "[$DATE_NOW] whois executed -> $LOGDIR/whois.data" >> events.log
  echo "[$DATE_NOW] nmap executed  -> $LOGDIR/nmap.data"  >> events.log

  
  
	
}	







INSTALL
ANON
RMT
collect_remote_info
EXTDATA
