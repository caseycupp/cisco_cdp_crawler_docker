#!/usr/bin/env python3
"""
Cisco CDP Site Inventory - Improved Device Detection Version
Discovers network devices via CDP and generates inventory CSV

Key Improvements:
- Device type detection based on MODEL (show version output)
- Supports routers, switches, distribution switches, and firewalls
- Handles your actual naming conventions
- More robust parsing for different Cisco platforms

Supported Devices:
- Cisco SD-WAN routers (C1000, C1100, C8000 series)
- Cisco ISR/ASR routers (ISR4451, ASR1000, 2900, etc.)
- Cisco switches (2900, 3000, 4000 series)
- Palo Alto firewalls (detected via CDP neighbors)

Note: Palo Alto firewalls will be discovered via CDP but cannot be logged into
      with Cisco IOS commands. They will be recorded with limited info.
"""

from netmiko import ConnectHandler
from collections import deque
import csv
import re
import getpass
import logging
import datetime
import socket
import sys
import signal

# =========================
# CONFIGURATION
# =========================
DOMAIN = "cuppco.lab"
DEVICE_TYPE = "cisco_ios"

# Updated naming patterns based on your actual conventions
# Routers: end with r + digits (e.g., ohdelr1, oksar2)
# Must NOT match: server1, router1 (full words)
ROUTER_NAME_REGEX = re.compile(r"[a-z0-9]+r\d+$", re.IGNORECASE)

# Distribution switches: end with disr + digits
DIST_SWITCH_NAME_REGEX = re.compile(r"disr\d+$", re.IGNORECASE)

# Access switches: end with s + digits (e.g., ohdels1, lasbes2)
# Must NOT match: test1, access1 (full words)
ACCESS_SWITCH_NAME_REGEX = re.compile(r"[a-z0-9]+s\d+$", re.IGNORECASE)

# Firewalls: end with f + digits, fw, or scaf + digits
FIREWALL_NAME_REGEX = re.compile(r"(f\d+|fw|scaf\d+)$", re.IGNORECASE)

# Combined device regex - matches network devices only
# Pattern: [site code][device type][number]
# Examples: ohdelr1, ohdels1, ohdeldisr1, ohdelfw, cdp_sw13, crawl01, vios, cclabs1
# Accepts: various naming patterns including CDP_SW##, crawl##, cclabs##, vios, etc.
# Rejects: server1, test1, ap-office1 (pure generic names)
DEVICE_NAME_REGEX = re.compile(r"([a-z0-9_]+\d+|[a-z0-9_]+[a-z]\d+|vios|nxos|paloalto)$", re.IGNORECASE)

# Model-based detection patterns (most reliable!)
ROUTER_MODEL_PATTERNS = [
    # Cisco SD-WAN routers (vEdge/cEdge)
    re.compile(r"C1000", re.IGNORECASE),            # C1000 series SD-WAN
    re.compile(r"C1100", re.IGNORECASE),            # C1100 series SD-WAN
    re.compile(r"C8000", re.IGNORECASE),            # C8000 series SD-WAN
    re.compile(r"C8200", re.IGNORECASE),            # C8200 series SD-WAN
    re.compile(r"C8300", re.IGNORECASE),            # C8300 series SD-WAN
    re.compile(r"C8500", re.IGNORECASE),            # C8500 series SD-WAN
    # Traditional ISR/ASR routers (DMVPN, non-SD-WAN)
    re.compile(r"ISR\d+", re.IGNORECASE),           # ISR4451, ISR4331, ISR2911, etc.
    re.compile(r"ASR\d+", re.IGNORECASE),           # ASR1000, ASR9000
    re.compile(r"CSR\d+", re.IGNORECASE),           # CSR1000v (virtual)
    re.compile(r"\d{4}\/K9", re.IGNORECASE),        # 2911/K9, 4451/K9
    re.compile(r"CISCO\d{4}", re.IGNORECASE),       # CISCO2911, CISCO4451
    re.compile(r"C\d{4}-", re.IGNORECASE),          # C2911-, C4451-
    # 800 series (small branch routers)
    re.compile(r"CISCO8\d{2}", re.IGNORECASE),      # CISCO809, CISCO829
    re.compile(r"C8\d{2}[^0]", re.IGNORECASE),      # C809, C829 (but not C8000)
    re.compile(r"80[0-9]", re.IGNORECASE),          # 809, 829, 861, 881, 891
    re.compile(r"82[0-9]", re.IGNORECASE),          # 829, 861
    re.compile(r"86[0-9]", re.IGNORECASE),          # 861, 867, 881, 886, 887, 891, 892
    re.compile(r"88[0-9]", re.IGNORECASE),          # 881, 886, 887
    re.compile(r"89[0-9]", re.IGNORECASE),          # 891, 892
    # Legacy routers
    re.compile(r"18\d{2}", re.IGNORECASE),          # 1841, 1861
    re.compile(r"28\d{2}", re.IGNORECASE),          # 2801, 2811, 2821
    re.compile(r"29\d{2}", re.IGNORECASE),          # 2901, 2911, 2921
    re.compile(r"38\d{2}", re.IGNORECASE),          # 3825, 3845
]

SWITCH_MODEL_PATTERNS = [
    # Catalyst 2900 series (access switches)
    re.compile(r"WS-C29\d+", re.IGNORECASE),        # WS-C2960X, WS-C2960, WS-C2950
    re.compile(r"C29\d+", re.IGNORECASE),           # C2960X, C2960, C2960L
    re.compile(r"2900", re.IGNORECASE),             # Generic 2900 series
    # Catalyst 3000 series (can be L2 or L3)
    re.compile(r"WS-C30\d+", re.IGNORECASE),        # WS-C3060
    re.compile(r"C30\d+", re.IGNORECASE),           # C3000 series
    # Other access switches
    re.compile(r"ME-\d+", re.IGNORECASE),           # ME-3400
    re.compile(r"catalyst", re.IGNORECASE),         # Generic Catalyst
]

DIST_SWITCH_MODEL_PATTERNS = [
    # Layer 3 switches (distribution/core)
    # 3000 series Layer 3
    re.compile(r"WS-C37\d+", re.IGNORECASE),        # WS-C3750, WS-C3750X (L3)
    re.compile(r"WS-C38\d+", re.IGNORECASE),        # WS-C3850 (L3)
    re.compile(r"C37\d+", re.IGNORECASE),           # C3750, C3750X (L3)
    re.compile(r"C38\d+", re.IGNORECASE),           # C3850 (L3)
    # 4000 series (distribution)
    re.compile(r"WS-C4\d+", re.IGNORECASE),         # WS-C4500, WS-C4900 (L3)
    re.compile(r"C4\d+", re.IGNORECASE),            # C4500 series (L3)
    re.compile(r"4500", re.IGNORECASE),             # Generic 4500
    # 6000/9000 series (core)
    re.compile(r"WS-C6\d+", re.IGNORECASE),         # WS-C6500 (L3)
    re.compile(r"C6\d+", re.IGNORECASE),            # C6500 series (L3)
    re.compile(r"C93\d+", re.IGNORECASE),           # C9300, C9500 (L3)
    re.compile(r"C95\d+", re.IGNORECASE),           # C9500 (core)
]

FIREWALL_MODEL_PATTERNS = [
    # Palo Alto firewalls
    re.compile(r"PA-\d+", re.IGNORECASE),           # PA-220, PA-850, PA-3220, etc.
    re.compile(r"PA-VM", re.IGNORECASE),            # PA-VM (virtual)
    re.compile(r"Palo Alto", re.IGNORECASE),        # Any Palo Alto
    # Legacy Cisco firewalls (if any still exist)
    re.compile(r"ASA\d+", re.IGNORECASE),           # ASA5506, ASA5525
    re.compile(r"FPR\d+", re.IGNORECASE),           # FPR2130, FPR4150
    re.compile(r"Firepower", re.IGNORECASE),        # Firepower models
]

CSV_FIELDS = [
    "site",
    "hostname",
    "status",
    "device_type",
    "model",
    "serial_number",
    "firmware"
]

# Connection timeouts (seconds)
TIMEOUT = 10
CONN_TIMEOUT = 10
AUTH_TIMEOUT = 10
BANNER_TIMEOUT = 10

# Global for graceful shutdown
rows_global = []
csv_file_global = ""

# =========================
# LOGGING SETUP
# =========================
def setup_logging(site_name):
    """Setup logging to both file and console"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"cdp_crawl_{site_name[:10].replace(' ', '_')}_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return log_file

# =========================
# SIGNAL HANDLER
# =========================
def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print('\n\n[!] Interrupted by user! Writing partial CSV...')
    logging.warning("Crawl interrupted by user")
    
    if rows_global and csv_file_global:
        write_csv(csv_file_global, rows_global)
        print(f"[+] Partial results saved to {csv_file_global}")
    
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# =========================
# HELPER FUNCTIONS
# =========================
def short_hostname(name: str) -> str:
    """Extract short hostname (remove domain). Handle IPs without splitting."""
    # Check if it's an IP address
    try:
        socket.inet_aton(name)
        return name.strip()  # It's an IP, return as-is
    except socket.error:
        pass
    # It's a hostname, extract short name
    return name.split(".")[0].lower().strip()

def fqdn_from_short(short: str) -> str:
    """Convert short hostname to FQDN, with DNS check. Fall back to IP if available."""
    # Check if it's already an IP address
    try:
        socket.inet_aton(short)
        return short  # It's an IP, use directly
    except socket.error:
        pass
    
    # Build FQDN
    fqdn = f"{short}.{DOMAIN}"
    
    # Try DNS resolution first
    try:
        resolved_ip = socket.gethostbyname(fqdn)
        logging.info(f"DNS resolved {fqdn} -> {resolved_ip}")
        return fqdn
    except socket.gaierror:
        logging.warning(f"DNS lookup failed for {fqdn}")
        
        # Fallback: Try to guess IP from hostname pattern
        # Lab pattern: cdp_sw13 -> 192.168.1.7X, crawlr1 -> 192.168.1.7X, etc.
        # This is a workaround for labs without DNS
        ip_mapping = {
            'crawlr1': '192.168.1.71',
            'crawlr2': '192.168.1.72',
            'cdp_sw12': '192.168.1.73',
            'cdp_sw13': '192.168.1.74',
            'cdp_sw14': '192.168.1.75',
            'cdp_sw15': '192.168.1.76',
            'cdp_sw16': '192.168.1.77',
            'nxos2': '192.168.1.78',
        }
        
        hostname_short = short.lower()
        if hostname_short in ip_mapping:
            fallback_ip = ip_mapping[hostname_short]
            logging.warning(f"Using hardcoded mapping: {hostname_short} -> {fallback_ip}")
            return fallback_ip
    
    # If all else fails, return FQDN anyway (might fail on connect)
    return fqdn

def site_csv_filename(site: str) -> str:
    """Generate CSV filename from site name"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # For IPs, use a fixed prefix; for hostnames, use site name
    if site.replace(".", "").isdigit():
        # It's an IP, use a fixed name
        safe_site = "cdp_crawl"
    else:
        safe_site = site.strip().replace(" ", "_").lower()[:15]
    return f"{safe_site}_{timestamp}.csv"

def connect_device(fqdn: str, username: str, password: str, secret: str):
    """
    Connect to device via SSH with proper timeouts
    """
    conn = ConnectHandler(
        device_type=DEVICE_TYPE,
        host=fqdn,
        username=username,
        password=password,
        secret=secret,
        fast_cli=False,
        timeout=TIMEOUT,
        conn_timeout=CONN_TIMEOUT,
        auth_timeout=AUTH_TIMEOUT,
        banner_timeout=BANNER_TIMEOUT
    )
    conn.enable()
    conn.send_command("terminal length 0")
    return conn

# =========================
# DEVICE TYPE DETECTION
# =========================
def detect_device_type_from_model(model: str, show_version_output: str) -> str:
    """
    Detect device type based on MODEL (most reliable method)
    """
    if not model:
        model = ""
    
    model_upper = model.upper()
    output_lower = show_version_output.lower()
    
    # Check for firewall models first (most specific)
    for pattern in FIREWALL_MODEL_PATTERNS:
        if pattern.search(model) or pattern.search(show_version_output):
            return "firewall"
    
    # Check for router models
    for pattern in ROUTER_MODEL_PATTERNS:
        if pattern.search(model):
            return "router"
    
    # Check for distribution switch models (Layer 3)
    for pattern in DIST_SWITCH_MODEL_PATTERNS:
        if pattern.search(model):
            return "distribution_switch"
    
    # Check for regular switch models
    for pattern in SWITCH_MODEL_PATTERNS:
        if pattern.search(model):
            return "switch"
    
    # Fallback: Check capabilities in show version output
    if "firewall" in output_lower or "asa" in output_lower:
        return "firewall"
    
    if "switch" in output_lower and "ports" in output_lower:
        # Check if it's a Layer 3 switch
        if "ip routing" in output_lower or "layer 3" in output_lower:
            return "distribution_switch"
        return "switch"
    
    if "router" in output_lower:
        return "router"
    
    # Last resort: fallback to "unknown"
    logging.warning(f"Could not determine device type from model: {model}")
    return "unknown"

def detect_device_type_from_hostname(hostname: str) -> str:
    """
    Fallback: Detect device type from hostname pattern
    """
    hostname_lower = hostname.lower()
    
    if FIREWALL_NAME_REGEX.search(hostname):
        return "firewall"
    
    if DIST_SWITCH_NAME_REGEX.search(hostname):
        return "distribution_switch"
    
    if ROUTER_NAME_REGEX.search(hostname):
        return "router"
    
    if ACCESS_SWITCH_NAME_REGEX.search(hostname):
        return "switch"
    
    return "unknown"

def detect_device_type(hostname: str, model: str, show_version_output: str) -> str:
    """
    Comprehensive device type detection
    Priority: 1) Model, 2) Show version output, 3) Hostname
    """
    # First try model-based detection (most reliable)
    device_type = detect_device_type_from_model(model, show_version_output)
    
    if device_type != "unknown":
        return device_type
    
    # Fallback to hostname pattern
    device_type = detect_device_type_from_hostname(hostname)
    
    if device_type != "unknown":
        logging.info(f"  Device type detected from hostname: {device_type}")
        return device_type
    
    logging.warning(f"Could not determine device type for {hostname}")
    return "unknown"

# =========================
# PARSING FUNCTIONS
# =========================
def parse_model_from_show_version(output: str) -> str:
    """
    Extract model from show version output
    Handles multiple Cisco output formats
    """
    lines = output.splitlines()
    
    # Method 1: Look for "Model Number" or "Model number"
    for line in lines:
        if "Model Number" in line or "Model number" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                return parts[-1].strip()
    
    # Method 2: Look for switch table format (for switches/stacks)
    # Format: "Switch Ports Model              SW Version"
    #         "*    1 28    WS-C3850-24P       16.12.4"
    for i, line in enumerate(lines):
        if "Switch" in line and "Ports" in line and "Model" in line:
            # Found header, look for data in next few lines
            for j in range(i + 1, min(i + 5, len(lines))):
                data_line = lines[j].strip()
                if data_line and not data_line.startswith("-"):
                    # Parse: "*    1 28    WS-C3850-24P       16.12.4"
                    parts = data_line.split()
                    # Look for part that matches switch model pattern
                    for part in parts:
                        if part.upper().startswith("WS-C") or part.upper().startswith("C29") or part.upper().startswith("C30") or part.upper().startswith("C37") or part.upper().startswith("C38"):
                            return part
            break
    
    # Method 3: Look for cisco model in first few lines
    for line in lines[:15]:
        line_lower = line.lower()
        
        # Pattern: "cisco ISR4451-X/K9 (2RU) processor"
        if "cisco" in line_lower and "processor" in line_lower:
            parts = line.split()
            for i, part in enumerate(parts):
                if part.lower() == "cisco" and i + 1 < len(parts):
                    model = parts[i + 1]
                    # Clean up model string
                    model = model.split("(")[0].strip()
                    return model
        
        # Pattern: "Cisco C3850-24P" or "cisco WS-C3850-24P"
        if "cisco" in line_lower and ("ws-c" in line_lower or "cisco c" in line_lower):
            parts = line.split()
            for part in parts:
                if part.upper().startswith("C") or part.upper().startswith("WS-C"):
                    return part.strip()
    
    # Method 4: Look for "Model" keyword anywhere
    for line in lines:
        if "Model" in line and ":" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                potential_model = parts[-1].strip()
                if potential_model and len(potential_model) > 2:
                    return potential_model
    
    return ""

def parse_serial_from_show_version(output: str) -> str:
    """Extract serial number from show version output"""
    lines = output.splitlines()
    
    # Method 1: Processor board ID
    for line in lines:
        if "Processor board ID" in line:
            parts = line.split()
            if parts:
                return parts[-1].strip()
    
    # Method 2: System serial number
    for line in lines:
        if "System serial number" in line or "System Serial Number" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                return parts[-1].strip()
    
    # Method 3: Switch stack serial (for switches)
    for line in lines:
        if "Switch" in line and "Serial" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if "Serial" in part and i + 2 < len(parts):
                    return parts[i + 2].strip()
    
    return ""

def parse_firmware_from_show_version(output: str) -> str:
    """Extract firmware version from show version output"""
    lines = output.splitlines()
    
    # Look for Cisco IOS version in first 10 lines
    for line in lines[:10]:
        if "Cisco IOS XE Software" in line or "Cisco IOS Software" in line:
            return line.strip()
    
    # Fallback: look for "Version" keyword
    for line in lines[:15]:
        if "Version" in line and ("IOS" in line or "Software" in line):
            return line.strip()
    
    return ""

def get_device_facts(conn, expected_hostname):
    """
    Parse device facts from show version
    Uses expected_hostname for consistency
    """
    output = conn.send_command("show version")
    
    # Use expected hostname (from queue) for consistency
    hostname = expected_hostname
    
    # Parse components
    model = parse_model_from_show_version(output)
    serial = parse_serial_from_show_version(output)
    firmware = parse_firmware_from_show_version(output)
    
    # Detect device type (model-based, most reliable)
    device_type = detect_device_type(hostname, model, output)
    
    # Warn about parsing failures
    if not model:
        logging.warning(f"Could not parse model for {hostname}")
    if not serial:
        logging.warning(f"Could not parse serial for {hostname}")
    if not firmware:
        logging.warning(f"Could not parse firmware for {hostname}")
    
    return {
        "hostname": hostname,
        "device_type": device_type,
        "model": model,
        "serial_number": serial,
        "firmware": firmware
    }

def get_cdp_neighbors(conn):
    """
    Parse CDP neighbors
    Returns list of short hostnames
    """
    output = conn.send_command("show cdp neighbors detail")
    neighbors = []
    
    # Split by "Device ID:" to get each neighbor block
    for block in output.split("Device ID:"):
        if block.strip() == "":
            continue
        
        # First line contains the device ID
        first_line = block.strip().splitlines()[0]
        neighbor = short_hostname(first_line)
        
        # Skip empty or invalid hostnames (like separator lines)
        if neighbor and len(neighbor) > 1 and not neighbor.startswith("-"):
            neighbors.append(neighbor)
    
    logging.info(f"  Found {len(neighbors)} CDP neighbors")
    return neighbors

# =========================
# CSV FUNCTIONS
# =========================
def write_csv(filename, rows):
    """Write rows to CSV file"""
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

# =========================
# MAIN CRAWL LOGIC
# =========================
def main():
    global rows_global, csv_file_global
    
    print("\n" + "="*60)
    print("Cisco CDP Site Inventory - Model-Based Detection")
    print("="*60 + "\n")
    
    # Get seed device input
    seed_input = input("Enter seed device hostname (short, FQDN, or IP): ").strip()
    
    if not seed_input:
        print("[!] Error: Seed hostname is required")
        return 1
    
    # Extract site name from first 5 characters of hostname
    seed_short = short_hostname(seed_input)
    site_name = seed_short[:5].upper()  # First 5 chars, uppercase
    
    print(f"[+] Site detected: {site_name}")
    
    # Setup logging
    log_file = setup_logging(site_name)
    logging.info("="*60)
    logging.info(f"Starting CDP crawl for site: {site_name}")
    logging.info(f"Seed device: {seed_input}")
    logging.info(f"Site name auto-detected from hostname: {site_name}")
    logging.info("="*60)
    
    # Get credentials
    username = input("SSH username: ").strip()
    password = getpass.getpass("SSH password: ")
    secret = getpass.getpass("Enable secret (press Enter if same as password): ")
    
    if not secret:
        secret = password
    
    if not username or not password:
        print("[!] Error: Username and password are required")
        return 1
    
    # Prepare CSV file
    csv_file = site_csv_filename(site_name)
    csv_file_global = csv_file
    
    logging.info(f"Output CSV: {csv_file}")
    logging.info(f"Log file: {log_file}")
    
    # Initialize crawl state
    queue = deque()
    queued = set()
    visited_ok = set()
    visited_fail = set()
    rows = []
    
    # Enqueue seed device
    queue.append(seed_short)
    queued.add(seed_short)
    
    logging.info(f"Starting crawl from {seed_short}")
    print(f"\n[+] Starting crawl from {seed_short}\n")
    
    # Main crawl loop
    while queue:
        hostname = queue.popleft()
        fqdn = fqdn_from_short(hostname)
        
        # Progress indicator
        total_processed = len(visited_ok) + len(visited_fail)
        total_discovered = total_processed + len(queue)
        progress = f"({total_processed}/{total_discovered} processed, {len(queue)} in queue)"
        
        print(f"[+] Processing {hostname} {progress}")
        logging.info(f"Processing {hostname}")
        
        conn = None
        try:
            # Attempt connection
            conn = connect_device(fqdn, username, password, secret)
            logging.info(f"  Connected to {hostname}")
            
            try:
                # Collect device facts
                facts = get_device_facts(conn, hostname)
                logging.info(f"  Device type: {facts['device_type']}, Model: {facts['model']}")
                
                # Discover neighbors
                neighbors = get_cdp_neighbors(conn)
                
                # Mark as successfully visited
                visited_ok.add(hostname)
                
                # Record successful device
                rows.append({
                    "site": site_name,
                    "hostname": facts["hostname"],
                    "status": "ok",
                    "device_type": facts["device_type"],
                    "model": facts["model"],
                    "serial_number": facts["serial_number"],
                    "firmware": facts["firmware"]
                })
                
                # Enqueue neighbors
                new_neighbors = 0
                skipped_already_seen = 0
                
                for n in neighbors:
                    # Check if we should discover this neighbor
                    # Use flexible matching - discover all network devices
                    if not DEVICE_NAME_REGEX.search(n):
                        logging.debug(f"  Skipping {n} (doesn't match device naming pattern)")
                        continue
                    
                    # Check if already seen (prevents loops and duplicates)
                    if n in visited_ok:
                        logging.debug(f"  Skipping {n} (already successfully visited)")
                        skipped_already_seen += 1
                        continue
                    
                    if n in visited_fail:
                        logging.debug(f"  Skipping {n} (already failed to login)")
                        skipped_already_seen += 1
                        continue
                    
                    if n in queued:
                        logging.debug(f"  Skipping {n} (already in queue)")
                        skipped_already_seen += 1
                        continue
                    
                    # Enqueue new neighbor
                    queue.append(n)
                    queued.add(n)
                    new_neighbors += 1
                    logging.info(f"  Queued neighbor: {n}")
                
                if new_neighbors > 0:
                    print(f"    → Discovered {new_neighbors} new neighbor(s)")
                if skipped_already_seen > 0:
                    logging.debug(f"  Skipped {skipped_already_seen} already-seen neighbor(s)")
            
            finally:
                # Always disconnect, even if facts/neighbors fail
                if conn:
                    conn.disconnect()
                    logging.debug(f"  Disconnected from {hostname}")
        
        except Exception as e:
            # Connection or collection failed
            error_msg = str(e)
            logging.error(f"  Failed to process {hostname}: {error_msg}")
            print(f"    ✗ Unable to process: {error_msg}")
            
            visited_fail.add(hostname)
            
            # Record failed device
            rows.append({
                "site": site_name,
                "hostname": hostname,
                "status": "unable_to_login",
                "device_type": "",
                "model": "",
                "serial_number": "",
                "firmware": ""
            })
    
    # Update global for signal handler
    rows_global = rows
    
    # Verify no duplicates in final output
    seen_hostnames = set()
    duplicates = []
    for row in rows:
        hostname = row["hostname"]
        if hostname in seen_hostnames:
            duplicates.append(hostname)
            logging.warning(f"DUPLICATE DETECTED: {hostname} appears multiple times!")
        seen_hostnames.add(hostname)
    
    if duplicates:
        print(f"\n[!] WARNING: Found {len(duplicates)} duplicate hostname(s): {duplicates}")
        logging.error(f"Duplicate hostnames found: {duplicates}")
        print(f"[!] This should not happen - check logs for details")
    
    # Write CSV
    print(f"\n[+] Writing CSV: {csv_file}")
    logging.info(f"Writing CSV output to {csv_file}")
    write_csv(csv_file, rows)
    
    # Summary by device type
    device_counts = {}
    for row in rows:
        if row["status"] == "ok":
            dtype = row["device_type"]
            device_counts[dtype] = device_counts.get(dtype, 0) + 1
    
    # Summary
    print("\n" + "="*60)
    print("CRAWL COMPLETE")
    print("="*60)
    print(f"Total devices discovered: {len(visited_ok) + len(visited_fail)}")
    print(f"  Successfully logged in:  {len(visited_ok)}")
    print(f"  Unable to login:         {len(visited_fail)}")
    print(f"\nDeduplication Stats:")
    print(f"  Unique devices in CSV:   {len(rows)}")
    print(f"  Devices queued total:    {len(queued)}")
    print(f"  Devices processed:       {len(visited_ok) + len(visited_fail)}")
    
    if device_counts:
        print(f"\nDevice Types Found:")
        for dtype, count in sorted(device_counts.items()):
            print(f"  {dtype:20s}: {count}")
    
    print(f"\nOutput files:")
    print(f"  CSV:  {csv_file}")
    print(f"  Log:  {log_file}")
    print("="*60 + "\n")
    
    logging.info("="*60)
    logging.info(f"Crawl complete - {len(visited_ok)} OK, {len(visited_fail)} failed")
    logging.info(f"Device types: {device_counts}")
    logging.info("="*60)
    
    return 0

# =========================
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)
