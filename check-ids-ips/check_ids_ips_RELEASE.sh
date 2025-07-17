#!/bin/bash
#
# check_ids_ips.sh — IDS/IPS and firewall checker for Linux systems
#
# This script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This script is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# Made by k2xploit
# Official github repo: https://github.com/k2xploit/linux-tools-and-ttps/tree/main/check-ids-ips

echo "Checking for IDS/IPS configurations on the system..."

# Function to check if a service is running
check_service() {
    local service=$1
    if command -v systemctl &> /dev/null; then
        echo "Checking service with systemctl: $service"
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running"
    elif command -v service &> /dev/null; then
        echo "Checking service with service: $service"
        service $service status &> /dev/null && echo "$service is running" || echo "$service is not running"
    else
        echo "Neither systemctl nor service command is available. Unable to check service status for $service."
    fi
}

# UFW is a simplified firewall management tool that provides an easy-to-use interface for configuring firewall rules in Linux.
check_ufw() {
    # Check if UFW is installed
    if command -v ufw > /dev/null; then
        echo "UFW is installed."

        # Check if UFW is active
        if ufw status | grep -q "Status: active"; then
            echo "UFW is active."

            # Show UFW status and rules
            ufw status verbose
        else
            echo "UFW is not active."
        fi
    else
        echo "UFW is not installed."
    fi
}

# Snort is an open-source network intrusion detection system (NIDS) capable of real-time traffic analysis and packet logging.
check_snort() {
    # Check if Snort is installed
    if command -v snort > /dev/null; then
        echo "Snort is installed."

        # Check if Snort service is running
        if pgrep snort > /dev/null; then
            echo "Snort service is running."

            # Display Snort version and configuration file path
            snort -V

            # List active network interfaces Snort is monitoring
            echo "Active network interfaces for Snort:"
            snort --daq-list
        else
            echo "Snort service is not running."
        fi
    else
        echo "Snort is not installed."
    fi
}

# Function to check if Fail2Ban is running
# Fail2Ban is an intrusion prevention software framework that protects servers from brute-force attacks by monitoring log files and banning IPs based on patterns.
check_fail2ban() {
    # Check if Fail2Ban is installed
    if command -v fail2ban-client > /dev/null; then
        echo "Fail2Ban is installed."

        # Check if Fail2Ban service is running
        if systemctl is-active --quiet fail2ban; then
            echo "Fail2Ban service is running."

            # Get the status of Fail2Ban and list active jails (protection rules)
            fail2ban-client status
        else
            echo "Fail2Ban service is not running."
        fi
    else
        echo "Fail2Ban is not installed."
    fi
}

# Function to check for AppArmor status and profiles
check_apparmor() {
    echo "Checking for AppArmor status and profiles..."

    # 1. Check if AppArmor is installed
    if command -v apparmor_status >/dev/null 2>&1; then
    # aa-status
        echo "AppArmor is installed."

        # 2. Check AppArmor status
        apparmor_status_output=$(sudo apparmor_status)
        echo "AppArmor status:"
        echo "$apparmor_status_output"

        # 3. List active profiles
        echo "Listing active AppArmor profiles..."
        sudo apparmor_status | grep "profiles are in enforce mode"
        sudo apparmor_status | grep "profiles are in complain mode"

		# config files in /etc/apparmor.d/
    else
        echo "AppArmor is NOT installed on this system."
    fi

    echo ""
}

# Function to check for iptables rules and status
check_iptables() {
    echo "Checking for iptables rules and status..."

    # 1. Check if iptables is installed
    if command -v iptables >/dev/null 2>&1; then
        echo "iptables is installed."

        # 2. Check if iptables rules are active
        if sudo iptables -L | grep -q "Chain"; then
            echo "iptables rules are currently active. Here are the active rules:"
            sudo iptables -L
            #sudo nft list ruleset
        else
            echo "No active iptables rules found."
        fi

        # 3. Check iptables rules for NAT table
        echo "Checking NAT table rules..."
        sudo iptables -t nat -L
    else
        echo "iptables is NOT installed on this system."
    fi

    echo ""
}


# ------------------------------------------------------------------------------
# Function: check_exec_shield
# Description:
#   This function checks for the legacy Exec Shield mechanism, which was used
#   in older Linux distros (like CentOS 6) to enforce memory protection (e.g.,
#   non-executable stack).
#
#   It includes checks for kernel parameters like `noexec=on`, which enforces
#   NX (No Execute) protections on memory pages.
#
#   The "noexec" kernel boot parameter can enforce a policy where memory regions
#   such as the stack cannot be executed, helping prevent certain exploit classes.
# ------------------------------------------------------------------------------
check_exec_shield() {
    echo "Checking for Exec Shield..."

    # 1. Check if the system is using a kernel that supports Exec Shield
    if grep -q "Exec Shield" /proc/cpuinfo 2>/dev/null; then
        echo "Exec Shield is supported by the CPU (detected in /proc/cpuinfo)"
    else
        echo "Exec Shield not detected in /proc/cpuinfo. Continuing check..."
    fi

    # 2. Check for sysctl settings related to Exec Shield
    if sysctl -a 2>/dev/null | grep -q "kernel.exec-shield"; then
        exec_shield_status=$(sysctl kernel.exec-shield 2>/dev/null)
        echo "Exec Shield is present in sysctl configuration:"
        echo "$exec_shield_status"
    else
        echo "Exec Shield sysctl setting not found. Checking other configurations..."
    fi

    # 3. Check if /proc/sys/kernel/exec-shield exists (alternative older method)
    if [ -f /proc/sys/kernel/exec-shield ]; then
        exec_shield_enabled=$(cat /proc/sys/kernel/exec-shield)
        echo "Exec Shield is enabled via /proc/sys/kernel/exec-shield: $exec_shield_enabled"
    else
        echo "Exec Shield setting not found in /proc/sys/kernel/exec-shield"
    fi

    # 4. Check for boot-time kernel parameters related to Exec Shield
    boot_params=$(cat /proc/cmdline 2>/dev/null)
    if echo "$boot_params" | grep -q "noexec=on"; then
        echo "Exec Shield might be enforced with 'noexec=on' kernel boot parameter."
    else
        echo "No 'noexec' kernel boot parameter found."
    fi

    # 5. Check dmesg for any Exec Shield related logs
    if dmesg | grep -q "ExecShield"; then
        echo "Exec Shield related logs found in dmesg:"
        dmesg | grep "ExecShield"
    else
        echo "No Exec Shield related logs found in dmesg."
    fi
}

# ------------------------------------------------------------------------------
# Function: check_nx
# Description:
#   Checks for NX (No eXecute) CPU and kernel support.
#
#   NX (also known as XD by Intel) is a hardware-based mitigation that prevents
#   execution of code from certain regions of memory (e.g., stack, heap).
#
#   This function detects whether NX is supported by the CPU, enabled in kernel
#   boot parameters, and actively enforced via dmesg logs.
#
#   The kernel parameter `noexec=off` disables NX; its absence usually means
#   NX is enabled.
# ------------------------------------------------------------------------------
check_nx() {
    echo "Checking for NX (No Execute) support..."

    # 1. Check if NX is supported by the CPU
    if grep -q 'nx' /proc/cpuinfo; then
        echo "NX is supported by the CPU."
    else
        echo "NX is NOT supported by the CPU."
    fi

    # 2. Check kernel boot parameters for disabling NX
    boot_params=$(cat /proc/cmdline 2>/dev/null)
    if echo "$boot_params" | grep -q "noexec=off"; then
        echo "NX is disabled via kernel boot parameter (noexec=off)."
    else
        echo "NX is enabled (no 'noexec=off' found in boot parameters)."
    fi

    # 3. Check dmesg logs for NX status
    if dmesg | grep -q "NX (Execute Disable) protection"; then
        echo "NX status found in dmesg logs:"
        dmesg | grep "NX (Execute Disable) protection"
    else
        echo "No NX related logs found in dmesg."
    fi

    echo ""
}

# ------------------------------------------------------------------------------
# Function: check_noexec_mounts
# Description:
#   Looks for mount points that have the 'noexec' flag set. This prevents
#   execution of binaries from those directories — often used on /tmp, /home,
#   /var to prevent script execution by attackers.
# ------------------------------------------------------------------------------
check_noexec_mounts() {
    echo "Checking for 'noexec' mount options on file systems..."

    mount | grep 'noexec' && echo "Found mount(s) with 'noexec' flag:" || echo "No mount points found with 'noexec'."

    echo ""
}

# Function to check for PaX (a kernel patch for security hardening)
check_pax() {
    echo "Checking for PaX protection..."

    # 1. Check if PaX is supported (on grsecurity-enabled kernels)
    if sysctl -a 2>/dev/null | grep -q "pax."; then
        echo "PaX is supported and sysctl configuration is present."
        sysctl -a 2>/dev/null | grep "pax."
    else
        echo "PaX is NOT found in sysctl configuration. Likely not supported on this kernel."
    fi

    # 2. Check if PaX is present in the kernel configuration (if the config is available)
    if [ -f /boot/config-$(uname -r) ]; then
        if grep -q "CONFIG_PAX" /boot/config-$(uname -r); then
            echo "PaX is enabled in the kernel configuration:"
            grep "CONFIG_PAX" /boot/config-$(uname -r)
        else
            echo "PaX is NOT enabled in the kernel configuration."
        fi
    else
        echo "Kernel configuration file not found, cannot check for PaX."
    fi

    echo ""
}

# ------------------------------------------------------------------------------
# Function: check_selinux
# Description:
#   Checks if SELinux is installed and its current enforcement mode.
#   SELinux (Security-Enhanced Linux) can enforce strict policies that prevent
#   execution or modification of files — even by root — depending on context.
# ------------------------------------------------------------------------------
check_selinux() {
    echo "Checking for SELinux status..."

    if command -v getenforce > /dev/null; then
        selinux_status=$(getenforce)
        echo "SELinux mode: $selinux_status"
    elif command -v sestatus &> /dev/null; then
        selinux_status=$(sestatus 2>/dev/null)
        echo "SELinux status found using sestatus:"
        echo "$selinux_status"
    elif [ -f /etc/selinux/config ]; then
        echo "SELinux configuration file found:"
        cat /etc/selinux/config | grep -E "^SELINUX="
    else
        echo "SELinux not installed or getenforce command not available."
    fi

    echo ""
}


# ------------------------------------------------------------------------------
# Function: check_nosuid
# Description:
#   Checks mounted filesystems for the 'nosuid' flag, which disables SUID/SGID
#   binaries on the mount point. This helps mitigate privilege escalation via
#   setuid-root binaries placed on external or less-trusted mounts.
#
#   Useful to detect if /tmp, /home, /mnt or other mounts are hardened.
# ------------------------------------------------------------------------------
check_nosuid() {
    echo "Checking for mount points with 'nosuid'..."

    mount | grep 'nosuid' && echo "Found mount(s) with 'nosuid' flag:" || echo "No mount points found with 'nosuid'."

    echo ""
}

# ------------------------------------------------------------------------------
# Function: check_restrictive_permissions
# Description:
#   Checks for potentially restrictive permissions on sensitive directories like
#   /tmp, /var/spool/cron, /etc/cron*, etc. using ls -ld.
# ------------------------------------------------------------------------------
check_restrictive_permissions() {
    echo "Checking for restrictive permissions on key directories..."

    for dir in /tmp /var/tmp /var/spool/cron /etc/cron*; do
        if [ -e "$dir" ]; then
            echo -n "$dir: "
            ls -ld "$dir"
        fi
    done

    echo ""
}

# ------------------------------------------------------------------------------
# Function: check_chattr_immutable
# Description:
#   Checks if any files or directories have the immutable flag (i) set via chattr.
#   This can prevent modifications, deletions, or writing — even by root.
# ------------------------------------------------------------------------------
check_chattr_immutable() {
    echo "Checking for immutable files (chattr +i)..."

    for path in /etc/cron* /var/spool/cron /tmp; do
        if [ -e "$path" ]; then
            echo "Checking $path..."
            lsattr -d "$path" 2>/dev/null | grep '\-i\-'
            find "$path" -xdev -type f -exec lsattr {} + 2>/dev/null | grep '\-i\-'
        fi
    done

    echo ""
}

# ------------------------------------------------------------------------------
# Function: check_clamav
# Description:
#   ClamAV (Clam AntiVirus) is an open-source antivirus engine for detecting
#   trojans, viruses, malware, and other malicious threats — primarily on Linux.
#
#   It is commonly installed on mail servers, web hosting environments,
#   and file servers where antivirus scanning is needed.
#
#   This function checks whether ClamAV is installed and if its services
#   (`clamd` or `clamav-daemon`) are currently running.
#
#   # If needed, these actions could be performed manually to stop ClamAV:
#   #   ps aux | grep clamav
#   #   pkill -f clamav
#   #   systemctl stop clamav
# ------------------------------------------------------------------------------
check_clamav() {
    echo "Checking for ClamAV presence..."

    if command -v clamscan > /dev/null || command -v freshclam > /dev/null; then
        echo "ClamAV appears to be installed."

        # Check for active ClamAV services
        if pgrep -f clamd > /dev/null || pgrep -f clamav > /dev/null; then
            echo "ClamAV service is running."
        else
            echo "ClamAV service is not running."
        fi
    else
        echo "ClamAV is not installed on this system."
    fi

    echo ""
}

# Check for common IDS/IPS services
services=("snort" "suricata" "ossec")
for service in "${services[@]}"; do
    check_service $service
done

echo

# Check for installed packages related to IDS/IPS
echo "Checking for installed IDS/IPS packages..."
if command -v dpkg &> /dev/null; then
    dpkg -l | grep -E 'snort|suricata|ossec'
elif command -v rpm &> /dev/null; then
    rpm -qa | grep -E 'snort|suricata|ossec'
else
    echo "Package manager not found (dpkg or rpm). Unable to check installed packages."
fi

echo

# Listing currently installed SELinux modules to see if snort, suricata or
# ossec is installed
echo "Checking for SELinux policy module installed and loaded for IDS/IPS..."
if command -v semodule >/dev/null 2>&1; then
	semodule -l | grep snort
	semodule -l | grep ossec
	semodule -l | grep suricata 
else
	echo "Command semodule not found."
fi

echo

# Check for network traffic analysis tools
echo "Checking for network traffic analysis tools..."
for tool in "wireshark" "tcpdump"; do
    if command -v $tool &> /dev/null; then
        echo "$tool is installed"
    else
        echo "$tool is not installed"
    fi
done

echo

# Check system logs for IDS/IPS related logs
echo "Checking system logs for IDS/IPS related logs..."
log_dirs=("/var/log/snort" "/var/log/suricata" "/var/log/ossec")
for log_dir in "${log_dirs[@]}"; do
    if [ -d "$log_dir" ]; then
        echo "Logs found in $log_dir:"
        ls -l $log_dir
    else
        echo "No logs found in $log_dir"
    fi
done

echo

# Check for running processes related to IDS/IPS
echo "Checking for running processes related to IDS/IPS..."
ps aux | grep -E 'snort|suricata|ossec'

echo

# Check for kernel modules related to network monitoring
echo "Checking for kernel modules related to network monitoring..."
lsmod | grep -E 'af_packet|ipt_LOG|ipt_REJECT|nf_conntrack|nf_log|xt_REJECT'

echo

# Check for configuration files related to IDS/IPS
echo "Checking for IDS/IPS configuration files..."
find /etc -type f -name '*snort*'
find /etc -type f -name '*suricata*'
find /etc -type f -name '*ossec*'


echo "Security Feature Checks"
echo "-----------------------------------------"
check_ufw
check_snort
check_fail2ban
check_apparmor
check_iptables
check_nx
check_pax
check_selinux
check_nosuid
check_noexec_mounts
check_exec_shield
check_nx
check_restrictive_permissions
check_chattr_immutable
check_clamav
echo "-----------------------------------------"
echo "Security checks completed."


echo
echo "IDS/IPS checks completed."
