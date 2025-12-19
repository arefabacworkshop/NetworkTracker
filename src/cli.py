"""
Network Connection Monitor - Command Line Interface
"""

import psutil
import socket
import argparse
import time
import sys
from datetime import datetime

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def resolve_hostname(ip, cache):
    """
    Resolves an IP address to a hostname using multiple DNS sources.
    """
    if ip in cache:
        return cache[ip]

    # Method 1: System DNS
    try:
        host_info = socket.gethostbyaddr(ip)
        hostname = host_info[0]
        cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        pass
    except Exception:
        pass

    # Method 2: Public DNS servers
    if DNS_AVAILABLE:
        dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        try:
            rev_name = dns.reversename.from_address(ip)
            for dns_server in dns_servers:
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 1.0
                    resolver.lifetime = 1.5
                    answers = resolver.resolve(rev_name, 'PTR')
                    if answers:
                        hostname = str(answers[0]).rstrip('.')
                        cache[ip] = hostname
                        return hostname
                except Exception:
                    continue
        except Exception:
            pass

    cache[ip] = None
    return None


def get_connections_for_pid(pid):
    """Retrieves active TCP/UDP connections for the given PID."""
    try:
        process = psutil.Process(pid)
        connections = process.connections(kind='inet')
        return connections
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return "ACCESS_DENIED"
    except Exception:
        return None


def find_pids_by_name(process_name):
    """Finds all PIDs associated with a given process name."""
    found_pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                found_pids.append(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return found_pids


def monitor_processes(pids, target_name, interval=1.0):
    """Continuously monitors the list of PIDs for new connections."""
    print(f"[*] Starting monitor for: {target_name}")
    print(f"[*] Monitoring PIDs: {pids}")
    print(f"[*] Press Ctrl+C to stop...")
    print("-" * 80)
    print(f"{'TIME':<10} | {'PID':<6} | {'HOSTNAME':<30} | {'REMOTE IP':<15} | {'STATUS'}")
    print("-" * 80)

    printed_hostnames = set()
    dns_cache = {}
    
    active_pids = set(pids)
    denied_pids = set()

    try:
        while active_pids:
            current_pids = list(active_pids)
            
            for pid in current_pids:
                connections = get_connections_for_pid(pid)
                
                if connections == "ACCESS_DENIED":
                    if pid not in denied_pids:
                        print(f"[!] Access denied to PID {pid}. Run as Administrator.")
                        denied_pids.add(pid)
                        active_pids.discard(pid)
                    continue
                
                if connections is None:
                    active_pids.discard(pid)
                    continue

                for conn in connections:
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        
                        if remote_ip in ["0.0.0.0", "::", "127.0.0.1", "::1"]:
                            continue
                        
                        if remote_ip.startswith("::ffff:"):
                            remote_ip = remote_ip[7:]

                        hostname = resolve_hostname(remote_ip, dns_cache)

                        if hostname:
                            if hostname not in printed_hostnames:
                                timestamp = datetime.now().strftime("%H:%M:%S")
                                print(f"{timestamp:<10} | {pid:<6} | {hostname:<30} | {remote_ip:<15} | {conn.status}")
                                printed_hostnames.add(hostname)
            
            if not active_pids:
                print("[*] All monitored processes have ended.")
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor network connections for a specific Windows process.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py chrome.exe
  python cli.py 1234
  python cli.py discord.exe --interval 1.0
        """
    )
    parser.add_argument("target", help="The Process ID (PID) or Process Name (e.g., Discord.exe) to monitor.")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds (default: 2.0)")
    
    args = parser.parse_args()

    target = args.target
    pids = []

    if target.isdigit():
        pids.append(int(target))
        target_display = f"PID {target}"
    else:
        print(f"[*] Searching for processes named '{target}'...")
        pids = find_pids_by_name(target)
        target_display = f"Process '{target}'"
        
        if not pids:
            print(f"[!] No active processes found with name: {target}")
            sys.exit(1)

    monitor_processes(pids, target_display, args.interval)


if __name__ == "__main__":
    main()
