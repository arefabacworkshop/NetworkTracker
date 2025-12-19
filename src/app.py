"""
Network Connection Monitor - Main Application
"""

import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import socket
import threading
import time
from datetime import datetime

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Connection Monitor")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Variables
        self.is_running = False
        self.monitor_thread = None
        self.printed_hostnames = set()
        self.printed_ips = set()
        self.dns_cache = {}
        self.target_name = ""  # Store target for refreshing PIDs
        
        # UI Components
        self.create_widgets()
        
        # Handle window close properly
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def on_closing(self):
        """Handle window close - stop monitoring thread first"""
        if self.is_running:
            self.is_running = False
            # Give thread a moment to stop gracefully
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=0.5)
        self.root.destroy()

    def create_widgets(self):
        # --- Input Frame ---
        input_frame = ttk.Frame(self.root, padding="10")
        input_frame.pack(fill=tk.X)
        
        ttk.Label(input_frame, text="Target (PID or Process Name):").pack(side=tk.LEFT, padx=5)
        
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "chrome.exe")
        
        self.start_btn = ttk.Button(input_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(input_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Right side buttons frame
        right_btn_frame = ttk.Frame(input_frame)
        right_btn_frame.pack(side=tk.RIGHT)
        
        self.clear_btn = ttk.Button(right_btn_frame, text="Clear Logs", command=self.clear_logs)
        self.clear_btn.pack(side=tk.RIGHT, padx=2)
        
        self.copy_ips_btn = ttk.Button(right_btn_frame, text="Copy IPs", command=self.copy_all_ips)
        self.copy_ips_btn.pack(side=tk.RIGHT, padx=2)
        
        self.copy_hosts_btn = ttk.Button(right_btn_frame, text="Copy Hostnames", command=self.copy_all_hostnames)
        self.copy_hosts_btn.pack(side=tk.RIGHT, padx=2)

        # --- Status Bar ---
        self.status_var = tk.StringVar()
        self.status_var.set("Ready. (Note: Run as Administrator to see all connections)")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # --- Treeview (Table) for results ---
        # Frame for Treeview and Scrollbar
        tree_frame = ttk.Frame(self.root, padding="10")
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("time", "pid", "hostname", "remote_ip", "status")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        # Define Headings
        self.tree.heading("time", text="Time")
        self.tree.heading("pid", text="PID")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("remote_ip", text="Remote IP")
        self.tree.heading("status", text="Status")
        
        # Define Columns
        self.tree.column("time", width=100, anchor=tk.CENTER)
        self.tree.column("pid", width=80, anchor=tk.CENTER)
        self.tree.column("hostname", width=350, anchor=tk.W)
        self.tree.column("remote_ip", width=150, anchor=tk.W)
        self.tree.column("status", width=100, anchor=tk.CENTER)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create right-click context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy Hostname", command=self.copy_selected_hostname)
        self.context_menu.add_command(label="Copy Remote IP", command=self.copy_selected_ip)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Row", command=self.copy_selected_row)
        
        # Bind right-click to treeview
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        """Show context menu on right-click"""
        # Select the item under cursor
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_selected_hostname(self):
        """Copy the hostname of the selected row to clipboard"""
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0], 'values')
            if values and len(values) >= 3:
                hostname = values[2]  # hostname is 3rd column
                self.root.clipboard_clear()
                self.root.clipboard_append(hostname)
                self.status_var.set(f"Copied hostname: {hostname}")
    
    def copy_selected_ip(self):
        """Copy the remote IP of the selected row to clipboard"""
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0], 'values')
            if values and len(values) >= 4:
                ip = values[3]  # remote_ip is 4th column
                self.root.clipboard_clear()
                self.root.clipboard_append(ip)
                self.status_var.set(f"Copied IP: {ip}")
    
    def copy_selected_row(self):
        """Copy the entire selected row to clipboard"""
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0], 'values')
            if values:
                row_text = "\t".join(str(v) for v in values)
                self.root.clipboard_clear()
                self.root.clipboard_append(row_text)
                self.status_var.set("Copied row to clipboard")
    
    def copy_all_hostnames(self):
        """Copy all hostnames from the table to clipboard"""
        hostnames = []
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if values and len(values) >= 3:
                hostname = values[2]
                if hostname and hostname != "N/A":
                    hostnames.append(hostname)
        
        if hostnames:
            # Remove duplicates while preserving order
            seen = set()
            unique_hostnames = []
            for h in hostnames:
                if h not in seen:
                    seen.add(h)
                    unique_hostnames.append(h)
            
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(unique_hostnames))
            self.status_var.set(f"Copied {len(unique_hostnames)} hostnames to clipboard")
        else:
            self.status_var.set("No hostnames to copy")
    
    def copy_all_ips(self):
        """Copy all remote IPs from the table to clipboard"""
        ips = []
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if values and len(values) >= 4:
                ip = values[3]
                if ip:
                    ips.append(ip)
        
        if ips:
            # Remove duplicates while preserving order
            seen = set()
            unique_ips = []
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    unique_ips.append(ip)
            
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(unique_ips))
            self.status_var.set(f"Copied {len(unique_ips)} IPs to clipboard")
        else:
            self.status_var.set("No IPs to copy")

    def resolve_hostname(self, ip):
        """Resolve hostname using multiple DNS sources before giving up."""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        hostname = None
        
        # Method 1: Standard system DNS (socket.gethostbyaddr)
        hostname = self._resolve_via_socket(ip)
        if hostname:
            self.dns_cache[ip] = hostname
            return hostname
        
        # Method 2: Try multiple public DNS servers using dnspython
        if DNS_AVAILABLE:
            hostname = self._resolve_via_dns_servers(ip)
            if hostname:
                self.dns_cache[ip] = hostname
                return hostname
        
        # All methods failed - cache as None so we don't retry constantly
        self.dns_cache[ip] = None
        return None
    
    def _resolve_via_socket(self, ip):
        """Try resolving hostname using system's default DNS."""
        try:
            host_info = socket.gethostbyaddr(ip)
            return host_info[0]
        except (socket.herror, socket.gaierror, socket.timeout):
            return None
        except Exception:
            return None
    
    def _resolve_via_dns_servers(self, ip):
        """Try resolving hostname using multiple public DNS servers."""
        # List of reliable public DNS servers
        dns_servers = [
            '8.8.8.8',        # Google Primary
            '8.8.4.4',        # Google Secondary
            '1.1.1.1',        # Cloudflare Primary
            '1.0.0.1',        # Cloudflare Secondary
            '9.9.9.9',        # Quad9 Primary
            '208.67.222.222', # OpenDNS Primary
        ]
        
        try:
            # Convert IP to reverse DNS format (PTR record query)
            rev_name = dns.reversename.from_address(ip)
            
            for dns_server in dns_servers:
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 1.0  # 1 second timeout per server
                    resolver.lifetime = 1.5  # Total query lifetime
                    
                    answers = resolver.resolve(rev_name, 'PTR')
                    if answers:
                        # Get the first answer and strip trailing dot
                        hostname = str(answers[0]).rstrip('.')
                        return hostname
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        
        return None

    def find_pids(self, target):
        pids = []
        if target.isdigit():
            pids.append(int(target))
        else:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() == target.lower():
                        pids.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        return pids

    def start_monitoring(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a PID or Process Name")
            return

        pids = self.find_pids(target)
        if not pids:
            messagebox.showerror("Error", f"No active processes found for: {target}")
            return

        # Store target name for potential PID refresh
        self.target_name = target

        # Clear deduplication sets for the new session so existing connections are shown again
        self.printed_hostnames.clear()
        self.printed_ips.clear()

        self.is_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.target_entry.config(state=tk.DISABLED)
        
        self.status_var.set(f"Monitoring {len(pids)} process(es) for '{target}'...")
        
        # Start the monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop, args=(pids,), daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.is_running = False
        self.status_var.set("Stopping...")
        # The thread will exit its loop when it sees is_running is False

    def clear_logs(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.printed_hostnames.clear()
        self.printed_ips.clear()

    def monitor_loop(self, initial_pids):
        active_pids = set(initial_pids)
        denied_pids = set()
        refresh_counter = 0
        
        while self.is_running and active_pids:
            # Refresh PIDs periodically if monitoring by process name (every 10 iterations)
            refresh_counter += 1
            if refresh_counter >= 10 and self.target_name and not self.target_name.isdigit():
                new_pids = self.find_pids(self.target_name)
                for pid in new_pids:
                    if pid not in active_pids and pid not in denied_pids:
                        active_pids.add(pid)
                refresh_counter = 0
            
            # Work on a copy to allow modification of the set during iteration
            current_pids = list(active_pids)
            
            for pid in current_pids:
                if not self.is_running: 
                    break
                
                try:
                    proc = psutil.Process(pid)
                    connections = proc.connections(kind='inet')
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    # Process has died
                    active_pids.discard(pid)
                    continue
                except psutil.AccessDenied:
                    if pid not in denied_pids:
                        # Notify user once per PID - capture pid value properly
                        denied_pid = pid  # Capture the value
                        self.root.after(0, lambda p=denied_pid: messagebox.showwarning("Access Denied", f"Access denied to PID {p}. Run as Admin."))
                        denied_pids.add(pid)
                        active_pids.discard(pid)
                    continue
                except Exception:
                    # Handle any other unexpected errors gracefully
                    continue

                for conn in connections:
                    if not self.is_running:
                        break
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        
                        # Filter out local loopbacks, empty addresses, and IPv6 mapped addresses
                        if remote_ip in ["0.0.0.0", "::", "127.0.0.1", "::1"]:
                            continue
                        # Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
                        if remote_ip.startswith("::ffff:"):
                            remote_ip = remote_ip[7:]  # Strip the prefix
                        
                        hostname = self.resolve_hostname(remote_ip)
                        
                        # Logic to determine if we should print this connection
                        should_print = False
                        
                        if hostname:
                            if hostname not in self.printed_hostnames:
                                should_print = True
                                self.printed_hostnames.add(hostname)
                        else:
                            # If no hostname, check if we've seen this IP
                            if remote_ip not in self.printed_ips:
                                should_print = True
                                self.printed_ips.add(remote_ip)
                        
                        if should_print:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            display_hostname = hostname if hostname else "N/A"
                            # Update UI in main thread
                            self.root.after(0, self.add_log, timestamp, pid, display_hostname, remote_ip, conn.status)
            
            # Sleep to prevent high CPU usage
            time.sleep(1.5)
        
        # When loop finishes (either stopped or all processes died)
        if self.is_running:
            # If we are still "running" but loop exited, it means all processes died
            self.root.after(0, self.monitoring_finished_all_died)
        else:
            self.root.after(0, self.monitoring_finished_user_stop)

    def add_log(self, timestamp, pid, hostname, remote_ip, status):
        # Insert at the top (index 0)
        self.tree.insert("", 0, values=(timestamp, pid, hostname, remote_ip, status))

    def monitoring_finished_all_died(self):
        self.is_running = False
        self.reset_ui_state()
        self.status_var.set("All monitored processes have ended.")
        messagebox.showinfo("Info", "All monitored processes have ended.")

    def monitoring_finished_user_stop(self):
        self.reset_ui_state()
        self.status_var.set("Monitoring stopped by user.")

    def reset_ui_state(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.target_entry.config(state=tk.NORMAL)
        self.target_name = ""  # Clear target name


def main():
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
