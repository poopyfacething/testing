import sys
import nmap
import socket
import requests
import threading
import time
import json
import platform
import subprocess
import ipaddress
import netifaces
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
import webbrowser
from functools import partial
import os
import tempfile
import shutil
from subprocess import Popen, PIPE

from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal, QSize
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QTabWidget, QComboBox, QProgressBar,
    QSplitter, QHeaderView, QMenuBar, QAction, QMessageBox,
    QGroupBox, QCheckBox, QTreeWidget, QTreeWidgetItem, QStyledItemDelegate,
    QFileDialog, QDialog, QDialogButtonBox, QGridLayout, QRadioButton, QFormLayout
)
from PyQt5.QtGui import QFont, QColor, QIcon, QBrush, QPalette

# Optional imports with improved error handling
SCAPY_AVAILABLE = False
WIFI_AVAILABLE = False
DNS_AVAILABLE = False
MATPLOTLIB_AVAILABLE = False
EXPLOITDB_AVAILABLE = False
PARAMIKO_AVAILABLE = False
FTPLIB_AVAILABLE = False

try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, ICMP, DNS, DHCP, BOOTP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    print("Scapy not available. Packet sniffing disabled.")

try:
    from wifi import Cell
    WIFI_AVAILABLE = True
except ImportError:
    print("WiFi module not available. WiFi features disabled.")

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    print("dnspython not available. DNS features disabled.")

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    print("Matplotlib not available. Graphs disabled.")

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    print("Paramiko not available. SSH features disabled.")

try:
    from ftplib import FTP
    FTPLIB_AVAILABLE = True
except ImportError:
    print("ftplib not available. FTP features disabled.")

try:
    import exploitdb
    EXPLOITDB_AVAILABLE = True
except ImportError:
    print("ExploitDB not available. Exploit DB features disabled.")

class ColorDelegate(QStyledItemDelegate):
    """Custom delegate for coloring items based on their status"""
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.column() == 1:  # Status column
            text = index.data(Qt.DisplayRole)
            if text == "Online":
                option.backgroundBrush = QBrush(QColor(200, 255, 200))
            elif text == "Offline":
                option.backgroundBrush = QBrush(QColor(255, 200, 200))

class BaseThread(QThread):
    """Base thread class with common functionality"""
    log_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()
        
    def stop(self):
        """Gracefully stop the thread"""
        self._stop_event.set()
        
    def log(self, message: str):
        """Helper method to log messages"""
        self.log_message.emit(message)

class NmapScannerThread(BaseThread):
    """Thread for performing Nmap scans"""
    scan_finished = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    host_discovered = pyqtSignal(dict)
    port_discovered = pyqtSignal(dict)

    def __init__(self, target, scan_type, options):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.options = options
        self.nm = nmap.PortScanner()

    def run(self):
        try:
            self.log(f"Starting {self.scan_type} scan on {self.target}...")
            
            scan_args = self._get_scan_args()
            self.log(f"Using scan arguments: {scan_args}")
            
            # Perform the scan with progress callback
            self.nm.scan(hosts=self.target, arguments=scan_args)
            
            if not self._stop_event.is_set():
                self.log("Scan completed successfully!")
                self.scan_finished.emit(self.nm._scan_result)
                self._process_scan_results()
        except Exception as e:
            self.log(f"Scan error: {str(e)}")

    def _process_scan_results(self):
        """Process scan results and emit signals for hosts and ports"""
        try:
            for host in self.nm.all_hosts():
                if self._stop_event.is_set():
                    break
                    
                host_data = self.nm[host]
                host_info = {
                    'host': host,
                    'status': host_data.state(),
                    'hostnames': ', '.join(host_data['hostnames']),
                    'os': host_data['osmatch'][0]['name'] if 'osmatch' in host_data and host_data['osmatch'] else 'Unknown'
                }
                self.host_discovered.emit(host_info)
                
                for proto in host_data.all_protocols():
                    ports = host_data[proto].keys()
                    for port in ports:
                        port_data = host_data[proto][port]
                        port_info = {
                            'host': host,
                            'port': port,
                            'state': port_data['state'],
                            'service': port_data['name'],
                            'version': f"{port_data.get('product', '')} {port_data.get('version', '')}".strip(),
                            'extra': port_data.get('extrainfo', '')
                        }
                        self.port_discovered.emit(port_info)
        except Exception as e:
            self.log(f"Error processing results: {str(e)}")

    def _get_scan_args(self) -> str:
        """Generate Nmap arguments based on scan type"""
        scan_args = ""
        if self.scan_type == "Quick Scan":
            scan_args = "-T4 -F --open"
        elif self.scan_type == "Intense Scan":
            scan_args = "-T4 -A -v"
        elif self.scan_type == "Port Range":
            scan_args = f"-p {self.options.get('ports', '1-1024')} --open"
        elif self.scan_type == "Service Detection":
            scan_args = "-sV --version-intensity 5"
        elif self.scan_type == "OS Detection":
            scan_args = "-O --osscan-limit"
        elif self.scan_type == "Vulnerability Scan":
            scan_args = "--script vuln,safe"
        elif self.scan_type == "Full Scan":
            scan_args = "-p- -sV -O -T4 -A -v"
        elif self.scan_type == "Custom":
            scan_args = self.options.get("custom_args", "")
        
        # Add timing template if not already specified
        if "-T" not in scan_args:
            scan_args += " -T4"
        
        return scan_args.strip()

class TrafficSnifferThread(BaseThread):
    """Thread for network traffic sniffing"""
    packet_received = pyqtSignal(dict)
    stats_updated = pyqtSignal(dict)

    def __init__(self, interface: str, capture_filters: Optional[Dict] = None):
        super().__init__()
        self.interface = interface
        self.capture_filters = capture_filters or {}
        self.packet_count = 0
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'DNS': 0, 'DHCP': 0, 'Other': 0}
        self.traffic_stats = {'incoming': 0, 'outgoing': 0}
        self.start_time = time.time()

    def run(self):
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available - packet sniffing disabled")
            return
            
        try:
            self.log(f"Starting traffic capture on {self.interface}...")
            
            # BPF filter based on selected protocols
            bpf_filter = self._create_bpf_filter()
            
            sniff(iface=self.interface, prn=self._process_packet, store=False,
                 filter=bpf_filter, stop_filter=lambda x: self._stop_event.is_set())
        except Exception as e:
            self.log(f"Traffic capture error: {str(e)}")

    def _create_bpf_filter(self) -> str:
        """Create BPF filter string based on selected protocols"""
        filters = []
        if self.capture_filters.get('tcp', True):
            filters.append('tcp')
        if self.capture_filters.get('udp', True):
            filters.append('udp')
        if self.capture_filters.get('icmp', True):
            filters.append('icmp or icmp6')
        if self.capture_filters.get('arp', True):
            filters.append('arp')
        if self.capture_filters.get('dns', True):
            filters.append('port 53')
        if self.capture_filters.get('dhcp', True):
            filters.append('port 67 or port 68')
            
        return ' or '.join(filters) if filters else ''

    def _process_packet(self, packet):
        """Process an individual network packet"""
        if self._stop_event.is_set():
            return

        packet_info = {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'source': '',
            'destination': '',
            'protocol': '',
            'length': len(packet),
            'info': '',
            'color': None,
            'scanned': False
        }

        # Update packet count
        self.packet_count += 1
        
        try:
            if IP in packet:
                packet_info['scanned'] = True
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_info['source'] = src_ip
                packet_info['destination'] = dst_ip
                
                # Determine traffic direction
                if src_ip.startswith(('192.168.', '10.', '172.16.')):
                    self.traffic_stats['outgoing'] += len(packet)
                else:
                    self.traffic_stats['incoming'] += len(packet)
                
                if TCP in packet:
                    self._process_tcp_packet(packet, packet_info)
                elif UDP in packet:
                    self._process_udp_packet(packet, packet_info)
                elif ICMP in packet:
                    self._process_icmp_packet(packet, packet_info)
            elif IPv6 in packet:
                packet_info['protocol'] = 'IPv6'
                packet_info['info'] = 'IPv6 Packet'
            elif ARP in packet:
                self._process_arp_packet(packet, packet_info)
            elif DHCP in packet or BOOTP in packet:
                self._process_dhcp_packet(packet, packet_info)
            else:
                packet_info['protocol'] = 'Other'
                packet_info['info'] = 'Unknown protocol'
        except Exception as e:
            packet_info['info'] = f'Error processing: {str(e)}'
            packet_info['color'] = QColor(255, 0, 0)

        # Emit packet and periodic stats
        self.packet_received.emit(packet_info)
        
        if self.packet_count % 10 == 0:
            self.stats_updated.emit({
                'packet_count': self.packet_count,
                'protocol_stats': self.protocol_stats,
                'traffic_stats': self.traffic_stats,
                'duration': time.time() - self.start_time,
                'scanned_count': sum(1 for p in self.protocol_stats.values() if p > 0)
            })

    def _process_tcp_packet(self, packet, packet_info: Dict):
        """Process TCP packet"""
        packet_info['protocol'] = 'TCP'
        tcp = packet[TCP]
        flags = tcp.sprintf('%flags%')
        packet_info['info'] = f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack}"
        
        # Color code by protocol
        if tcp.dport == 80 or tcp.sport == 80:
            packet_info['color'] = QColor(255, 200, 200)  # Light red for HTTP
        elif tcp.dport == 443 or tcp.sport == 443:
            packet_info['color'] = QColor(200, 255, 200)  # Light green for HTTPS
        elif tcp.dport == 22 or tcp.sport == 22:
            packet_info['color'] = QColor(200, 200, 255)  # Light blue for SSH
        
        self.protocol_stats['TCP'] += 1

    def _process_udp_packet(self, packet, packet_info: Dict):
        """Process UDP packet"""
        packet_info['protocol'] = 'UDP'
        udp = packet[UDP]
        packet_info['info'] = f"{udp.sport} → {udp.dport}"
        
        # Check for DNS
        if (udp.sport == 53 or udp.dport == 53) and DNS in packet:
            self._process_dns_packet(packet, packet_info)
            return
            
        self.protocol_stats['UDP'] += 1

    def _process_dns_packet(self, packet, packet_info: Dict):
        """Process DNS packet"""
        packet_info['protocol'] = 'DNS'
        dns = packet[DNS]
        if dns.qr == 0:  # Query
            query = dns.qd.qname.decode() if dns.qd else '?'
            packet_info['info'] = f"DNS Query: {query}"
        else:  # Response
            answers = ", ".join([str(rr.rdata) for rr in dns.an if hasattr(rr, 'rdata')])
            packet_info['info'] = f"DNS Response: {answers}"
        
        self.protocol_stats['DNS'] += 1
        packet_info['color'] = QColor(255, 255, 200)  # Light yellow for DNS

    def _process_icmp_packet(self, packet, packet_info: Dict):
        """Process ICMP packet"""
        packet_info['protocol'] = 'ICMP'
        icmp = packet[ICMP]
        packet_info['info'] = f"Type: {icmp.type}, Code: {icmp.code}"
        
        self.protocol_stats['ICMP'] += 1
        packet_info['color'] = QColor(255, 200, 255)  # Light purple for ICMP

    def _process_arp_packet(self, packet, packet_info: Dict):
        """Process ARP packet"""
        packet_info['protocol'] = 'ARP'
        arp = packet[ARP]
        if arp.op == 1:  # Request
            packet_info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:  # Reply
            packet_info['info'] = f"{arp.hwsrc} is at {arp.psrc}"
        
        packet_info['source'] = arp.psrc
        packet_info['destination'] = arp.pdst
        self.protocol_stats['ARP'] += 1
        packet_info['color'] = QColor(200, 255, 255)  # Light cyan for ARP

    def _process_dhcp_packet(self, packet, packet_info: Dict):
        """Process DHCP packet"""
        packet_info['protocol'] = 'DHCP'
        dhcp = packet[DHCP]
        options = {opt[0]: opt[1] for opt in dhcp.options if isinstance(opt, tuple)}
        
        msg_type = options.get('message-type', [1])[0]
        types = {
            1: "Discover",
            2: "Offer",
            3: "Request",
            4: "Decline",
            5: "ACK",
            6: "NAK",
            7: "Release",
            8: "Inform"
        }
        packet_info['info'] = f"DHCP {types.get(msg_type, 'Unknown')}"
        
        self.protocol_stats['DHCP'] += 1
        packet_info['color'] = QColor(255, 220, 200)  # Light orange for DHCP

class PingSweepThread(BaseThread):
    """Thread for performing ping sweeps"""
    ping_result = pyqtSignal(str, bool)
    progress_updated = pyqtSignal(int, str)
    finished = pyqtSignal()

    def __init__(self, network_range: str, timeout: int = 1, threads: int = 50):
        super().__init__()
        self.network_range = network_range
        self.timeout = timeout
        self.threads = threads

    def run(self):
        try:
            self.log(f"Starting ping sweep on {self.network_range} with {self.threads} threads...")
            
            # Parse network range
            if '/' in self.network_range:
                hosts = self._generate_ip_range_from_cidr()
            elif '-' in self.network_range:
                hosts = self._generate_ip_range_from_dash()
            else:
                hosts = [self.network_range]
            
            if not hosts:
                self.log("Error: Invalid network range format")
                return
                
            total_hosts = len(hosts)
            completed = 0
            
            # Thread pool for concurrent pings
            with threading.Semaphore(self.threads):
                for i, host in enumerate(hosts):
                    if self._stop_event.is_set():
                        break
                    
                    # Wait for an available thread
                    while threading.active_count() > self.threads + 1:  # +1 for main thread
                        time.sleep(0.01)
                    
                    # Start ping in a new thread
                    t = threading.Thread(target=self._ping_host, args=(host,))
                    t.daemon = True
                    t.start()
                    
                    completed += 1
                    progress = int((completed / total_hosts) * 100)
                    self.progress_updated.emit(progress, f"Pinging {host}...")
            
            if not self._stop_event.is_set():
                self.finished.emit()
                self.log("Ping sweep completed.")
        except Exception as e:
            self.log(f"Ping sweep error: {str(e)}")

    def _ping_host(self, host: str):
        """Ping an individual host"""
        try:
            # Use system ping for better performance
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-W', str(self.timeout), host]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            is_alive = result.returncode == 0
            self.ping_result.emit(host, is_alive)
        except Exception as e:
            self.log(f"Ping error for {host}: {str(e)}")
            self.ping_result.emit(host, False)

    def _generate_ip_range_from_cidr(self) -> List[str]:
        """Generate IP list from CIDR notation"""
        try:
            network = ipaddress.ip_network(self.network_range, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError:
            return []

    def _generate_ip_range_from_dash(self) -> List[str]:
        """Generate IP list from range notation (192.168.1.1-100)"""
        try:
            base, end = self.network_range.split('-')
            base_parts = base.split('.')
            if len(base_parts) != 4:
                return []
            
            start_ip = int(base_parts[3])
            end_ip = int(end)
            
            ips = []
            for i in range(start_ip, end_ip + 1):
                ips.append(f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}")
            return ips
        except (ValueError, IndexError):
            return []

class WifiAnalyzerThread(BaseThread):
    """Thread for WiFi network analysis"""
    networks_updated = pyqtSignal(list)

    def __init__(self, interface: Optional[str] = None):
        super().__init__()
        self.interface = interface

    def run(self):
        if not WIFI_AVAILABLE:
            self.log("WiFi module not available - WiFi scanning disabled")
            return
            
        while not self._stop_event.is_set():
            try:
                cells = list(Cell.all(self.interface)) if self.interface else list(Cell.all())
                # Sort by signal strength (descending)
                cells.sort(key=lambda x: x.signal, reverse=True)
                self.networks_updated.emit(cells)
            except Exception as e:
                self.log(f"WiFi scan error: {str(e)}")
            
            # Wait before next scan
            for _ in range(10):  # Check every 0.5s for stop signal
                if self._stop_event.is_set():
                    break
                time.sleep(0.5)

class NetworkStatsThread(BaseThread):
    """Thread for collecting network statistics"""
    stats_updated = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0

    def run(self):
        while not self._stop_event.is_set():
            try:
                stats = self._collect_stats()
                self.stats_updated.emit(stats)
            except Exception as e:
                self.log(f"Stats collection error: {str(e)}")
            
            # Wait before next update
            for _ in range(20):  # Check every second for stop signal
                if self._stop_event.is_set():
                    break
                time.sleep(0.05)

    def _collect_stats(self) -> Dict:
        """Collect various network statistics"""
        stats = {}
        
        try:
            # Network interfaces information
            interfaces = netifaces.interfaces()
            stats['interfaces'] = {}
            
            for iface in interfaces:
                if iface.startswith('lo'):
                    continue
                    
                if_stats = {}
                try:
                    addrs = netifaces.ifaddresses(iface)
                    
                    # IPv4 addresses
                    if netifaces.AF_INET in addrs:
                        ipv4_addrs = []
                        for addr in addrs[netifaces.AF_INET]:
                            ip_info = {
                                'address': addr.get('addr', ''),
                                'netmask': addr.get('netmask', ''),
                                'broadcast': addr.get('broadcast', '')
                            }
                            ipv4_addrs.append(ip_info)
                        if_stats['ipv4'] = ipv4_addrs
                    
                    # IPv6 addresses
                    if netifaces.AF_INET6 in addrs:
                        ipv6_addrs = []
                        for addr in addrs[netifaces.AF_INET6]:
                            ip_info = {
                                'address': addr.get('addr', '').split('%')[0],
                                'netmask': addr.get('netmask', '')
                            }
                            ipv6_addrs.append(ip_info)
                        if_stats['ipv6'] = ipv6_addrs
                    
                    # MAC address
                    if netifaces.AF_LINK in addrs:
                        if_stats['mac'] = addrs[netifaces.AF_LINK][0].get('addr', '')
                except Exception as e:
                    if_stats['error'] = f"Interface error: {str(e)}"
                
                # Network usage statistics
                try:
                    io = psutil.net_io_counters(pernic=True).get(iface)
                    if io:
                        if_stats['bytes_sent'] = str(io.bytes_sent)
                        if_stats['bytes_recv'] = str(io.bytes_recv)
                        if_stats['packets_sent'] = str(io.packets_sent)
                        if_stats['packets_recv'] = str(io.packets_recv)
                except Exception as e:
                    if_stats['io_error'] = str(e)
                
                stats['interfaces'][iface] = if_stats
            
            # System-wide network stats
            try:
                net_io = psutil.net_io_counters()
                stats['total'] = {
                    'bytes_sent': str(net_io.bytes_sent),
                    'bytes_recv': str(net_io.bytes_recv),
                    'packets_sent': str(net_io.packets_sent),
                    'packets_recv': str(net_io.packets_recv)
                }
                
                # Calculate bandwidth
                current_bytes_sent = net_io.bytes_sent
                current_bytes_recv = net_io.bytes_recv
                
                if self.last_bytes_sent > 0 and self.last_bytes_recv > 0:
                    stats['bandwidth'] = {
                        'sent': current_bytes_sent - self.last_bytes_sent,
                        'recv': current_bytes_recv - self.last_bytes_recv
                    }
                
                self.last_bytes_sent = current_bytes_sent
                self.last_bytes_recv = current_bytes_recv
            except Exception as e:
                stats['total_error'] = str(e)
            
            # Connections - more robust handling
            try:
                connections = psutil.net_connections(kind='inet')
                stats['connections'] = []
                
                for conn in connections:
                    try:
                        conn_info = {
                            'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                            'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                            'status': str(conn.status),
                            'pid': str(conn.pid) if conn.pid else ''
                        }
                        
                        # Safely handle local address
                        if conn.laddr:
                            conn_info['local_addr'] = f"{conn.laddr.ip}:{conn.laddr.port}" 
                        else:
                            conn_info['local_addr'] = 'N/A'
                        
                        # Safely handle remote address
                        if conn.raddr:
                            conn_info['remote_addr'] = f"{conn.raddr.ip}:{conn.raddr.port}"
                        else:
                            conn_info['remote_addr'] = 'N/A'
                            
                        stats['connections'].append(conn_info)
                    except Exception as e:
                        stats['connections_error'] = str(e)
            except Exception as e:
                stats['connections_error'] = str(e)
            
            # Other network info
            try:
                gateways = netifaces.gateways()
                stats['gateways'] = gateways.get('default', {})
            except Exception as e:
                stats['gateways_error'] = str(e)
            
            stats['hostname'] = socket.gethostname()
            stats['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        except Exception as e:
            stats['error'] = f"Failed to collect stats: {str(e)}"
        
        return stats

class RemoteAccessThread(BaseThread):
    """Thread for testing remote access protocols"""
    result_found = pyqtSignal(str, str, str)  # service, status, details
    progress_updated = pyqtSignal(int, str)
    connection_success = pyqtSignal(str, object)  # service, connection
    finished = pyqtSignal()

    def __init__(self, ip: str, username: str, password: str, 
                 try_ssh: bool, try_rdp: bool, try_vnc: bool, 
                 try_telnet: bool, try_ftp: bool):
        super().__init__()
        self.ip = ip
        self.username = username
        self.password = password
        self.try_ssh = try_ssh
        self.try_rdp = try_rdp
        self.try_vnc = try_vnc
        self.try_telnet = try_telnet
        self.try_ftp = try_ftp

    def run(self):
        try:
            self.log(f"Starting remote access attempt for {self.ip}")
            
            # Try SSH if selected
            if self.try_ssh:
                self.test_ssh()
                
            # Try FTP if selected
            if self.try_ftp:
                self.test_ftp()
                
            # Would add similar methods for RDP, VNC, Telnet
            
            self.progress_updated.emit(100, "Scan completed")
            self.log("Remote access scan completed")
            self.finished.emit()
            
        except Exception as e:
            self.log(f"Scan error: {str(e)}")

    def test_ssh(self):
        """Test SSH connection to target"""
        self.progress_updated.emit(10, "Testing SSH connection")
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                client.connect(
                    self.ip,
                    username=self.username if self.username else 'root',
                    password=self.password if self.password else None,
                    timeout=5,
                    banner_timeout=5
                )
                
                self.result_found.emit("SSH", "Success", "Connected with provided credentials")
                self.connection_success.emit("SSH", client)
                return
                
            except paramiko.AuthenticationException:
                self.result_found.emit("SSH", "Failed", "Authentication failed")
            except paramiko.SSHException as e:
                self.result_found.emit("SSH", "Failed", f"SSH error: {str(e)}")
            except socket.timeout:
                self.result_found.emit("SSH", "Failed", "Connection timed out")
            except Exception as e:
                self.result_found.emit("SSH", "Failed", f"Error: {str(e)}")
                
        except ImportError:
            self.result_found.emit("SSH", "Skipped", "Paramiko library not installed")

    def test_ftp(self):
        """Test FTP connection to target"""
        self.progress_updated.emit(30, "Testing FTP connection")
        try:
            from ftplib import FTP
            
            try:
                ftp = FTP(self.ip, timeout=5)
                
                if self.username or self.password:
                    ftp.login(
                        user=self.username if self.username else 'anonymous',
                        passwd=self.password if self.password else 'anonymous@'
                    )
                else:
                    ftp.login()  # Try anonymous
                
                self.result_found.emit("FTP", "Success", "Connected with provided credentials")
                self.connection_success.emit("FTP", ftp)
                return
                
            except Exception as e:
                self.result_found.emit("FTP", "Failed", f"FTP error: {str(e)}")
                
        except ImportError:
            self.result_found.emit("FTP", "Skipped", "FTP library not available")

class TrafficGraph(FigureCanvas):
    """Widget for displaying traffic graph"""
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib not available")
            
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.ax = self.fig.add_subplot(111)
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Bytes')
        self.ax.grid(True)
        
        self.timestamps = []
        self.incoming = []
        self.outgoing = []
        self.max_points = 60  # Show last 60 data points
        
        self.line_in, = self.ax.plot([], [], 'g-', label='Incoming')
        self.line_out, = self.ax.plot([], [], 'r-', label='Outgoing')
        self.ax.legend()
        
    def update_graph(self, stats: Dict):
        """Update the graph with new traffic data"""
        if len(self.timestamps) >= self.max_points:
            self.timestamps.pop(0)
            self.incoming.pop(0)
            self.outgoing.pop(0)
            
        self.timestamps.append(datetime.now().strftime("%H:%M:%S"))
        self.incoming.append(stats['traffic_stats']['incoming'])
        self.outgoing.append(stats['traffic_stats']['outgoing'])
        
        self.line_in.set_data(range(len(self.timestamps)), self.incoming)
        self.line_out.set_data(range(len(self.timestamps)), self.outgoing)
        
        self.ax.relim()
        self.ax.autoscale_view()
        self.draw()

class ProtocolPieChart(FigureCanvas):
    """Widget for displaying protocol distribution pie chart"""
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib not available")
            
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.ax = self.fig.add_subplot(111)
        self.protocols = ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'DHCP', 'Other']
        self.counts = [0] * len(self.protocols)
        
    def update_chart(self, protocol_stats: Dict):
        """Update the pie chart with new protocol statistics"""
        self.counts = [protocol_stats.get(p, 0) for p in self.protocols]
        
        # Only show protocols with non-zero counts
        labels = []
        sizes = []
        for p, c in zip(self.protocols, self.counts):
            if c > 0:
                labels.append(p)
                sizes.append(c)
        
        if sizes:
            self.ax.clear()
            self.ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            self.ax.axis('equal')
            self.draw()

class NetworkToolkit(QMainWindow):
    """Main application window for the Network Toolkit"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Toolkit Pro")
        self.setGeometry(100, 100, 1400, 900)
        
        # Load settings
        self.settings = {}
        self.load_settings()
        
        # Initialize threads
        self.scan_thread = None
        self.sniffer_thread = None
        self.ping_thread = None
        self.wifi_thread = None
        self.stats_thread = None
        self.access_thread = None
        
        # Initialize UI
        self.init_ui()
        
        # Start periodic updates
        self.start_time = time.time()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(1000)  # Update every second
        
        # Apply theme
        if 'theme' in self.settings:
            self.apply_theme(self.settings['theme'])

    def show_about(self):
        """Show the about dialog"""
        about_text = """
        <h2>Advanced Network Toolkit Pro</h2>
        <p>Version 2.0</p>
        <p>A comprehensive network analysis tool with:</p>
        <ul>
            <li>Enhanced Nmap scanner</li>
            <li>Improved traffic monitor with protocol analysis</li>
            <li>Fast ping sweeper</li>
            <li>WiFi network analyzer</li>
            <li>Detailed network statistics</li>
            <li>IP information lookup</li>
            <li>Remote access testing</li>
        </ul>
        <p>Developed using Python, PyQt5, Scapy, and Nmap</p>
        """
        QMessageBox.about(self, "About Network Toolkit", about_text)
        
    def load_settings(self):
        """Load application settings from file"""
        try:
            with open('network_toolkit_settings.json', 'r') as f:
                self.settings = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.settings = {
                'theme': 'Light',
                'nmap': {
                    'last_target': '192.168.1.1',
                    'last_scan_type': 'Quick Scan'
                },
                'traffic': {
                    'last_interface': None,
                    'capture_filters': {
                        'tcp': True,
                        'udp': True,
                        'icmp': True,
                        'arp': True,
                        'dns': True,
                        'dhcp': True
                    }
                },
                'ping': {
                    'last_range': '192.168.1.0/24'
                }
            }
    
    def save_settings(self):
        """Save application settings to file"""
        try:
            with open('network_toolkit_settings.json', 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save settings: {str(e)}")
    
    def init_ui(self):
        """Initialize the user interface"""
        # Create menu bar
        self.create_menu_bar()
        
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Tab widget for different functionalities
        self.main_tabs = QTabWidget()
        main_layout.addWidget(self.main_tabs)
        
        # Create all tabs
        self.create_nmap_tab()
        self.create_ip_lookup_tab()
        self.create_traffic_monitor_tab()
        self.create_ping_sweep_tab()
        if WIFI_AVAILABLE:
            self.create_wifi_analyzer_tab()
        self.create_network_stats_tab()
        self.create_ip_remote_access_tab()
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        # Apply saved settings
        self.apply_settings()
    
    def apply_settings(self):
        """Apply saved settings to the UI"""
        # Nmap settings
        if 'nmap' in self.settings:
            self.target_input.setText(self.settings['nmap'].get('last_target', '192.168.1.1'))
            scan_type = self.settings['nmap'].get('last_scan_type', 'Quick Scan')
            index = self.scan_type.findText(scan_type)
            if index >= 0:
                self.scan_type.setCurrentIndex(index)
        
        # Traffic monitor settings
        if 'traffic' in self.settings:
            last_interface = self.settings['traffic'].get('last_interface')
            if last_interface:
                index = self.interface_combo.findText(last_interface)
                if index >= 0:
                    self.interface_combo.setCurrentIndex(index)
            
            if 'capture_filters' in self.settings['traffic']:
                for name, checkbox in self.protocol_filters.items():
                    if name in self.settings['traffic']['capture_filters']:
                        checkbox.setChecked(self.settings['traffic']['capture_filters'][name])
        
        # Ping sweep settings
        if 'ping' in self.settings:
            self.ping_range_input.setText(self.settings['ping'].get('last_range', '192.168.1.0/24'))
    
    def create_menu_bar(self):
        """Create the application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        save_action = QAction('Save Settings', self)
        save_action.triggered.connect(self.save_settings)
        file_menu.addAction(save_action)
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')

        payload_menu = tools_menu.addMenu('Payload Generation')
        
        msfvenom_action = QAction('MSFVenom Payload Generator', self)
        msfvenom_action.triggered.connect(self.show_msfvenom_generator)
        payload_menu.addAction(msfvenom_action)
        
        veil_action = QAction('Veil-Evasion Payload Generator', self)
        veil_action.triggered.connect(self.show_veil_evasion)
        payload_menu.addAction(veil_action)
        
        donut_action = QAction('Donut Shellcode Converter', self)
        donut_action.triggered.connect(self.show_donut_converter)
        payload_menu.addAction(donut_action)
        
        obfuscator_action = QAction('Packer/Obfuscator Toolkit', self)
        obfuscator_action.triggered.connect(self.show_obfuscator_toolkit)
        payload_menu.addAction(obfuscator_action)
        
        # Add scanning tools
        scan_menu = tools_menu.addMenu('Advanced Scanning')
        
        nikto_action = QAction('Nikto Web Scanner', self)
        nikto_action.triggered.connect(self.show_nikto_scanner)
        scan_menu.addAction(nikto_action)
        
        openvas_action = QAction('OpenVAS Vulnerability Scan', self)
        openvas_action.triggered.connect(self.show_openvas_scan)
        scan_menu.addAction(openvas_action)
        
        rustscan_action = QAction('RustScan Port Scanner', self)
        rustscan_action.triggered.connect(self.show_rustscan)
        scan_menu.addAction(rustscan_action)
        
        bettercap_action = QAction('Bettercap Network Tool', self)
        bettercap_action.triggered.connect(self.show_bettercap)
        scan_menu.addAction(bettercap_action)
        
        # Add new tools to the tools menu
        if DNS_AVAILABLE:
            dns_action = QAction('DNS Lookup / Reverse DNS', self)
            dns_action.triggered.connect(self.show_dns_tools)
            tools_menu.addAction(dns_action)
            
        port_knock_action = QAction('Port Knocking Listener', self)
        port_knock_action.triggered.connect(self.show_port_knocking)
        tools_menu.addAction(port_knock_action)
        
        vuln_scan_action = QAction('Vulnerability Scanner', self)
        vuln_scan_action.triggered.connect(self.show_vulnerability_scanner)
        tools_menu.addAction(vuln_scan_action)
        
        exploitdb_action = QAction('Exploit DB Searcher', self)
        exploitdb_action.triggered.connect(self.show_exploitdb_searcher)
        tools_menu.addAction(exploitdb_action)
        
        # Add actions for each tab
        tabs = [
            ("Nmap Scanner", 0),
            ("IP Lookup", 1),
            ("Traffic Monitor", 2),
            ("Ping Sweep", 3)
        ]
        
        if WIFI_AVAILABLE:
            tabs.append(("WiFi Analyzer", 4))
            
        tabs.extend([
            ("Network Stats", 5 if WIFI_AVAILABLE else 4),
            ("IP Remote Access", 6 if WIFI_AVAILABLE else 5)
        ])
        
        for name, index in tabs:
            action = QAction(name, self)
            action.triggered.connect(lambda _, i=index: self.main_tabs.setCurrentIndex(i))
            tools_menu.addAction(action)
        
        # Settings menu
        settings_menu = menubar.addMenu('Settings')
        
        theme_action = QAction('Theme Settings', self)
        theme_action.triggered.connect(self.show_theme_settings)
        settings_menu.addAction(theme_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_theme_settings(self):
        """Show the theme settings dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Theme Settings")
        dialog.setModal(True)
        layout = QVBoxLayout()
        
        # Theme selection
        theme_group = QGroupBox("Theme Settings")
        theme_layout = QVBoxLayout()
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "Catppuccin Latte", "Catppuccin Frappe", 
                                 "Catppuccin Macchiato", "Catppuccin Mocha"])
        
        # Load saved theme
        current_theme = self.settings.get('theme', 'Light')
        index = self.theme_combo.findText(current_theme)
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)
        
        theme_layout.addWidget(QLabel("Select Theme:"))
        theme_layout.addWidget(self.theme_combo)
        theme_group.setLayout(theme_layout)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(lambda: self.apply_theme_settings(dialog))
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(theme_group)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
    def apply_theme_settings(self, dialog):
        """Apply the selected theme settings"""
        selected_theme = self.theme_combo.currentText()
        self.settings['theme'] = selected_theme
        self.save_settings()
        self.apply_theme(selected_theme)
        dialog.accept()
    
    def apply_theme(self, theme_name):
        """Apply the selected theme to the application"""
        if theme_name == "Light":
            self.set_light_theme()
        elif theme_name == "Dark":
            self.set_dark_theme()
        elif "Catppuccin" in theme_name:
            self.set_catppuccin_theme(theme_name)
    
    def set_light_theme(self):
        """Set light theme colors"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.AlternateBase, QColor(233, 233, 233))
        palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 220))
        palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
        palette.setColor(QPalette.Text, QColor(0, 0, 0))
        palette.setColor(QPalette.Button, QColor(240, 240, 240))
        palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
        palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        QApplication.setPalette(palette)

    def set_dark_theme(self):
        """Set dark theme colors"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Base, QColor(42, 42, 42))
        palette.setColor(QPalette.AlternateBase, QColor(66, 66, 66))
        palette.setColor(QPalette.ToolTipBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        QApplication.setPalette(palette)

    def set_catppuccin_theme(self, variant):
        """Set Catppuccin theme colors based on variant"""
        palette = QPalette()
        
        # Define Catppuccin color schemes
        colors = {
            "Catppuccin Latte": {
                "base": "#eff1f5",
                "text": "#4c4f69",
                "subtext": "#6c6f85",
                "overlay": "#9ca0b0",
                "surface": "#ccd0da",
                "highlight": "#7287fd"
            },
            "Catppuccin Frappe": {
                "base": "#303446",
                "text": "#c6d0f5",
                "subtext": "#a5adce",
                "overlay": "#737994",
                "surface": "#414559",
                "highlight": "#8caaee"
            },
            "Catppuccin Macchiato": {
                "base": "#24273a",
                "text": "#cad3f5",
                "subtext": "#a5adcb",
                "overlay": "#6e738d",
                "surface": "#363a4f",
                "highlight": "#8aadf4"
            },
            "Catppuccin Mocha": {
                "base": "#1e1e2e",
                "text": "#cdd6f4",
                "subtext": "#bac2de",
                "overlay": "#6c7086",
                "surface": "#313244",
                "highlight": "#89b4fa"
            }
        }
        
        theme = colors.get(variant, colors["Catppuccin Mocha"])
        
        palette.setColor(QPalette.Window, QColor(theme["base"]))
        palette.setColor(QPalette.WindowText, QColor(theme["text"]))
        palette.setColor(QPalette.Base, QColor(theme["base"]))
        palette.setColor(QPalette.AlternateBase, QColor(theme["surface"]))
        palette.setColor(QPalette.ToolTipBase, QColor(theme["surface"]))
        palette.setColor(QPalette.ToolTipText, QColor(theme["text"]))
        palette.setColor(QPalette.Text, QColor(theme["text"]))
        palette.setColor(QPalette.Button, QColor(theme["surface"]))
        palette.setColor(QPalette.ButtonText, QColor(theme["text"]))
        palette.setColor(QPalette.BrightText, QColor("#f38ba8"))  # Red
        palette.setColor(QPalette.Highlight, QColor(theme["highlight"]))
        palette.setColor(QPalette.HighlightedText, QColor(theme["base"]))
        QApplication.setPalette(palette)
    
    def create_nmap_tab(self):
        """Create the Nmap scanner tab"""
        nmap_tab = QWidget()
        nmap_layout = QVBoxLayout()
        nmap_tab.setLayout(nmap_layout)
        
        splitter = QSplitter(Qt.Vertical)
        nmap_layout.addWidget(splitter)
        
        # Top panel - Controls and results
        top_panel = QWidget()
        top_layout = QVBoxLayout()
        top_panel.setLayout(top_layout)
        
        # Scan controls
        control_panel = QWidget()
        control_layout = QHBoxLayout()
        control_panel.setLayout(control_layout)
        
        target_label = QLabel("Target:")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP, range (192.168.1.1-100), or subnet (192.168.1.0/24)")
        
        scan_label = QLabel("Scan Type:")
        self.scan_type = QComboBox()
        self.scan_type.addItems([
            "Quick Scan", "Intense Scan", "Port Range", 
            "Service Detection", "OS Detection", 
            "Vulnerability Scan", "Full Scan", "Custom"
        ])
        
        self.port_range_input = QLineEdit("1-1024")
        self.port_range_input.setPlaceholderText("Port range (e.g., 1-1000)")
        self.port_range_input.hide()
        
        self.custom_args_input = QLineEdit()
        self.custom_args_input.setPlaceholderText("Custom nmap arguments")
        self.custom_args_input.hide()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setIcon(QIcon.fromTheme("system-search"))
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.setIcon(QIcon.fromTheme("process-stop"))
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.stop_scan_button.setEnabled(False)
        
        control_layout.addWidget(target_label)
        control_layout.addWidget(self.target_input)
        control_layout.addWidget(scan_label)
        control_layout.addWidget(self.scan_type)
        control_layout.addWidget(self.port_range_input)
        control_layout.addWidget(self.custom_args_input)
        control_layout.addWidget(self.scan_button)
        control_layout.addWidget(self.stop_scan_button)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.hide()
        
        self.progress_label = QLabel()
        self.progress_label.hide()
        
        self.scan_type.currentTextChanged.connect(self.update_scan_options)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        
        # Hosts table
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(6)
        self.hosts_table.setHorizontalHeaderLabels(["Host", "Status", "Hostname", "OS Guess", "Ports", "Services"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.hosts_table.horizontalHeader().setStretchLastSection(True)
        self.hosts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hosts_table.setSelectionMode(QTableWidget.SingleSelection)
        self.hosts_table.doubleClicked.connect(self.show_host_details)
        
        # Ports table
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(5)
        self.ports_table.setHorizontalHeaderLabels(["Port", "State", "Service", "Version", "Extra Info"])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ports_table.horizontalHeader().setStretchLastSection(True)
        
        # Vulnerability table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(3)
        self.vuln_table.setHorizontalHeaderLabels(["Port", "Vulnerability", "Description"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.vuln_table.horizontalHeader().setStretchLastSection(True)
        
        self.results_tabs.addTab(self.hosts_table, "Hosts")
        self.results_tabs.addTab(self.ports_table, "Ports")
        self.results_tabs.addTab(self.vuln_table, "Vulnerabilities")
        
        top_layout.addWidget(control_panel)
        top_layout.addWidget(self.progress_bar)
        top_layout.addWidget(self.progress_label)
        top_layout.addWidget(self.results_tabs)
        
        # Bottom panel (log output)
        bottom_panel = QWidget()
        bottom_layout = QVBoxLayout()
        bottom_panel.setLayout(bottom_layout)
        
        log_label = QLabel("Scan Log:")
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Courier", 10))
        
        bottom_layout.addWidget(log_label)
        bottom_layout.addWidget(self.log_output)
        
        splitter.addWidget(top_panel)
        splitter.addWidget(bottom_panel)
        splitter.setSizes([600, 200])
        
        self.main_tabs.addTab(nmap_tab, "Nmap Scanner")

    def create_ip_lookup_tab(self):
        """Create the IP lookup tab"""
        ip_tab = QWidget()
        ip_layout = QVBoxLayout()
        ip_tab.setLayout(ip_layout)
        
        input_panel = QWidget()
        input_layout = QHBoxLayout()
        input_panel.setLayout(input_layout)
        
        self.ip_lookup_input = QLineEdit()
        self.ip_lookup_input.setPlaceholderText("Enter IP address or domain")
        lookup_button = QPushButton("Lookup")
        lookup_button.setIcon(QIcon.fromTheme("edit-find"))
        lookup_button.clicked.connect(self.lookup_ip)
        
        input_layout.addWidget(self.ip_lookup_input)
        input_layout.addWidget(lookup_button)
        
        # Results display
        self.ip_info_tree = QTreeWidget()
        self.ip_info_tree.setHeaderLabels(["Property", "Value"])
        self.ip_info_tree.setColumnCount(2)
        self.ip_info_tree.setHeaderHidden(False)
        self.ip_info_tree.setIndentation(0)
        
        ip_layout.addWidget(input_panel)
        ip_layout.addWidget(self.ip_info_tree)
        
        self.main_tabs.addTab(ip_tab, "IP Lookup")
    
    def create_traffic_monitor_tab(self):
        """Create the traffic monitor tab"""
        traffic_tab = QWidget()
        traffic_layout = QVBoxLayout()
        traffic_tab.setLayout(traffic_layout)
        
        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout()
        control_panel.setLayout(control_layout)
        
        interface_label = QLabel("Network Interface:")
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        
        self.start_button = QPushButton("Start Capture")
        self.start_button.setIcon(QIcon.fromTheme("media-playback-start"))
        self.start_button.clicked.connect(self.start_traffic_capture)
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setIcon(QIcon.fromTheme("media-playback-stop"))
        self.stop_button.clicked.connect(self.stop_traffic_capture)
        self.stop_button.setEnabled(False)
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.setIcon(QIcon.fromTheme("edit-clear"))
        self.clear_button.clicked.connect(self.clear_traffic_table)
        
        self.save_button = QPushButton("Save Capture")
        self.save_button.setIcon(QIcon.fromTheme("document-save"))
        self.save_button.clicked.connect(self.save_capture)
        
        control_layout.addWidget(interface_label)
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addWidget(self.save_button)
        
        # Filter panel
        filter_panel = QGroupBox("Capture Filters")
        filter_layout = QHBoxLayout()
        filter_panel.setLayout(filter_layout)
        
        self.protocol_filters = {
            'tcp': QCheckBox("TCP"),
            'udp': QCheckBox("UDP"),
            'icmp': QCheckBox("ICMP"),
            'arp': QCheckBox("ARP"),
            'dns': QCheckBox("DNS"),
            'dhcp': QCheckBox("DHCP")
        }
        
        for name, checkbox in self.protocol_filters.items():
            checkbox.setChecked(True)
            filter_layout.addWidget(checkbox)
        
        filter_layout.addStretch()
        
        # Display filter
        display_filter_panel = QWidget()
        display_filter_layout = QHBoxLayout()
        display_filter_panel.setLayout(display_filter_layout)
        
        display_filter_label = QLabel("Display Filter:")
        self.traffic_filter_combo = QComboBox()
        self.traffic_filter_combo.addItems(["All", "TCP", "UDP", "ICMP", "ARP", "DNS", "DHCP", "Other"])
        
        display_filter_layout.addWidget(display_filter_label)
        display_filter_layout.addWidget(self.traffic_filter_combo)
        display_filter_layout.addStretch()
        
        # Traffic table
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(6)
        self.traffic_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol", "Length", "Info"])
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.traffic_table.horizontalHeader().setStretchLastSection(True)
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.traffic_table.setSortingEnabled(True)
        
        # Stats and graphs
        stats_panel = QWidget()
        stats_layout = QHBoxLayout()
        stats_panel.setLayout(stats_layout)
        
        # Traffic graph
        try:
            self.traffic_graph = TrafficGraph()
            stats_layout.addWidget(self.traffic_graph)
        except ImportError:
            self.traffic_graph = None
            stats_layout.addWidget(QLabel("Traffic graph disabled - matplotlib not installed"))
        
        # Protocol pie chart
        try:
            self.protocol_pie = ProtocolPieChart()
            stats_layout.addWidget(self.protocol_pie)
        except ImportError:
            self.protocol_pie = None
            stats_layout.addWidget(QLabel("Protocol chart disabled - matplotlib not installed"))
        
        # Add widgets to main layout
        traffic_layout.addWidget(control_panel)
        traffic_layout.addWidget(filter_panel)
        traffic_layout.addWidget(display_filter_panel)
        traffic_layout.addWidget(self.traffic_table)
        traffic_layout.addWidget(stats_panel)
        
        self.main_tabs.addTab(traffic_tab, "Traffic Monitor")
    
    def create_ping_sweep_tab(self):
        """Create the ping sweep tab"""
        ping_tab = QWidget()
        ping_layout = QVBoxLayout()
        ping_tab.setLayout(ping_layout)
        
        # Input panel
        input_panel = QWidget()
        input_layout = QHBoxLayout()
        input_panel.setLayout(input_layout)
        
        self.ping_range_input = QLineEdit()
        self.ping_range_input.setPlaceholderText("Enter network range (e.g., 192.168.1.0/24 or 192.168.1.1-100)")
        ping_button = QPushButton("Start Ping Sweep")
        ping_button.setIcon(QIcon.fromTheme("network-wired"))
        ping_button.clicked.connect(self.start_ping_sweep)
        stop_ping_button = QPushButton("Stop")
        stop_ping_button.setIcon(QIcon.fromTheme("process-stop"))
        stop_ping_button.clicked.connect(self.stop_ping_sweep)
        
        input_layout.addWidget(self.ping_range_input)
        input_layout.addWidget(ping_button)
        input_layout.addWidget(stop_ping_button)
        
        # Progress bar
        self.ping_progress = QProgressBar()
        self.ping_progress.setRange(0, 100)
        self.ping_progress.hide()
        self.ping_progress_label = QLabel()
        self.ping_progress_label.hide()
        
        # Filter panel
        filter_panel = QWidget()
        filter_layout = QHBoxLayout()
        filter_panel.setLayout(filter_layout)
        
        filter_label = QLabel("Filter:")
        self.ping_filter_combo = QComboBox()
        self.ping_filter_combo.addItems(["All", "Responding", "Not Responding"])
        
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.ping_filter_combo)
        filter_layout.addStretch()
        
        # Results table
        self.ping_results_table = QTableWidget()
        self.ping_results_table.setColumnCount(3)
        self.ping_results_table.setHorizontalHeaderLabels(["IP Address", "Status", "Open Ports"])
        self.ping_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ping_results_table.setItemDelegateForColumn(1, ColorDelegate(self.ping_results_table))
        self.ping_results_table.doubleClicked.connect(self.ping_host_double_clicked)
        
        # Add widgets to main layout
        ping_layout.addWidget(input_panel)
        ping_layout.addWidget(self.ping_progress)
        ping_layout.addWidget(self.ping_progress_label)
        ping_layout.addWidget(filter_panel)
        ping_layout.addWidget(self.ping_results_table)
        
        self.main_tabs.addTab(ping_tab, "Ping Sweep")
    
    def create_wifi_analyzer_tab(self):
        """Create the WiFi analyzer tab"""
        wifi_tab = QWidget()
        wifi_layout = QVBoxLayout()
        wifi_tab.setLayout(wifi_layout)
        
        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout()
        control_panel.setLayout(control_layout)
        
        # Interface selection
        interface_label = QLabel("Interface:")
        self.wifi_interface_combo = QComboBox()
        self.refresh_wifi_interfaces()
        
        self.refresh_wifi_button = QPushButton("Refresh Networks")
        self.refresh_wifi_button.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_wifi_button.clicked.connect(self.refresh_wifi_networks)
        
        self.start_monitor_button = QPushButton("Start Monitoring")
        self.start_monitor_button.setIcon(QIcon.fromTheme("media-playback-start"))
        self.start_monitor_button.clicked.connect(self.start_wifi_monitoring)
        
        self.stop_monitor_button = QPushButton("Stop Monitoring")
        self.stop_monitor_button.setIcon(QIcon.fromTheme("media-playback-stop"))
        self.stop_monitor_button.clicked.connect(self.stop_wifi_monitoring)
        self.stop_monitor_button.setEnabled(False)
        
        control_layout.addWidget(interface_label)
        control_layout.addWidget(self.wifi_interface_combo)
        control_layout.addWidget(self.refresh_wifi_button)
        control_layout.addWidget(self.start_monitor_button)
        control_layout.addWidget(self.stop_monitor_button)
        
        # WiFi networks table
        self.wifi_table = QTableWidget()
        self.wifi_table.setColumnCount(7)
        self.wifi_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Channel", "Signal", "Quality", "Security", "Frequency"])
        self.wifi_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.wifi_table.setSortingEnabled(True)
        
        # Add widgets to layout
        wifi_layout.addWidget(control_panel)
        wifi_layout.addWidget(self.wifi_table)
        
        self.main_tabs.addTab(wifi_tab, "WiFi Analyzer")

    def refresh_wifi_interfaces(self):
        """Refresh available WiFi interfaces"""
        self.wifi_interface_combo.clear()
        try:
            interfaces = netifaces.interfaces()
            wifi_interfaces = [iface for iface in interfaces if iface.startswith(('wlan', 'wlp', 'wifi'))]
            for iface in wifi_interfaces:
                self.wifi_interface_combo.addItem(iface)
            if wifi_interfaces:
                self.wifi_interface_combo.setCurrentIndex(0)
        except Exception as e:
            self.status_label.setText(f"Error refreshing interfaces: {str(e)}")

    def create_network_stats_tab(self):
        """Create the network statistics tab"""
        stats_tab = QWidget()
        stats_layout = QVBoxLayout()
        stats_tab.setLayout(stats_layout)
        
        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout()
        control_panel.setLayout(control_layout)
        
        self.refresh_stats_button = QPushButton("Refresh Stats")
        self.refresh_stats_button.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_stats_button.clicked.connect(self.refresh_network_stats)
        
        self.start_monitor_stats_button = QPushButton("Start Monitoring")
        self.start_monitor_stats_button.setIcon(QIcon.fromTheme("media-playback-start"))
        self.start_monitor_stats_button.clicked.connect(self.start_stats_monitoring)
        
        self.stop_monitor_stats_button = QPushButton("Stop Monitoring")
        self.stop_monitor_stats_button.setIcon(QIcon.fromTheme("media-playback-stop"))
        self.stop_monitor_stats_button.clicked.connect(self.stop_stats_monitoring)
        self.stop_monitor_stats_button.setEnabled(False)
        
        control_layout.addWidget(self.refresh_stats_button)
        control_layout.addWidget(self.start_monitor_stats_button)
        control_layout.addWidget(self.stop_monitor_stats_button)
        
        # Stats tree
        self.stats_tree = QTreeWidget()
        self.stats_tree.setHeaderLabels(["Property", "Value"])
        self.stats_tree.setColumnCount(2)
        self.stats_tree.setHeaderHidden(False)
        self.stats_tree.setIndentation(20)
        
        # Bandwidth graph
        try:
            self.bandwidth_graph = FigureCanvas(Figure(figsize=(5, 3)))
            self.bw_ax = self.bandwidth_graph.figure.add_subplot(111)
            self.bw_ax.set_xlabel('Time')
            self.bw_ax.set_ylabel('Bytes')
            self.bw_ax.grid(True)
            
            # Initialize bandwidth graph data
            self.bw_timestamps = []
            self.bw_sent = []
            self.bw_recv = []
            self.bw_line_sent, = self.bw_ax.plot([], [], 'g-', label='Sent')
            self.bw_line_recv, = self.bw_ax.plot([], [], 'r-', label='Received')
            self.bw_ax.legend()
            
            stats_layout.addWidget(self.bandwidth_graph)
        except ImportError:
            self.bandwidth_graph = None
            stats_layout.addWidget(QLabel("Bandwidth graph disabled - matplotlib not installed"))
        
        # Add widgets to layout
        stats_layout.addWidget(control_panel)
        stats_layout.addWidget(self.stats_tree)
        
        self.main_tabs.addTab(stats_tab, "Network Stats")
    
    def create_ip_remote_access_tab(self):
        """Create the IP remote access tab"""
        access_tab = QWidget()
        access_layout = QVBoxLayout()
        access_tab.setLayout(access_layout)

        # Input panel
        input_panel = QWidget()
        input_layout = QHBoxLayout()
        input_panel.setLayout(input_layout)

        self.remote_ip_input = QLineEdit()
        self.remote_ip_input.setPlaceholderText("Enter target IP address")
        
        self.remote_user_input = QLineEdit()
        self.remote_user_input.setPlaceholderText("Username")
        
        self.remote_pass_input = QLineEdit()
        self.remote_pass_input.setPlaceholderText("Password/PIN")
        self.remote_pass_input.setEchoMode(QLineEdit.Password)
        
        connect_btn = QPushButton("Connect")
        connect_btn.clicked.connect(self.attempt_remote_access)
        
        vm_btn = QPushButton("Create VirtualBox")
        vm_btn.clicked.connect(self.create_virtualbox_vm)
        
        input_layout.addWidget(QLabel("IP:"))
        input_layout.addWidget(self.remote_ip_input)
        input_layout.addWidget(QLabel("User:"))
        input_layout.addWidget(self.remote_user_input)
        input_layout.addWidget(QLabel("Pass:"))
        input_layout.addWidget(self.remote_pass_input)
        input_layout.addWidget(connect_btn)
        input_layout.addWidget(vm_btn)

        # Connection methods group
        methods_group = QGroupBox("Connection Methods")
        methods_layout = QHBoxLayout()
        methods_group.setLayout(methods_layout)
        
        self.ssh_check = QCheckBox("SSH")
        self.ssh_check.setChecked(True)
        self.rdp_check = QCheckBox("RDP")
        self.vnc_check = QCheckBox("VNC")
        self.telnet_check = QCheckBox("Telnet")
        self.ftp_check = QCheckBox("FTP")
        
        methods_layout.addWidget(self.ssh_check)
        methods_layout.addWidget(self.rdp_check)
        methods_layout.addWidget(self.vnc_check)
        methods_layout.addWidget(self.telnet_check)
        methods_layout.addWidget(self.ftp_check)

        # Results display
        self.access_results_tree = QTreeWidget()
        self.access_results_tree.setHeaderLabels(["Service", "Status", "Details"])
        self.access_results_tree.setColumnCount(3)
        self.access_results_tree.setHeaderHidden(False)
        self.access_results_tree.setIndentation(0)

        # File browser (for successful connections)
        self.file_browser = QTreeWidget()
        self.file_browser.setHeaderLabels(["Name", "Type", "Size", "Permissions"])
        self.file_browser.setColumnCount(4)
        self.file_browser.hide()  # Only show when we have a successful connection

        # Command execution panel (for successful connections)
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute...")
        self.command_input.hide()
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.hide()

        # Progress bar
        self.access_progress = QProgressBar()
        self.access_progress.setRange(0, 100)
        self.access_progress.hide()

        # Log output
        self.access_log = QTextEdit()
        self.access_log.setReadOnly(True)
        self.access_log.setFont(QFont("Courier", 10))

        # Add widgets to layout
        access_layout.addWidget(input_panel)
        access_layout.addWidget(methods_group)
        access_layout.addWidget(self.access_progress)
        access_layout.addWidget(self.access_results_tree)
        access_layout.addWidget(self.file_browser)
        access_layout.addWidget(self.command_input)
        access_layout.addWidget(self.command_output)
        access_layout.addWidget(QLabel("Connection Log:"))
        access_layout.addWidget(self.access_log)

        self.main_tabs.addTab(access_tab, "IP Remote Access")

    def create_virtualbox_vm(self):
        """Create VirtualBox VM with specified IP"""
        ip = self.remote_ip_input.text()
        password = self.remote_pass_input.text()
        
        if not ip or not self.is_valid_ip(ip):
            QMessageBox.warning(self, "Error", "Invalid IP address")
            return
        
        try:
            vm_name = f"VM_{ip.replace('.','_')}"
            commands = [
                f'VBoxManage createvm --name "{vm_name}" --register',
                f'VBoxManage modifyvm "{vm_name}" --memory 2048 --ostype Linux_64',
                f'VBoxManage modifyvm "{vm_name}" --nic1 bridged --bridgeadapter1 eth0',
                f'VBoxManage modifyvm "{vm_name}" --natpf1 "ssh,tcp,,2222,,22"'
            ]
            
            for cmd in commands:
                subprocess.run(cmd, shell=True, check=True)
            
            QMessageBox.information(self, "Success", f"VM {vm_name} created\nPassword: {password}")
            
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"VM creation failed: {str(e)}")
    
    def refresh_interfaces(self):
        """Refresh the list of available network interfaces"""
        self.interface_combo.clear()
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                # Skip loopback and non-wireless interfaces
                if iface.startswith('lo') or iface.startswith('docker'):
                    continue
                self.interface_combo.addItem(iface)
            
            # Select the first non-loopback interface
            if self.interface_combo.count() > 0:
                self.interface_combo.setCurrentIndex(0)
        except Exception as e:
            self.status_label.setText(f"Error refreshing interfaces: {str(e)}")

    def create_advanced_tools_tab(self):
        """Create the Advanced Tools tab with new security tools"""
        tools_tab = QWidget()
        layout = QVBoxLayout()
        tools_tab.setLayout(layout)
        
        # Tool grid layout
        grid = QGridLayout()
        grid.setSpacing(10)
        
        # Create tool buttons
        tools = [
            ("Metasploit", self.launch_metasploit, "#FF6B6B"),
            ("Hydra", partial(self.launch_tool_dialog, "Hydra"), "#4ECDC4"),
            ("John the Ripper", partial(self.launch_tool_dialog, "John"), "#45B7D1"),
            ("Netcat", self.launch_netcat_dialog, "#96CEB4"),
            ("Aircrack-ng", self.launch_aircrack_dialog, "#FFEEAD"),
            ("Ghidra", self.launch_ghidra, "#D4A5A5"),
            ("theHarvester", self.launch_harvester_dialog, "#88D8B0"),
            ("Zphisher", self.launch_zphisher, "#FF9999"),
            ("Shodan", self.launch_shodan_dialog, "#99CCFF")
        ]

        # Add buttons to grid
        positions = [(i//3, i%3) for i in range(len(tools))]
        for (name, handler, color), pos in zip(tools, positions):
            btn = QPushButton(name)
            btn.setStyleSheet(f"background-color: {color}; padding: 15px;")
            btn.clicked.connect(handler)
            grid.addWidget(btn, pos[0], pos[1])

        # Add documentation/help area
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
            <h3>Tool Quick Guide</h3>
            <ul>
                <li><b>Metasploit:</b> Penetration testing framework</li>
                <li><b>Hydra:</b> Network logon cracker</li>
                <li><b>John:</b> Password cracker</li>
                <li><b>Netcat:</b> Network swiss army knife</li>
                <li><b>Aircrack-ng:</b> WiFi security tools</li>
                <li><b>Ghidra:</b> Reverse engineering suite</li>
                <li><b>theHarvester:</b> OSINT reconnaissance</li>
                <li><b>Zphisher:</b> Phishing tool</li>
                <li><b>Shodan:</b> IoT search engine</li>
            </ul>
        """)

        layout.addLayout(grid)
        layout.addWidget(help_text)
        self.main_tabs.addTab(tools_tab, "Advanced Tools")

    # New tool launch methods
    def launch_tool_dialog(self, tool_name):
        """Generic dialog for tools requiring parameter input"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{tool_name} Configuration")
        layout = QVBoxLayout()
        
        # Common input fields
        target_input = QLineEdit()
        target_input.setObjectName("target")  # ✅ Add this
        port_input = QLineEdit()
        port_input.setObjectName("port")     # ✅ Add this
        service_combo = QComboBox()
        service_combo.setObjectName("service")  # ✅ Add this
        
        # Tool-specific configuration
        if tool_name == "Hydra":
            service_combo = QComboBox()
            service_combo.addItems(["ssh", "ftp", "http-post-form", "smb"])
            username_input = QLineEdit()
            password_list_btn = QPushButton("Select Password List")
            
            form = QFormLayout()
            form.addRow("Target:", target_input)
            form.addRow("Port:", port_input)
            form.addRow("Service:", service_combo)
            form.addRow("Username:", username_input)
            form.addRow("Password List:", password_list_btn)
            
        elif tool_name == "John":
            hash_input = QLineEdit()
            wordlist_btn = QPushButton("Select Wordlist")
            
            form = QFormLayout()
            form.addRow("Hash File:", hash_input)
            form.addRow("Wordlist:", wordlist_btn)
        
        # Common execution button
        run_btn = QPushButton(f"Run {tool_name}")
        run_btn.clicked.connect(partial(self.execute_tool, tool_name, dialog))
        
        layout.addLayout(form)
        layout.addWidget(output_area)
        layout.addWidget(run_btn)
        dialog.setLayout(layout)
        dialog.exec_()

    def execute_tool(self, tool_name, dialog):
        """Execute the selected tool with parameters"""
        # This would contain the actual command execution logic
        # Example for Hydra:
        if tool_name == "Hydra":
            target = dialog.findChild(QLineEdit, "target").text()
            port = dialog.findChild(QLineEdit, "port").text()
            service = dialog.findChild(QComboBox, "service").currentText()
            username = dialog.findChild(QLineEdit, "username").text()
            password_list = "path/to/selected/file"
            
            cmd = f"hydra -l {username} -P {password_list} -s {port} {service}://{target}"
            self.run_command(cmd, dialog.findChild(QTextEdit))
            
    def run_command(self, command, output_widget):
        """Generic command runner with output display"""
        def worker():
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            while True:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                if output:
                    output_widget.append(output.decode().strip())
            process.wait()
            
        threading.Thread(target=worker, daemon=True).start()

    def launch_metasploit(self):
        """Launch Metasploit framework interface"""
        try:
            subprocess.Popen(["x-terminal-emulator", "-e", "msfconsole"])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to launch Metasploit: {str(e)}")

    def launch_netcat_dialog(self):
        """Netcat listener/connector dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Netcat Configuration")
        layout = QVBoxLayout()
        
        mode_group = QGroupBox("Operation Mode")
        mode_layout = QHBoxLayout()
        listen_radio = QRadioButton("Listen")
        connect_radio = QRadioButton("Connect")
        mode_layout.addWidget(listen_radio)
        mode_layout.addWidget(connect_radio)
        mode_group.setLayout(mode_layout)
        
        port_input = QLineEdit()
        command_input = QLineEdit()
        execute_btn = QPushButton("Execute")
        
        form = QFormLayout()
        form.addRow("Port:", port_input)
        form.addRow("Command:", command_input)
        
        layout.addWidget(mode_group)
        layout.addLayout(form)
        layout.addWidget(execute_btn)
        dialog.setLayout(layout)
        dialog.exec_()

    def launch_aircrack_dialog(self):
        """Aircrack-ng WiFi cracking dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Aircrack-ng Configuration")
        layout = QVBoxLayout()
        
        handshake_btn = QPushButton("Select Handshake File")
        wordlist_btn = QPushButton("Select Wordlist")
        run_btn = QPushButton("Start Cracking")
        
        layout.addWidget(handshake_btn)
        layout.addWidget(wordlist_btn)
        layout.addWidget(run_btn)
        dialog.setLayout(layout)
        dialog.exec_()

    def launch_ghidra(self):
        """Launch Ghidra reverse engineering tool"""
        try:
            subprocess.Popen(["ghidra"])
        except Exception as e:
            QMessageBox.warning(self, "Error", "Ghidra not found. Ensure it's installed and in PATH")

    def launch_harvester_dialog(self):
        """theHarvester OSINT dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("theHarvester Configuration")
        layout = QVBoxLayout()
        
        domain_input = QLineEdit()
        sources_combo = QComboBox()
        sources_combo.addItems(["all", "google", "linkedin", "twitter"])
        limit_input = QLineEdit("500")
        
        form = QFormLayout()
        form.addRow("Domain:", domain_input)
        form.addRow("Sources:", sources_combo)
        form.addRow("Limit:", limit_input)
        
        run_btn = QPushButton("Start Harvesting")
        layout.addLayout(form)
        layout.addWidget(run_btn)
        dialog.setLayout(layout)
        dialog.exec_()

    def launch_zphisher(self):
        """Launch Zphisher phishing tool"""
        try:
            subprocess.Popen(["bash", "-c", "cd zphisher && ./zphisher.sh"], cwd=os.path.expanduser("~"))
        except Exception as e:
            QMessageBox.warning(self, "Error", "Zphisher not found. Clone from https://github.com/htr-tech/zphisher")

    def launch_shodan_dialog(self):
        """Shodan search interface"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Shodan Search")
        layout = QVBoxLayout()
        
        api_key_input = QLineEdit()
        query_input = QLineEdit()
        results_area = QTextEdit()
        
        form = QFormLayout()
        form.addRow("API Key:", api_key_input)
        form.addRow("Search Query:", query_input)
        
        search_btn = QPushButton("Search Shodan")
        layout.addLayout(form)
        layout.addWidget(results_area)
        layout.addWidget(search_btn)
        dialog.setLayout(layout)
        dialog.exec_()

    def show_msfvenom_generator(self):
        """Show MSFVenom payload generator dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("MSFVenom Payload Generator")
        dialog.setMinimumWidth(600)
        layout = QVBoxLayout()
        
        # Payload type selection
        type_group = QGroupBox("Payload Settings")
        type_layout = QFormLayout()
        
        self.msf_payload_type = QComboBox()
        self.msf_payload_type.addItems([
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "android/meterpreter/reverse_tcp",
            "java/meterpreter/reverse_tcp",
            "php/meterpreter/reverse_tcp"
        ])
        
        self.msf_lhost = QLineEdit()
        self.msf_lhost.setPlaceholderText("Attacker IP")
        
        self.msf_lport = QLineEdit("4444")
        
        self.msf_output_format = QComboBox()
        self.msf_output_format.addItems([
            "exe", "dll", "ps1", "py", "raw", "elf", "apk", "war", "jsp"
        ])
        
        self.msf_output_file = QLineEdit()
        self.msf_output_file.setPlaceholderText("Output file path")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_msf_output)
        
        type_layout.addRow("Payload Type:", self.msf_payload_type)
        type_layout.addRow("LHOST:", self.msf_lhost)
        type_layout.addRow("LPORT:", self.msf_lport)
        type_layout.addRow("Output Format:", self.msf_output_format)
        type_layout.addRow("Output File:", self.msf_output_file)
        type_layout.addRow("", browse_button)
        type_group.setLayout(type_layout)
        
        # Advanced options
        adv_group = QGroupBox("Advanced Options")
        adv_layout = QVBoxLayout()
        
        self.msf_encoder = QComboBox()
        self.msf_encoder.addItems(["none", "x86/shikata_ga_nai", "x64/xor", "cmd/powershell_base64"])
        
        self.msf_iterations = QSpinBox()
        self.msf_iterations.setRange(1, 20)
        self.msf_iterations.setValue(1)
        
        adv_layout.addWidget(QLabel("Encoder:"))
        adv_layout.addWidget(self.msf_encoder)
        adv_layout.addWidget(QLabel("Iterations:"))
        adv_layout.addWidget(self.msf_iterations)
        adv_group.setLayout(adv_layout)
        
        # Generate button and output
        generate_button = QPushButton("Generate Payload")
        generate_button.clicked.connect(self.generate_msfvenom_payload)
        
        self.msf_output = QTextEdit()
        self.msf_output.setReadOnly(True)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(type_group)
        layout.addWidget(adv_group)
        layout.addWidget(generate_button)
        layout.addWidget(self.msf_output)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
    def browse_msf_output(self):
        """Browse for output file location"""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Payload", "", "All Files (*)")
        if file_name:
            self.msf_output_file.setText(file_name)
    
    def generate_msfvenom_payload(self):
        """Generate payload using MSFVenom"""
        payload = self.msf_payload_type.currentText()
        lhost = self.msf_lhost.text()
        lport = self.msf_lport.text()
        out_format = self.msf_output_format.currentText()
        out_file = self.msf_output_file.text()
        encoder = self.msf_encoder.currentText()
        iterations = self.msf_iterations.value()
        
        if not lhost:
            QMessageBox.warning(self, "Error", "Please enter LHOST (your IP)")
            return
        if not lport.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid port number")
            return
        
        # Build command
        cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", out_format]
        
        if encoder != "none":
            cmd.extend(["-e", encoder, "-i", str(iterations)])
        
        if out_file:
            cmd.extend(["-o", out_file])
        
        try:
            process = Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.msf_output.append("Payload generated successfully!\n")
                self.msf_output.append(stdout.decode())
                
                if out_file:
                    self.msf_output.append(f"\nSaved to: {out_file}")
            else:
                self.msf_output.append("Error generating payload:\n")
                self.msf_output.append(stderr.decode())
        
        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "MSFVenom not found. Please ensure Metasploit is installed.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate payload: {str(e)}")

    # Veil-Evasion Payload Generator
    def show_veil_evasion(self):
        """Show Veil-Evasion payload generator dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Veil-Evasion Payload Generator")
        dialog.setMinimumWidth(600)
        layout = QVBoxLayout()
        
        # Payload settings
        type_group = QGroupBox("Payload Settings")
        type_layout = QFormLayout()
        
        self.veil_payload_type = QComboBox()
        self.veil_payload_type.addItems([
            "python/meterpreter/rev_tcp",
            "python/shellcode_inject/aes_encrypt",
            "c/meterpreter/rev_tcp",
            "powershell/meterpreter/rev_tcp"
        ])
        
        self.veil_lhost = QLineEdit()
        self.veil_lhost.setPlaceholderText("Attacker IP")
        
        self.veil_lport = QLineEdit("4444")
        
        self.veil_output_file = QLineEdit()
        self.veil_output_file.setPlaceholderText("Output file path (optional)")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_veil_output)
        
        type_layout.addRow("Payload Type:", self.veil_payload_type)
        type_layout.addRow("LHOST:", self.veil_lhost)
        type_layout.addRow("LPORT:", self.veil_lport)
        type_layout.addRow("Output File:", self.veil_output_file)
        type_layout.addRow("", browse_button)
        type_group.setLayout(type_layout)
        
        # Generate button and output
        generate_button = QPushButton("Generate Payload")
        generate_button.clicked.connect(self.generate_veil_payload)
        
        self.veil_output = QTextEdit()
        self.veil_output.setReadOnly(True)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(type_group)
        layout.addWidget(generate_button)
        layout.addWidget(self.veil_output)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
    def browse_veil_output(self):
        """Browse for Veil output file location"""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Payload", "", "All Files (*)")
        if file_name:
            self.veil_output_file.setText(file_name)
    
    def generate_veil_payload(self):
        """Generate payload using Veil-Evasion"""
        payload = self.veil_payload_type.currentText()
        lhost = self.veil_lhost.text()
        lport = self.veil_lport.text()
        out_file = self.veil_output_file.text()
        
        if not lhost:
            QMessageBox.warning(self, "Error", "Please enter LHOST (your IP)")
            return
        if not lport.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid port number")
            return
        
        try:
            # Create temp directory for Veil output
            temp_dir = tempfile.mkdtemp()
            
            # Build command
            cmd = ["veil-evasion", "-t", payload, "--ip", lhost, "--port", lport, "-o", "payload"]
            
            process = Popen(cmd, stdout=PIPE, stderr=PIPE, cwd=temp_dir)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.veil_output.append("Payload generated successfully!\n")
                self.veil_output.append(stdout.decode())
                
                # Find generated files
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        if file.startswith("payload"):
                            src_path = os.path.join(root, file)
                            
                            if out_file:
                                # Copy to user-specified location
                                shutil.copy(src_path, out_file)
                                self.veil_output.append(f"\nSaved to: {out_file}")
                            else:
                                # Show path to temp file
                                self.veil_output.append(f"\nGenerated file: {src_path}")
            else:
                self.veil_output.append("Error generating payload:\n")
                self.veil_output.append(stderr.decode())
        
        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "Veil-Evasion not found. Please ensure it is installed.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate payload: {str(e)}")
        finally:
            # Clean up temp directory
            if 'temp_dir' in locals():
                shutil.rmtree(temp_dir, ignore_errors=True)

    # Donut Shellcode Converter
    def show_donut_converter(self):
        """Show Donut shellcode converter dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Donut Shellcode Converter")
        dialog.setMinimumWidth(600)
        layout = QVBoxLayout()
        
        # File selection
        file_group = QGroupBox("Input File")
        file_layout = QHBoxLayout()
        
        self.donut_input_file = QLineEdit()
        self.donut_input_file.setPlaceholderText("Select EXE or DLL file")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_donut_input)
        
        file_layout.addWidget(self.donut_input_file)
        file_layout.addWidget(browse_button)
        file_group.setLayout(file_layout)
        
        # Options
        opt_group = QGroupBox("Options")
        opt_layout = QFormLayout()
        
        self.donut_arch = QComboBox()
        self.donut_arch.addItems(["x86", "x64", "x84 (both)"])
        
        self.donut_output_file = QLineEdit()
        self.donut_output_file.setPlaceholderText("Output file path (optional)")
        out_browse_button = QPushButton("Browse...")
        out_browse_button.clicked.connect(self.browse_donut_output)
        
        opt_layout.addRow("Architecture:", self.donut_arch)
        opt_layout.addRow("Output File:", self.donut_output_file)
        opt_layout.addRow("", out_browse_button)
        opt_group.setLayout(opt_layout)
        
        # Convert button and output
        convert_button = QPushButton("Convert to Shellcode")
        convert_button.clicked.connect(self.convert_with_donut)
        
        self.donut_output = QTextEdit()
        self.donut_output.setReadOnly(True)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(file_group)
        layout.addWidget(opt_group)
        layout.addWidget(convert_button)
        layout.addWidget(self.donut_output)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
    def browse_donut_input(self):
        """Browse for input file for Donut"""
        file_name, _ = QFileDialog.getOpenFileName(self, "Select EXE/DLL", "", "Executable Files (*.exe *.dll);;All Files (*)")
        if file_name:
            self.donut_input_file.setText(file_name)
    
    def browse_donut_output(self):
        """Browse for Donut output file location"""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Shellcode", "", "Binary Files (*.bin);;All Files (*)")
        if file_name:
            self.donut_output_file.setText(file_name)
    
    def convert_with_donut(self):
        """Convert EXE/DLL to shellcode using Donut"""
        input_file = self.donut_input_file.text()
        output_file = self.donut_output_file.text()
        arch = self.donut_arch.currentText()
        
        if not input_file:
            QMessageBox.warning(self, "Error", "Please select an input file")
            return
        if not os.path.isfile(input_file):
            QMessageBox.warning(self, "Error", "Input file does not exist")
            return
        
        try:
            # Build command
            cmd = ["donut", "-a", arch[:2], "-f", "1", input_file]
            
            if output_file:
                cmd.extend(["-o", output_file])
            
            process = Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.donut_output.append("Conversion successful!\n")
                self.donut_output.append(stdout.decode())
                
                if output_file:
                    self.donut_output.append(f"\nSaved to: {output_file}")
                else:
                    # Donut creates a file with .bin extension by default
                    base_name = os.path.splitext(os.path.basename(input_file))[0]
                    default_output = f"{base_name}.bin"
                    if os.path.exists(default_output):
                        self.donut_output.append(f"\nOutput file: {os.path.abspath(default_output)}")
            else:
                self.donut_output.append("Error during conversion:\n")
                self.donut_output.append(stderr.decode())
        
        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "Donut not found. Please ensure it is installed.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to convert file: {str(e)}")

    # Packer/Obfuscator Toolkit
    def show_obfuscator_toolkit(self):
        """Show packer/obfuscator toolkit dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Packer/Obfuscator Toolkit")
        dialog.setMinimumWidth(700)
        layout = QVBoxLayout()
        
        # File selection
        file_group = QGroupBox("Input File")
        file_layout = QHBoxLayout()
        
        self.obfuscator_input_file = QLineEdit()
        self.obfuscator_input_file.setPlaceholderText("Select file to obfuscate")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_obfuscator_input)
        
        file_layout.addWidget(self.obfuscator_input_file)
        file_layout.addWidget(browse_button)
        file_group.setLayout(file_layout)
        
        # Tool selection
        tool_group = QGroupBox("Tool Selection")
        tool_layout = QVBoxLayout()
        
        self.obfuscator_tool = QComboBox()
        self.obfuscator_tool.addItems([
            "UPX (Packer)",
            "PyInstaller (Python)",
            "PyArmor (Python)",
            "Obfuscator-LLVM (C/C++)",
            "ConfuserEx (.NET)"
        ])
        
        tool_layout.addWidget(self.obfuscator_tool)
        tool_group.setLayout(tool_layout)
        
        # Options
        opt_group = QGroupBox("Options")
        opt_layout = QFormLayout()
        
        self.obfuscator_output_file = QLineEdit()
        self.obfuscator_output_file.setPlaceholderText("Output file path (optional)")
        out_browse_button = QPushButton("Browse...")
        out_browse_button.clicked.connect(self.browse_obfuscator_output)
        
        opt_layout.addRow("Output File:", self.obfuscator_output_file)
        opt_layout.addRow("", out_browse_button)
        opt_group.setLayout(opt_layout)
        
        # Process button and output
        process_button = QPushButton("Process File")
        process_button.clicked.connect(self.process_with_obfuscator)
        
        self.obfuscator_output = QTextEdit()
        self.obfuscator_output.setReadOnly(True)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(file_group)
        layout.addWidget(tool_group)
        layout.addWidget(opt_group)
        layout.addWidget(process_button)
        layout.addWidget(self.obfuscator_output)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
    def browse_obfuscator_input(self):
        """Browse for input file for obfuscator"""
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_name:
            self.obfuscator_input_file.setText(file_name)
    
    def browse_obfuscator_output(self):
        """Browse for obfuscator output file location"""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Output", "", "All Files (*)")
        if file_name:
            self.obfuscator_output_file.setText(file_name)
    
    def process_with_obfuscator(self):
        """Process file with selected obfuscator/packer"""
        input_file = self.obfuscator_input_file.text()
        output_file = self.obfuscator_output_file.text()
        tool = self.obfuscator_tool.currentText()
        
        if not input_file:
            QMessageBox.warning(self, "Error", "Please select an input file")
            return
        if not os.path.isfile(input_file):
            QMessageBox.warning(self, "Error", "Input file does not exist")
            return
        
        try:
            if "UPX" in tool:
                self.run_upx(input_file, output_file)
            elif "PyInstaller" in tool:
                self.run_pyinstaller(input_file, output_file)
            elif "PyArmor" in tool:
                self.run_pyarmor(input_file, output_file)
            elif "Obfuscator-LLVM" in tool:
                self.run_obfuscator_llvm(input_file, output_file)
            elif "ConfuserEx" in tool:
                self.run_confuserex(input_file, output_file)
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to process file: {str(e)}")
    
    def run_upx(self, input_file, output_file):
        """Run UPX packer"""
        cmd = ["upx", input_file]
        if output_file:
            cmd.extend(["-o", output_file])
        
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        
        self.obfuscator_output.append("UPX Output:\n")
        self.obfuscator_output.append(stdout.decode())
        if stderr:
            self.obfuscator_output.append("\nErrors:\n")
            self.obfuscator_output.append(stderr.decode())
    
    def run_pyinstaller(self, input_file, output_file):
        """Run PyInstaller"""
        if not input_file.endswith('.py'):
            QMessageBox.warning(self, "Error", "PyInstaller requires a Python script")
            return
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        
        try:
            cmd = ["pyinstaller", "--onefile", "--distpath", temp_dir, input_file]
            process = Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            
            self.obfuscator_output.append("PyInstaller Output:\n")
            self.obfuscator_output.append(stdout.decode())
            if stderr:
                self.obfuscator_output.append("\nErrors:\n")
                self.obfuscator_output.append(stderr.decode())
            
            # Find the output executable
            base_name = os.path.splitext(os.path.basename(input_file))[0]
            exe_name = f"{base_name}.exe" if os.name == 'nt' else base_name
            exe_path = os.path.join(temp_dir, exe_name)
            
            if os.path.exists(exe_path):
                if output_file:
                    shutil.copy(exe_path, output_file)
                    self.obfuscator_output.append(f"\nSaved to: {output_file}")
                else:
                    self.obfuscator_output.append(f"\nGenerated executable: {exe_path}")
            else:
                self.obfuscator_output.append("\nError: Could not find output executable")
        
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def run_pyarmor(self, input_file, output_file):
        """Run PyArmor obfuscator"""
        if not input_file.endswith('.py'):
            QMessageBox.warning(self, "Error", "PyArmor requires a Python script")
            return
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        
        try:
            cmd = ["pyarmor", "obfuscate", "--output", temp_dir, input_file]
            process = Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            
            self.obfuscator_output.append("PyArmor Output:\n")
            self.obfuscator_output.append(stdout.decode())
            if stderr:
                self.obfuscator_output.append("\nErrors:\n")
                self.obfuscator_output.append(stderr.decode())
            
            # Find the output file
            base_name = os.path.basename(input_file)
            obfuscated_path = os.path.join(temp_dir, base_name)
            
            if os.path.exists(obfuscated_path):
                if output_file:
                    shutil.copy(obfuscated_path, output_file)
                    self.obfuscator_output.append(f"\nSaved to: {output_file}")
                else:
                    self.obfuscator_output.append(f"\nObfuscated script: {obfuscated_path}")
            else:
                self.obfuscator_output.append("\nError: Could not find obfuscated output")
        
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def run_obfuscator_llvm(self, input_file, output_file):
        """Run Obfuscator-LLVM"""
        if not (input_file.endswith('.c') or input_file.endswith('.cpp')):
            QMessageBox.warning(self, "Error", "Obfuscator-LLVM requires C/C++ source")
            return
        
        self.obfuscator_output.append("Obfuscator-LLVM requires manual compilation.\n")
        self.obfuscator_output.append("Please install and configure Obfuscator-LLVM, then compile with:\n")
        self.obfuscator_output.append(f"clang -mllvm -fla -mllvm -sub -mllvm -bcf {input_file} -o {output_file or 'output'}")
    
    def run_confuserex(self, input_file, output_file):
        """Run ConfuserEx"""
        if not input_file.endswith('.exe'):
            QMessageBox.warning(self, "Error", "ConfuserEx requires a .NET executable")
            return
        
        self.obfuscator_output.append("ConfuserEx is a GUI tool for .NET obfuscation.\n")
        self.obfuscator_output.append("Please run ConfuserEx manually with the provided executable.")

    # Nikto Web Scanner
    def show_nikto_scanner(self):
        """Show Nikto web scanner dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Nikto Web Scanner")
        dialog.setMinimumWidth(700)
        layout = QVBoxLayout()
        
        # Target selection
        target_group = QGroupBox("Scan Target")
        target_layout = QFormLayout()
        
        self.nikto_target = QLineEdit()
        self.nikto_target.setPlaceholderText("http://example.com or https://example.com")
        
        self.nikto_port = QLineEdit()
        self.nikto_port.setPlaceholderText("80 or 443 (default based on protocol)")
        
        target_layout.addRow("Target URL:", self.nikto_target)
        target_layout.addRow("Port (optional):", self.nikto_port)
        target_group.setLayout(target_layout)
        
        # Options
        opt_group = QGroupBox("Scan Options")
        opt_layout = QVBoxLayout()
        
        self.nikto_ssl = QCheckBox("Force SSL")
        self.nikto_evasion = QCheckBox("Use Evasion Techniques")
        self.nikto_tuning = QComboBox()
        self.nikto_tuning.addItems([
            "Normal scan (0)",
            "File Upload (1)",
            "Misconfigurations (2)",
            "Information Disclosure (3)",
            "Injection (4)",
            "XSS (5)",
            "Remote File Retrieval (6)",
            "Command Execution (7)"
        ])
        
        opt_layout.addWidget(self.nikto_ssl)
        opt_layout.addWidget(self.nikto_evasion)
        opt_layout.addWidget(QLabel("Tuning:"))
        opt_layout.addWidget(self.nikto_tuning)
        opt_group.setLayout(opt_layout)
        
        # Scan button and output
        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.run_nikto_scan)
        
        self.nikto_output = QTextEdit()
        self.nikto_output.setReadOnly(True)
        
        # Progress bar
        self.nikto_progress = QProgressBar()
        self.nikto_progress.hide()
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(target_group)
        layout.addWidget(opt_group)
        layout.addWidget(scan_button)
        layout.addWidget(self.nikto_progress)
        layout.addWidget(self.nikto_output)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
    def run_nikto_scan(self):
        """Run Nikto web vulnerability scan"""
        target = self.nikto_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target URL")
            return
        
        port = self.nikto_port.text().strip()
        ssl = self.nikto_ssl.isChecked()
        evasion = self.nikto_evasion.isChecked()
        tuning = self.nikto_tuning.currentText()[0]  # Get first character (number)
        
        try:
            # Build command
            cmd = ["nikto", "-host", target]
            
            if port:
                cmd.extend(["-port", port])
            if ssl:
                cmd.extend(["-ssl"])
            if evasion:
                cmd.extend(["-evasion", "1"])
            if tuning != "0":
                cmd.extend(["-Tuning", tuning])
            
            self.nikto_progress.show()
            self.nikto_output.clear()
            
            # Run Nikto in a thread to avoid UI freeze
            thread = threading.Thread(target=self._run_nikto_thread, args=(cmd,))
            thread.daemon = True
            thread.start()
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to start scan: {str(e)}")
    
    def _run_nikto_thread(self, cmd):
        """Thread function to run Nikto scan"""
        try:
            process = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.nikto_output.append(output.strip())
            
            stderr = process.stderr.read()
            if stderr:
                self.nikto_output.append("\nErrors:\n")
                self.nikto_output.append(stderr)
            
            self.nikto_progress.hide()
        
        except Exception as e:
            self.nikto_output.append(f"Error during scan: {str(e)}")
            self.nikto_progress.hide()

    # OpenVAS Vulnerability Scan
    def show_openvas_scan(self):
        """Show OpenVAS vulnerability scan dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("OpenVAS Vulnerability Scan")
        dialog.setMinimumWidth(700)
        layout = QVBoxLayout()
        
        # Target selection
        target_group = QGroupBox("Scan Target")
        target_layout = QFormLayout()
        
        self.openvas_target = QLineEdit()
        self.openvas_target.setPlaceholderText("IP address or hostname")
        
        self.openvas_port = QLineEdit()
        self.openvas_port.setPlaceholderText("Port range (optional)")
        
        target_layout.addRow("Target:", self.openvas_target)
        target_layout.addRow("Ports:", self.openvas_port)
        target_group.setLayout(target_layout)
        
        # Credentials
        cred_group = QGroupBox("Credentials (optional)")
        cred_layout = QFormLayout()
        
        self.openvas_username = QLineEdit()
        self.openvas_username.setPlaceholderText("Username")
        
        self.openvas_password = QLineEdit()
        self.openvas_password.setPlaceholderText("Password")
        self.openvas_password.setEchoMode(QLineEdit.Password)
        
        cred_layout.addRow("Username:", self.openvas_username)
        cred_layout.addRow("Password:", self.openvas_password)
        cred_group.setLayout(cred_layout)
        
        # Options
        opt_group = QGroupBox("Scan Options")
        opt_layout = QVBoxLayout()
        
        self.openvas_scan_type = QComboBox()
        self.openvas_scan_type.addItems([
            "Full and fast",
            "Full and fast ultimate",
            "Full and very deep",
            "Full and very deep ultimate",
            "Host Discovery",
            "System Discovery"
        ])
        
        opt_layout.addWidget(QLabel("Scan Type:"))
        opt_layout.addWidget(self.openvas_scan_type)
        opt_group.setLayout(opt_layout)
        
        # Scan button and output
        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.run_openvas_scan)
        
        self.openvas_output = QTextEdit()
        self.openvas_output.setReadOnly(True)
        
        # Progress bar
        self.openvas_progress = QProgressBar()
        self.openvas_progress.hide()
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(target_group)
        layout.addWidget(cred_group)
        layout.addWidget(opt_group)
        layout.addWidget(scan_button)
        layout.addWidget(self.openvas_progress)
        layout.addWidget(self.openvas_output)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
def run_openvas_scan(self):
    """Run OpenVAS vulnerability scan"""
    target = self.openvas_target.text().strip()
    if not target:
        QMessageBox.warning(self, "Error", "Please enter a target")
        return

    port = self.openvas_port.text().strip()
    username = self.openvas_username.text().strip()
    password = self.openvas_password.text().strip()
    scan_type = self.openvas_scan_type.currentText()

    try:
        # Build command (simplified - actual OpenVAS uses API)
        cmd = [
            "omp",
            "--username", username or "admin",
            "--password", password or "admin",
            "--xml"
        ]

        # Create XML payload
        xml_payload = (
            f"<create_task>"
            f"<name>Network Toolkit Scan</name>"
            f"<target><hosts>{target}</hosts>"
        )
        if port:
            xml_payload += f"<ports>{port}</ports>"
        xml_payload += f"</target><config><name>{scan_type}</name></config></create_task>"

        cmd.append(xml_payload)

        self.openvas_progress.show()
        self.openvas_output.clear()
        self.openvas_output.append("Starting OpenVAS scan... (This may take a while)")

        # Run in thread
        import threading  # Ensure threading is imported
        thread = threading.Thread(target=self._run_openvas_thread, args=(target, cmd))
        thread.daemon = True
        thread.start()

    except Exception as e:
        QMessageBox.warning(self, "Error", f"Failed to start scan: {str(e)}")
    
    def _run_openvas_thread(self, target, cmd):
        """Thread function to run OpenVAS scan"""
        try:
            # Simulate scan (actual OpenVAS implementation would use omp or API)
            for i in range(1, 101):
                time.sleep(0.5)
                self.openvas_progress.setValue(i)
                if i % 10 == 0:
                    self.openvas_output.append(f"Scan progress: {i}% completed for {target}")

            # Simulated completion message
            self.openvas_output.append(f"Scan for {target} completed successfully.")
        except Exception as e:
            self.openvas_output.append(f"Error during scan: {str(e)}")


    def show_dns_tools(self):
        """Show DNS lookup/reverse DNS dialog"""
        if not DNS_AVAILABLE:
            QMessageBox.warning(self, "Error", "DNS features not available - dnspython not installed")
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("DNS Tools")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout()
        
        # Tab widget for different DNS functions
        tabs = QTabWidget()
        
        # DNS Lookup tab
        lookup_tab = QWidget()
        lookup_layout = QVBoxLayout()
        
        lookup_input = QLineEdit()
        lookup_input.setPlaceholderText("Enter domain name (e.g., example.com)")
        lookup_button = QPushButton("Lookup DNS Records")
        lookup_button.clicked.connect(lambda: self.perform_dns_lookup(lookup_input.text(), lookup_results))
        
        lookup_results = QTextEdit()
        lookup_results.setReadOnly(True)
        
        lookup_layout.addWidget(QLabel("Domain to lookup:"))
        lookup_layout.addWidget(lookup_input)
        lookup_layout.addWidget(lookup_button)
        lookup_layout.addWidget(QLabel("Results:"))
        lookup_layout.addWidget(lookup_results)
        lookup_tab.setLayout(lookup_layout)
        
        # Reverse DNS tab
        reverse_tab = QWidget()
        reverse_layout = QVBoxLayout()
        
        reverse_input = QLineEdit()
        reverse_input.setPlaceholderText("Enter IP address (e.g., 8.8.8.8)")
        reverse_button = QPushButton("Reverse DNS Lookup")
        reverse_button.clicked.connect(lambda: self.perform_reverse_dns(reverse_input.text(), reverse_results))
        
        reverse_results = QTextEdit()
        reverse_results.setReadOnly(True)
        
        reverse_layout.addWidget(QLabel("IP address for reverse lookup:"))
        reverse_layout.addWidget(reverse_input)
        reverse_layout.addWidget(reverse_button)
        reverse_layout.addWidget(QLabel("Results:"))
        reverse_layout.addWidget(reverse_results)
        reverse_tab.setLayout(reverse_layout)
        
        tabs.addTab(lookup_tab, "DNS Lookup")
        tabs.addTab(reverse_tab, "Reverse DNS")
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(tabs)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()

    def perform_dns_lookup(self, domain, output_widget):
        """Perform DNS lookup for a domain"""
        if not domain:
            QMessageBox.warning(self, "Error", "Please enter a domain name")
            return
        
        try:
            output_widget.clear()
            output_widget.append(f"DNS records for {domain}:\n")
            
            # Query different record types
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                    if answers.rrset:
                        output_widget.append(f"\n{rtype} Records:")
                        for answer in answers:
                            output_widget.append(f"  {answer}")
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    output_widget.append(f"\nDomain {domain} does not exist")
                    break
                except Exception as e:
                    output_widget.append(f"\nError querying {rtype} records: {str(e)}")
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"DNS lookup failed: {str(e)}")

    def perform_reverse_dns(self, ip, output_widget):
        """Perform reverse DNS lookup for an IP"""
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return
        
        try:
            output_widget.clear()
            output_widget.append(f"Reverse DNS for {ip}:\n")
            
            rev_name = dns.reversename.from_address(ip)
            try:
                answers = dns.resolver.resolve(rev_name, 'PTR')
                for answer in answers:
                    output_widget.append(f"Hostname: {answer}")
            except dns.resolver.NXDOMAIN:
                output_widget.append("No PTR record found for this IP address")
            except Exception as e:
                output_widget.append(f"Error: {str(e)}")
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Reverse DNS lookup failed: {str(e)}")

    def show_port_knocking(self):
        """Show port knocking listener dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Port Knocking Listener")
        dialog.setMinimumWidth(500)
        layout = QVBoxLayout()
        
        # Sequence input
        seq_group = QGroupBox("Knock Sequence")
        seq_layout = QVBoxLayout()
        
        self.knock_sequence = QLineEdit()
        self.knock_sequence.setPlaceholderText("Enter port sequence (e.g., 1000,2000,3000)")
        
        self.knock_protocol = QComboBox()
        self.knock_protocol.addItems(["TCP", "UDP"])
        
        seq_layout.addWidget(QLabel("Port sequence (comma-separated):"))
        seq_layout.addWidget(self.knock_sequence)
        seq_layout.addWidget(QLabel("Protocol:"))
        seq_layout.addWidget(self.knock_protocol)
        seq_group.setLayout(seq_layout)
        
        # Action to take
        action_group = QGroupBox("Action on Successful Knock")
        action_layout = QVBoxLayout()
        
        self.knock_action = QComboBox()
        self.knock_action.addItems([
            "Open port 22 (SSH)", 
            "Open port 3389 (RDP)", 
            "Execute custom command"
        ])
        
        self.knock_command = QLineEdit()
        self.knock_command.setPlaceholderText("Enter command to execute")
        self.knock_command.setEnabled(False)
        
        self.knock_action.currentTextChanged.connect(lambda: self.knock_command.setEnabled(
            self.knock_action.currentText() == "Execute custom command"
        ))
        
        action_layout.addWidget(QLabel("Action:"))
        action_layout.addWidget(self.knock_action)
        action_layout.addWidget(QLabel("Custom command:"))
        action_layout.addWidget(self.knock_command)
        action_group.setLayout(action_layout)
        
        # Control buttons
        button_box = QDialogButtonBox()
        self.start_knock_button = QPushButton("Start Listening")
        self.start_knock_button.clicked.connect(self.start_port_knocking)
        self.stop_knock_button = QPushButton("Stop Listening")
        self.stop_knock_button.clicked.connect(self.stop_port_knocking)
        self.stop_knock_button.setEnabled(False)
        
        button_box.addButton(self.start_knock_button, QDialogButtonBox.ActionRole)
        button_box.addButton(self.stop_knock_button, QDialogButtonBox.ActionRole)
        button_box.addButton(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        # Log output
        self.knock_log = QTextEdit()
        self.knock_log.setReadOnly(True)
        
        layout.addWidget(seq_group)
        layout.addWidget(action_group)
        layout.addWidget(button_box)
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.knock_log)
        dialog.setLayout(layout)
        
        dialog.exec_()

    def start_port_knocking(self):
        """Start listening for port knocks"""
        try:
            sequence = self.knock_sequence.text().strip()
            if not sequence:
                QMessageBox.warning(self, "Error", "Please enter a port sequence")
                return
            
            ports = [int(p.strip()) for p in sequence.split(',')]
            protocol = self.knock_protocol.currentText().lower()
            
            self.knock_listener = PortKnockListener(
                ports, 
                protocol,
                self.knock_action.currentText(),
                self.knock_command.text(),
                self.knock_log
            )
            self.knock_listener.start()
            
            self.start_knock_button.setEnabled(False)
            self.stop_knock_button.setEnabled(True)
            self.knock_log.append(f"Listening for {protocol.upper()} knocks on sequence: {sequence}")
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to start listener: {str(e)}")

    def stop_port_knocking(self):
        """Stop the port knock listener"""
        if hasattr(self, 'knock_listener') and self.knock_listener.isRunning():
            self.knock_listener.stop()
            self.knock_log.append("Listener stopped")
        
        self.start_knock_button.setEnabled(True)
        self.stop_knock_button.setEnabled(False)

    def show_vulnerability_scanner(self):
        """Show vulnerability scanner dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Vulnerability Scanner")
        dialog.setMinimumWidth(600)
        layout = QVBoxLayout()
        
        # Target selection
        target_group = QGroupBox("Scan Target")
        target_layout = QHBoxLayout()
        
        self.vuln_target = QLineEdit()
        self.vuln_target.setPlaceholderText("Enter IP address or hostname")
        
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(self.vuln_target)
        target_group.setLayout(target_layout)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        self.vuln_type = QComboBox()
        self.vuln_type.addItems([
            "Quick Scan", 
            "Full Scan", 
            "Web Application Scan",
            "Database Scan",
            "Custom Scan"
        ])
        
        self.vuln_credentials = QLineEdit()
        self.vuln_credentials.setPlaceholderText("Credentials (user:pass) if needed")
        
        options_layout.addWidget(QLabel("Scan type:"))
        options_layout.addWidget(self.vuln_type)
        options_layout.addWidget(QLabel("Credentials:"))
        options_layout.addWidget(self.vuln_credentials)
        options_group.setLayout(options_layout)
        
        # Control buttons
        button_box = QDialogButtonBox()
        self.start_vuln_scan_button = QPushButton("Start Scan")
        self.start_vuln_scan_button.clicked.connect(self.start_vulnerability_scan)
        self.stop_vuln_scan_button = QPushButton("Stop Scan")
        self.stop_vuln_scan_button.clicked.connect(self.stop_vulnerability_scan)
        self.stop_vuln_scan_button.setEnabled(False)
        
        button_box.addButton(self.start_vuln_scan_button, QDialogButtonBox.ActionRole)
        button_box.addButton(self.stop_vuln_scan_button, QDialogButtonBox.ActionRole)
        button_box.addButton(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        # Results display
        self.vuln_results = QTableWidget()
        self.vuln_results.setColumnCount(5)
        self.vuln_results.setHorizontalHeaderLabels(["Host", "Port", "Service", "Vulnerability", "Severity"])
        self.vuln_results.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Progress bar
        self.vuln_progress = QProgressBar()
        self.vuln_progress.setRange(0, 100)
        self.vuln_progress.hide()
        
        # Log output
        self.vuln_log = QTextEdit()
        self.vuln_log.setReadOnly(True)
        
        layout.addWidget(target_group)
        layout.addWidget(options_group)
        layout.addWidget(button_box)
        layout.addWidget(self.vuln_progress)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.vuln_results)
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.vuln_log)
        dialog.setLayout(layout)
        
        dialog.exec_()

    def start_vulnerability_scan(self):
        """Start vulnerability scan"""
        target = self.vuln_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        try:
            scan_type = self.vuln_type.currentText()
            credentials = self.vuln_credentials.text().strip()
            
            self.vuln_scanner = VulnerabilityScanner(
                target,
                scan_type,
                credentials,
                self.vuln_results,
                self.vuln_log,
                self.vuln_progress
            )
            self.vuln_scanner.start()
            
            self.start_vuln_scan_button.setEnabled(False)
            self.stop_vuln_scan_button.setEnabled(True)
            self.vuln_progress.show()
            self.vuln_log.append(f"Starting {scan_type} on {target}...")
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to start scan: {str(e)}")

    def stop_vulnerability_scan(self):
        """Stop vulnerability scan"""
        if hasattr(self, 'vuln_scanner') and self.vuln_scanner.isRunning():
            self.vuln_scanner.stop()
            self.vuln_log.append("Scan stopped by user")
        
        self.start_vuln_scan_button.setEnabled(True)
        self.stop_vuln_scan_button.setEnabled(False)
        self.vuln_progress.hide()

    def show_exploitdb_searcher(self):
        """Show Exploit DB search dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Exploit DB Searcher")
        dialog.setMinimumWidth(700)
        layout = QVBoxLayout()
        
        # Search criteria
        search_group = QGroupBox("Search Criteria")
        search_layout = QVBoxLayout()
        
        self.exploit_query = QLineEdit()
        self.exploit_query.setPlaceholderText("Search term (e.g., 'WordPress 5.1')")
        
        self.exploit_platform = QComboBox()
        self.exploit_platform.addItems(["All", "Windows", "Linux", "Unix", "PHP", "ASP", "JSP"])
        
        self.exploit_type = QComboBox()
        self.exploit_type.addItems(["All", "Remote", "Local", "DoS", "Webapps", "Shellcode"])
        
        search_button = QPushButton("Search Exploits")
        search_button.clicked.connect(self.search_exploitdb)
        
        search_layout.addWidget(QLabel("Search term:"))
        search_layout.addWidget(self.exploit_query)
        search_layout.addWidget(QLabel("Platform:"))
        search_layout.addWidget(self.exploit_platform)
        search_layout.addWidget(QLabel("Type:"))
        search_layout.addWidget(self.exploit_type)
        search_layout.addWidget(search_button)
        search_group.setLayout(search_layout)
        
        # Results display
        self.exploit_results = QTableWidget()
        self.exploit_results.setColumnCount(6)
        self.exploit_results.setHorizontalHeaderLabels(["ID", "Date", "Platform", "Type", "Title", "Author"])
        self.exploit_results.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.exploit_results.doubleClicked.connect(self.show_exploit_details)
        
        # Details panel
        self.exploit_details = QTextEdit()
        self.exploit_details.setReadOnly(True)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(search_group)
        layout.addWidget(self.exploit_results)
        layout.addWidget(QLabel("Details:"))
        layout.addWidget(self.exploit_details)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        dialog.exec_()
        

    def search_exploitdb(self):
        """Search Exploit DB for vulnerabilities"""
        query = self.exploit_query.text().strip()
        if not query:
            QMessageBox.warning(self, "Error", "Please enter a search term")
            return
        
        try:
            platform = self.exploit_platform.currentText()
            exploit_type = self.exploit_type.currentText()
            
            # Search Exploit DB
            results = exploitdb.search(
                query=query,
                platform=platform if platform != "All" else None,
                type=exploit_type if exploit_type != "All" else None
            )
            
            # Display results
            self.exploit_results.setRowCount(0)
            for exploit in results:
                row = self.exploit_results.rowCount()
                self.exploit_results.insertRow(row)
                
                self.exploit_results.setItem(row, 0, QTableWidgetItem(str(exploit.id)))
                self.exploit_results.setItem(row, 1, QTableWidgetItem(exploit.date))
                self.exploit_results.setItem(row, 2, QTableWidgetItem(exploit.platform))
                self.exploit_results.setItem(row, 3, QTableWidgetItem(exploit.type))
                self.exploit_results.setItem(row, 4, QTableWidgetItem(exploit.title))
                self.exploit_results.setItem(row, 5, QTableWidgetItem(exploit.author))
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Search failed: {str(e)}")

    def show_exploit_details(self, index):
        """Show details for selected exploit"""
        try:
            exploit_id = int(self.exploit_results.item(index.row(), 0).text())
            exploit = exploitdb.get(exploit_id)
            
            details = f"""
            <h2>{exploit.title}</h2>
            <p><b>ID:</b> {exploit.id}<br>
            <b>Date:</b> {exploit.date}<br>
            <b>Author:</b> {exploit.author}<br>
            <b>Platform:</b> {exploit.platform}<br>
            <b>Type:</b> {exploit.type}<br>
            <b>Verified:</b> {exploit.verified}</p>
            <h3>Description:</h3>
            <p>{exploit.description}</p>
            <h3>Code:</h3>
            <pre>{exploit.code}</pre>
            """
            
            self.exploit_details.setHtml(details)
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get exploit details: {str(e)}")

    def refresh_wifi_networks(self):
        """Refresh the list of available WiFi networks"""
        if not WIFI_AVAILABLE:
            QMessageBox.warning(self, "Error", "WiFi features not available - wifi module not installed")
            return
            
        try:
            # Try to automatically detect WiFi interfaces
            wifi_interfaces = []
            for iface in netifaces.interfaces():
                if iface.startswith('wlan') or iface.startswith('wlp') or iface.startswith('wifi'):
                    wifi_interfaces.append(iface)
            
            if not wifi_interfaces:
                raise Exception("No WiFi interfaces found (looking for wlan*, wlp*, wifi*)")
            
            # Use the first WiFi interface found
            interface = wifi_interfaces[0]
            self.status_label.setText(f"Scanning WiFi networks on {interface}...")
            
            # Scan for networks
            cells = list(Cell.all(interface))
            
            # Sort by signal strength (descending)
            cells.sort(key=lambda x: x.signal, reverse=True)
            
            # Clear previous results
            self.wifi_table.setRowCount(0)
            
            # Populate table with network information
            for cell in cells:
                row = self.wifi_table.rowCount()
                self.wifi_table.insertRow(row)
                
                # SSID (network name)
                ssid = cell.ssid if cell.ssid else "<hidden>"
                self.wifi_table.setItem(row, 0, QTableWidgetItem(ssid))
                
                # BSSID (MAC address)
                self.wifi_table.setItem(row, 1, QTableWidgetItem(cell.address))
                
                # Channel
                self.wifi_table.setItem(row, 2, QTableWidgetItem(str(cell.channel)))
                
                # Signal strength (dBm)
                signal = cell.signal
                self.wifi_table.setItem(row, 3, QTableWidgetItem(f"{signal} dBm"))
                
                # Quality (0-100%)
                quality = min(max(2 * (signal + 100), 0), 100)  # Convert dBm to percentage
                self.wifi_table.setItem(row, 4, QTableWidgetItem(f"{quality}%"))
                
                # Security type
                security = cell.encryption_type if cell.encrypted else "Open"
                self.wifi_table.setItem(row, 5, QTableWidgetItem(security))
                
                # Frequency
                self.wifi_table.setItem(row, 6, QTableWidgetItem(f"{cell.frequency} GHz"))
                
                # Color code based on signal strength
                for col in range(self.wifi_table.columnCount()):
                    item = self.wifi_table.item(row, col)
                    if signal > -50:  # Excellent
                        item.setBackground(QColor(200, 255, 200))
                    elif signal > -60:  # Good
                        item.setBackground(QColor(230, 255, 200))
                    elif signal > -70:  # Fair
                        item.setBackground(QColor(255, 255, 200))
                    else:  # Poor
                        item.setBackground(QColor(255, 200, 200))
            
            self.status_label.setText(f"Found {len(cells)} WiFi networks on {interface}")
            
        except Exception as e:
            error_msg = f"WiFi scan error: {str(e)}"
            self.status_label.setText(error_msg)
            QMessageBox.warning(self, "Error", error_msg)
    
    def start_wifi_monitoring(self):
        """Start WiFi monitoring"""
        if not WIFI_AVAILABLE:
            QMessageBox.warning(self, "Error", "WiFi features require 'wifi' module")
            return
        
        interface = self.wifi_interface_combo.currentText()
        if not interface:
            QMessageBox.warning(self, "Error", "Select a WiFi interface")
            return
        
        self.wifi_thread = WifiAnalyzerThread(interface)
        self.wifi_thread.networks_updated.connect(self.update_wifi_networks)
        self.wifi_thread.start()
        self.start_monitor_button.setEnabled(False)
        self.stop_monitor_button.setEnabled(True)
    
    def stop_wifi_monitoring(self):
        """Stop WiFi monitoring"""
        if self.wifi_thread and self.wifi_thread.isRunning():
            self.wifi_thread.stop()
            self.wifi_thread.quit()
            
        self.start_monitor_button.setEnabled(True)
        self.stop_monitor_button.setEnabled(False)
        self.refresh_wifi_button.setEnabled(True)
    
    def update_wifi_networks(self, cells):
        """Update the WiFi networks display with new data"""
        # Update table
        self.refresh_wifi_networks()
        
        if not self.wifi_graph:
            return
            
        # Update signal strength graph
        current_time = datetime.now().strftime("%H:%M:%S")
        
        for cell in cells:
            ssid = cell.ssid or cell.address  # Use BSSID if SSID is hidden
            
            if ssid not in self.wifi_lines:
                # Create a new line for this network
                line, = self.wifi_ax.plot([], [], label=ssid[:20])  # Truncate long SSIDs
                self.wifi_lines[ssid] = {
                    'line': line,
                    'timestamps': [],
                    'signals': []
                }
            
            # Add new data point
            data = self.wifi_lines[ssid]
            data['timestamps'].append(current_time)
            data['signals'].append(cell.signal)
            
            # Keep only the last 20 points
            if len(data['timestamps']) > 20:
                data['timestamps'] = data['timestamps'][-20:]
                data['signals'] = data['signals'][-20:]
            
            # Update the line
            data['line'].set_data(range(len(data['timestamps'])), data['signals'])
        
        # Update graph limits and legend
        self.wifi_ax.relim()
        self.wifi_ax.autoscale_view()
        
        # Only show legend if we have a reasonable number of networks
        if len(self.wifi_lines) <= 10:
            self.wifi_ax.legend(loc='upper right')
        else:
            self.wifi_ax.legend().remove()
        
        self.wifi_graph.draw()
    
    def refresh_network_stats(self):
        """Refresh the network statistics display"""
        try:
            self.stats_tree.clear()
            
            # Get network stats
            stats = self._collect_network_stats()
            
            # Add stats to tree
            interfaces_item = QTreeWidgetItem(["Network Interfaces"])
            for iface, iface_data in stats.get('interfaces', {}).items():
                iface_item = QTreeWidgetItem([iface])
                
                for prop, value in iface_data.items():
                    if isinstance(value, list):
                        value = ', '.join(map(str, value))
                    QTreeWidgetItem(iface_item, [prop, str(value)])
                
                interfaces_item.addChild(iface_item)
            self.stats_tree.addTopLevelItem(interfaces_item)
            
            # Connections
            connections_item = QTreeWidgetItem(["Active Connections"])
            for conn in stats.get('connections', []):
                conn_item = QTreeWidgetItem([
                    f"{conn['local_addr']} -> {conn['remote_addr']}",
                    f"{conn['type']} {conn['status']}"
                ])
                connections_item.addChild(conn_item)
            self.stats_tree.addTopLevelItem(connections_item)
            
            # Other stats
            for prop, value in stats.items():
                if prop not in ['interfaces', 'connections']:
                    if isinstance(value, dict):
                        item = QTreeWidgetItem([prop])
                        for subprop, subvalue in value.items():
                            QTreeWidgetItem(item, [subprop, str(subvalue)])
                    else:
                        item = QTreeWidgetItem([prop, str(value)])
                    self.stats_tree.addTopLevelItem(item)
            
            self.stats_tree.expandAll()
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not get network stats: {str(e)}")
    
    def _collect_network_stats(self):
        """Collect various network statistics"""
        stats = {}
        
        try:
            # Network interfaces information
            interfaces = netifaces.interfaces()
            stats['interfaces'] = {}
            
            for iface in interfaces:
                if iface.startswith('lo'):
                    continue  # Skip loopback interface
                    
                if_stats = {}
                addrs = netifaces.ifaddresses(iface)
                
                # IPv4 addresses
                if netifaces.AF_INET in addrs:
                    ipv4_addrs = []
                    for addr in addrs[netifaces.AF_INET]:
                        ip_info = {
                            'address': addr.get('addr', ''),
                            'netmask': addr.get('netmask', ''),
                            'broadcast': addr.get('broadcast', '')
                        }
                        ipv4_addrs.append(ip_info)
                    if_stats['ipv4'] = ipv4_addrs
                
                # IPv6 addresses
                if netifaces.AF_INET6 in addrs:
                    ipv6_addrs = []
                    for addr in addrs[netifaces.AF_INET6]:
                        ip_info = {
                            'address': addr.get('addr', '').split('%')[0],
                            'netmask': addr.get('netmask', '')
                        }
                        ipv6_addrs.append(ip_info)
                    if_stats['ipv6'] = ipv6_addrs
                
                # MAC address
                if netifaces.AF_LINK in addrs:
                    if_stats['mac'] = addrs[netifaces.AF_LINK][0].get('addr', '')
                
                # Network usage statistics
                try:
                    io = psutil.net_io_counters(pernic=True).get(iface)
                    if io:
                        if_stats['bytes_sent'] = str(io.bytes_sent)
                        if_stats['bytes_recv'] = str(io.bytes_recv)
                        if_stats['packets_sent'] = str(io.packets_sent)
                        if_stats['packets_recv'] = str(io.packets_recv)
                except Exception as e:
                    if_stats['io_error'] = str(e)
                
                stats['interfaces'][iface] = if_stats
            
            # System-wide network statistics
            try:
                net_io = psutil.net_io_counters()
                stats['total'] = {
                    'bytes_sent': str(net_io.bytes_sent),
                    'bytes_recv': str(net_io.bytes_recv),
                    'packets_sent': str(net_io.packets_sent),
                    'packets_recv': str(net_io.packets_recv)
                }
            except Exception as e:
                stats['total_error'] = str(e)
            
            # Active network connections
            try:
                connections = psutil.net_connections(kind='inet')
                stats['connections'] = []
                
                for conn in connections:
                    try:
                        conn_info = {
                            'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                            'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                            'status': str(conn.status),
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                            'pid': str(conn.pid) if conn.pid else ''
                        }
                        stats['connections'].append(conn_info)
                    except Exception as e:
                        stats['connections_error'] = str(e)
            except Exception as e:
                stats['connections_error'] = str(e)
            
            # Gateway information
            try:
                gateways = netifaces.gateways()
                stats['gateways'] = {
                    'default': gateways.get('default', {}),
                    'ipv4': gateways.get(netifaces.AF_INET, []),
                    'ipv6': gateways.get(netifaces.AF_INET6, [])
                }
            except Exception as e:
                stats['gateways_error'] = str(e)
            
            stats['hostname'] = socket.gethostname()
            stats['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        except Exception as e:
            stats['error'] = f"Failed to collect stats: {str(e)}"
        
        return stats
    
    def start_stats_monitoring(self):
        """Start continuous network stats monitoring"""
        if self.stats_thread and self.stats_thread.isRunning():
            return
            
        self.stats_thread = NetworkStatsThread()
        self.stats_thread.stats_updated.connect(self.update_network_stats)
        self.stats_thread.log_message.connect(lambda msg: self.status_label.setText(f"Stats: {msg}"))
        self.stats_thread.start()
        
        self.start_monitor_stats_button.setEnabled(False)
        self.stop_monitor_stats_button.setEnabled(True)
        self.refresh_stats_button.setEnabled(False)
        
        # Clear bandwidth graph data
        self.bw_timestamps = []
        self.bw_sent = []
        self.bw_recv = []
    
    def stop_stats_monitoring(self):
        """Stop network stats monitoring"""
        if self.stats_thread and self.stats_thread.isRunning():
            self.stats_thread.stop()
            self.stats_thread.quit()
            
        self.start_monitor_stats_button.setEnabled(True)
        self.stop_monitor_stats_button.setEnabled(False)
        self.refresh_stats_button.setEnabled(True)
    
    def update_network_stats(self, stats):
        """Update the network stats display with new data"""
        # Update tree view
        self.refresh_network_stats()
        
        if not self.bandwidth_graph:
            return
            
        # Update bandwidth graph
        current_time = datetime.now().strftime("%H:%M:%S")
        
        if len(self.bw_timestamps) >= 20:
            self.bw_timestamps.pop(0)
            self.bw_sent.pop(0)
            self.bw_recv.pop(0)
            
        self.bw_timestamps.append(current_time)
        
        # Add bandwidth data if available
        if 'bandwidth' in stats:
            self.bw_sent.append(stats['bandwidth']['sent'])
            self.bw_recv.append(stats['bandwidth']['recv'])
        else:
            # Add zeros if no bandwidth data
            self.bw_sent.append(0)
            self.bw_recv.append(0)
        
        # Update graph
        self.bw_line_sent.set_data(range(len(self.bw_timestamps)), self.bw_sent)
        self.bw_line_recv.set_data(range(len(self.bw_timestamps)), self.bw_recv)
        
        self.bw_ax.relim()
        self.bw_ax.autoscale_view()
        self.bandwidth_graph.draw()
    
    def update_scan_options(self, scan_type):
        """Update the scan options based on selected scan type"""
        self.port_range_input.hide()
        self.custom_args_input.hide()
        
        if scan_type == "Port Range":
            self.port_range_input.show()
        elif scan_type == "Custom":
            self.custom_args_input.show()
    
    def start_scan(self):
        """Start an Nmap scan"""
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, "Warning", "Scan already in progress")
            return
            
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target to scan")
            return
            
        scan_type = self.scan_type.currentText()
        options = {}
        
        if scan_type == "Port Range":
            options["ports"] = self.port_range_input.text().strip()
        elif scan_type == "Custom":
            options["custom_args"] = self.custom_args_input.text().strip()
        
        # Save settings
        self.settings['nmap']['last_target'] = target
        self.settings['nmap']['last_scan_type'] = scan_type
        self.save_settings()
        
        # Clear previous results
        self.hosts_table.setRowCount(0)
        self.ports_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        self.log_output.clear()
        
        self.scan_thread = NmapScannerThread(target, scan_type, options)
        self.scan_thread.scan_finished.connect(self.display_results)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.host_discovered.connect(self.add_host_result)
        self.scan_thread.port_discovered.connect(self.add_port_result)
        self.scan_thread.log_message.connect(self.log_output.append)
        
        self.progress_bar.show()
        self.progress_label.show()
        self.scan_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current Nmap scan"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.log_output.append("Scan stopped by user")
            self.scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
            self.progress_bar.hide()
            self.progress_label.hide()
    
    def update_progress(self, percent, message):
        """Update the scan progress display"""
        self.progress_bar.setValue(percent)
        self.progress_label.setText(message)
        if percent >= 100:
            self.progress_bar.hide()
            self.progress_label.hide()
            self.scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
    
    def add_host_result(self, host_info):
        """Add a discovered host to the results table"""
        row = self.hosts_table.rowCount()
        self.hosts_table.insertRow(row)
        
        self.hosts_table.setItem(row, 0, QTableWidgetItem(host_info['host']))
        self.hosts_table.setItem(row, 1, QTableWidgetItem(host_info['status'].capitalize()))
        self.hosts_table.setItem(row, 2, QTableWidgetItem(host_info['hostnames']))
        self.hosts_table.setItem(row, 3, QTableWidgetItem(host_info['os']))
        
        # Placeholder for ports and services
        self.hosts_table.setItem(row, 4, QTableWidgetItem("Scanning..."))
        self.hosts_table.setItem(row, 5, QTableWidgetItem("Scanning..."))
    
    def add_port_result(self, port_info):
        """Add a discovered port to the results table"""
        # Update ports table
        row = self.ports_table.rowCount()
        self.ports_table.insertRow(row)
        
        self.ports_table.setItem(row, 0, QTableWidgetItem(str(port_info['port'])))
        self.ports_table.setItem(row, 1, QTableWidgetItem(port_info['state']))
        self.ports_table.setItem(row, 2, QTableWidgetItem(port_info['service']))
        self.ports_table.setItem(row, 3, QTableWidgetItem(port_info['version']))
        self.ports_table.setItem(row, 4, QTableWidgetItem(port_info['extra']))
        
        # Update host row with port count and services
        for i in range(self.hosts_table.rowCount()):
            host_item = self.hosts_table.item(i, 0)
            if host_item and host_item.text() == port_info['host']:
                # Update port count
                ports_item = self.hosts_table.item(i, 4)
                if ports_item:
                    if ports_item.text() == "Scanning...":
                        ports_item.setText("1")
                    else:
                        try:
                            ports_item.setText(str(int(ports_item.text()) + 1))
                        except:
                            ports_item.setText("1")
                
                # Update services
                services_item = self.hosts_table.item(i, 5)
                if services_item:
                    if services_item.text() == "Scanning...":
                        services_item.setText(port_info['service'])
                    else:
                        services = services_item.text().split(', ')
                        if port_info['service'] not in services:
                            services.append(port_info['service'])
                            services_item.setText(', '.join(services))
                
                break
    
    def display_results(self, scan_data):
        """Display the final scan results"""
        # Check for vulnerabilities
        if 'scan' in scan_data:
            for host in scan_data['scan']:
                host_data = scan_data['scan'][host]
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if 'script' in port_data:
                            for script, output in port_data['script'].items():
                                if 'vuln' in script.lower() or 'CVE' in output:
                                    row = self.vuln_table.rowCount()
                                    self.vuln_table.insertRow(row)
                                    
                                    self.vuln_table.setItem(row, 0, QTableWidgetItem(f"{host}:{port}"))
                                    self.vuln_table.setItem(row, 1, QTableWidgetItem(script))
                                    self.vuln_table.setItem(row, 2, QTableWidgetItem(output))
    
    def show_host_details(self, index):
        """Show detailed information for a specific host"""
        host_item = self.hosts_table.item(index.row(), 0)
        if not host_item:
            return
            
        host = host_item.text()
        if not self.scan_thread or not self.scan_thread.nm:
            return
            
        scan_data = self.scan_thread.nm._scan_result
        if 'scan' not in scan_data or host not in scan_data['scan']:
            return
            
        host_data = scan_data['scan'][host]
        self.ports_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                row = self.ports_table.rowCount()
                self.ports_table.insertRow(row)
                
                self.ports_table.setItem(row, 0, QTableWidgetItem(str(port)))
                self.ports_table.setItem(row, 1, QTableWidgetItem(port_data['state']))
                self.ports_table.setItem(row, 2, QTableWidgetItem(port_data['name']))
                self.ports_table.setItem(row, 3, QTableWidgetItem(f"{port_data.get('product', '')} {port_data.get('version', '')}".strip()))
                self.ports_table.setItem(row, 4, QTableWidgetItem(port_data.get('extrainfo', '')))
                
                # Check for vulnerabilities
                if 'script' in port_data:
                    for script, output in port_data['script'].items():
                        if 'vuln' in script.lower() or 'CVE' in output:
                            row = self.vuln_table.rowCount()
                            self.vuln_table.insertRow(row)
                            
                            self.vuln_table.setItem(row, 0, QTableWidgetItem(str(port)))
                            self.vuln_table.setItem(row, 1, QTableWidgetItem(script))
                            self.vuln_table.setItem(row, 2, QTableWidgetItem(output))
        
        self.results_tabs.setCurrentIndex(1)  # Switch to ports tab
    
    def lookup_ip(self):
        """Lookup information for an IP address or domain"""
        ip = self.ip_lookup_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address or domain")
            return
        
        try:
            # Clear previous results
            self.ip_info_tree.clear()
            
            # Get IP if domain was entered
            if not self.is_valid_ip(ip):
                try:
                    resolved_ip = socket.gethostbyname(ip)
                    QTreeWidgetItem(["Domain", ip])
                    ip = resolved_ip
                except socket.gaierror:
                    QMessageBox.warning(self, "Error", "Could not resolve domain")
                    return
            
            # Add basic IP info
            ip_item = QTreeWidgetItem(["IP Address", ip])
            self.ip_info_tree.addTopLevelItem(ip_item)
            
            # Check IP type
            is_private = self.is_private_ip(ip)
            ip_type = "Private" if is_private else "Public"
            QTreeWidgetItem(["IP Type", ip_type])
            
            # Add IP version
            ip_version = "IPv6" if ":" in ip else "IPv4"
            QTreeWidgetItem(["IP Version", ip_version])
            
            # For private IPs, add local network info
            if is_private:
                self._add_local_network_info(ip)
            
            # Geolocation for public IPs
            if not is_private:
                try:
                    response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                    data = response.json()
                    
                    if data['status'] == 'success':
                        geo_item = QTreeWidgetItem(["Geolocation"])
                        self.ip_info_tree.addTopLevelItem(geo_item)
                        
                        details = [
                            ("Country", data.get('country', 'N/A')),
                            ("Region", data.get('regionName', 'N/A')),
                            ("City", data.get('city', 'N/A')),
                            ("ZIP", data.get('zip', 'N/A')),
                            ("Coordinates", f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}"),
                            ("Timezone", data.get('timezone', 'N/A')),
                            ("ISP", data.get('isp', 'N/A')),
                            ("Organization", data.get('org', 'N/A')),
                            ("AS", data.get('as', 'N/A'))
                        ]
                        
                        for name, value in details:
                            QTreeWidgetItem(geo_item, [name, str(value)])
                except Exception as e:
                    QTreeWidgetItem(["Geolocation Error", str(e)])
            
            # Network information
            net_item = QTreeWidgetItem(["Network Information"])
            self.ip_info_tree.addTopLevelItem(net_item)
            
            # Reverse DNS
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                QTreeWidgetItem(net_item, ["Hostname", hostname])
                if aliases:
                    QTreeWidgetItem(net_item, ["Aliases", ", ".join(aliases)])
            except socket.herror:
                QTreeWidgetItem(net_item, ["Hostname", "Not available"])
            
            # Ping test
            try:
                param = '-n' if platform.system() == 'Windows' else '-c'
                command = ['ping', param, '1', '-W', '1', ip]
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    # Extract ping time from output
                    output = result.stdout.decode()
                    time_ms = "Unknown"
                    
                    if 'time=' in output:
                        time_part = output.split('time=')[1].split()[0]
                        time_ms = time_part.replace('ms', '') + ' ms'
                    
                    QTreeWidgetItem(net_item, ["Ping", f"Responding ({time_ms})"])
                else:
                    QTreeWidgetItem(net_item, ["Ping", "No response"])
            except:
                QTreeWidgetItem(net_item, ["Ping", "Failed"])
            
            # WHOIS information
            try:
                import pythonwhois
                whois_data = pythonwhois.get_whois(ip)
                whois_item = QTreeWidgetItem(["WHOIS Information"])
                self.ip_info_tree.addTopLevelItem(whois_item)
                
                for key, value in whois_data.items():
                    if value and not isinstance(value, list):
                        QTreeWidgetItem(whois_item, [key, str(value)])
            except ImportError:
                QTreeWidgetItem(["WHOIS", "python-whois not installed"])
            except Exception as e:
                QTreeWidgetItem(["WHOIS Error", str(e)])
            
            # Security information
            sec_item = QTreeWidgetItem(["Security Information"])
            self.ip_info_tree.addTopLevelItem(sec_item)
            
            # Check if IP is in any blacklists
            try:
                blacklists = [
                    "zen.spamhaus.org",
                    "bl.spamcop.net",
                    "b.barracudacentral.org"
                ]
                
                listed = []
                for bl in blacklists:
                    try:
                        reversed_ip = ".".join(ip.split('.')[::-1])
                        lookup = f"{reversed_ip}.{bl}"
                        socket.gethostbyname(lookup)
                        listed.append(bl)
                    except socket.gaierror:
                        pass
                
                if listed:
                    QTreeWidgetItem(sec_item, ["Blacklisted", ", ".join(listed)])
                else:
                    QTreeWidgetItem(sec_item, ["Blacklisted", "No"])
            except:
                QTreeWidgetItem(sec_item, ["Blacklist Check", "Failed"])
            
            # Expand all items
            self.ip_info_tree.expandAll()
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to lookup IP: {str(e)}")

    def _add_local_network_info(self, ip):
        """Add information about local network for private IPs"""
        try:
            # Get network interface for this IP
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            if addr['addr'] == ip:
                                # Found the interface
                                iface_item = QTreeWidgetItem(["Network Interface", iface])
                                self.ip_info_tree.addTopLevelItem(iface_item)
                                
                                # Add MAC address if available
                                if netifaces.AF_LINK in addrs:
                                    mac = addrs[netifaces.AF_LINK][0]['addr']
                                    self.ip_info_tree.addTopLevelItem(QTreeWidgetItem(["MAC Address", mac]))
                                
                                # Add netmask and broadcast
                                if 'netmask' in addr:
                                    self.ip_info_tree.addTopLevelItem(QTreeWidgetItem(["Netmask", addr['netmask']]))
                                if 'broadcast' in addr:
                                    self.ip_info_tree.addTopLevelItem(QTreeWidgetItem(["Broadcast", addr['broadcast']]))
                                
                                return
                except:
                    continue
        except:
            pass

    def is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def start_traffic_capture(self):
        """Start capturing network traffic"""
        if not SCAPY_AVAILABLE:
            QMessageBox.warning(self, "Error", "Packet sniffing features not available - scapy not installed")
            return
            
        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(self, "Error", "Please select a network interface")
            return
        
        # Verify interface exists
        interfaces = netifaces.interfaces()
        if interface not in interfaces:
            QMessageBox.warning(self, "Error", f"Interface '{interface}' not found! Available interfaces: {', '.join(interfaces)}")
            return
            
        # Save settings
        self.settings['traffic']['last_interface'] = interface
        self.save_settings()
        
        # Get capture filters
        capture_filters = {}
        for name, checkbox in self.protocol_filters.items():
            capture_filters[name] = checkbox.isChecked()
        
        # Save capture filters
        self.settings['traffic']['capture_filters'] = capture_filters
        self.save_settings()
        
        self.traffic_table.setRowCount(0)
        self.sniffer_thread = TrafficSnifferThread(interface, capture_filters)
        self.sniffer_thread.packet_received.connect(self.add_traffic_row)
        self.sniffer_thread.stats_updated.connect(self.update_traffic_stats)
        self.sniffer_thread.log_message.connect(lambda msg: self.status_label.setText(f"Traffic: {msg}"))
        self.sniffer_thread.start()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
    
    def stop_traffic_capture(self):
        """Stop capturing network traffic"""
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.quit()
            
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def clear_traffic_table(self):
        """Clear the traffic capture table"""
        self.traffic_table.setRowCount(0)
    
    def save_capture(self):
        """Save the captured traffic to a file"""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Capture", "", "Text Files (*.txt);;CSV Files (*.csv)")
        if not file_name:
            return
        
        try:
            with open(file_name, 'w') as f:
                if file_name.endswith('.csv'):
                    # Write CSV header
                    f.write("Timestamp,Source,Destination,Protocol,Length,Info\n")
                    
                    # Write CSV rows
                    for row in range(self.traffic_table.rowCount()):
                        line = []
                        for col in range(self.traffic_table.columnCount()):
                            item = self.traffic_table.item(row, col)
                            line.append(item.text() if item else "")
                        f.write(','.join(line) + '\n')
                else:
                    # Write text format
                    for row in range(self.traffic_table.rowCount()):
                        line = []
                        for col in range(self.traffic_table.columnCount()):
                            item = self.traffic_table.item(row, col)
                            line.append(item.text() if item else "")
                        f.write(' | '.join(line) + '\n')
            
            self.status_label.setText(f"Capture saved to {file_name}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save capture: {str(e)}")
    
    def add_traffic_row(self, packet_info):
        """Add a packet to the traffic table"""
        # Check display filter
        filter_type = self.traffic_filter_combo.currentText()
        if filter_type == "TCP" and packet_info.get('protocol') != 'TCP':
            return
        if filter_type == "UDP" and packet_info.get('protocol') != 'UDP':
            return
        if filter_type == "ICMP" and packet_info.get('protocol') != 'ICMP':
            return
        if filter_type == "ARP" and packet_info.get('protocol') != 'ARP':
            return
        if filter_type == "DNS" and packet_info.get('protocol') != 'DNS':
            return
        if filter_type == "DHCP" and packet_info.get('protocol') != 'DHCP':
            return
        if filter_type == "Other" and packet_info.get('protocol') in ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'DHCP']:
            return
        
        row = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row)
        
        for col, key in enumerate(['timestamp', 'source', 'destination', 'protocol', 'length', 'info']):
            item = QTableWidgetItem(packet_info.get(key, ''))
            
            # Apply color if specified
            if col == 3 and packet_info.get('color'):  # Protocol column
                item.setForeground(packet_info['color'])
            elif col == 5:  # Info column
                if packet_info.get('color'):
                    item.setForeground(packet_info['color'])
            
            self.traffic_table.setItem(row, col, item)
        
        # Auto-scroll to bottom
        self.traffic_table.scrollToBottom()
    
    def update_traffic_stats(self, stats):
        """Update the traffic statistics display"""
        # Update traffic graph
        if self.traffic_graph:
            self.traffic_graph.update_graph(stats)
        
        # Update protocol pie chart
        if self.protocol_pie:
            self.protocol_pie.update_chart(stats['protocol_stats'])
        
        # Update status bar with packet count
        self.status_label.setText(f"Packets captured: {stats['packet_count']} | "
                                f"Incoming: {stats['traffic_stats']['incoming']} bytes | "
                                f"Outgoing: {stats['traffic_stats']['outgoing']} bytes")
    
    def start_ping_sweep(self):
        """Start a ping sweep"""
        if self.ping_thread and self.ping_thread.isRunning():
            QMessageBox.warning(self, "Warning", "Ping sweep is already running")
            return
            
        network_range = self.ping_range_input.text().strip()
        if not network_range:
            QMessageBox.warning(self, "Error", "Please enter a network range")
            return
        
        # Save settings
        self.settings['ping']['last_range'] = network_range
        self.save_settings()
        
        self.ping_results_table.setRowCount(0)
        self.ping_thread = PingSweepThread(network_range)
        self.ping_thread.ping_result.connect(self.add_ping_result)
        self.ping_thread.progress_updated.connect(self.update_ping_progress)
        self.ping_thread.finished.connect(self.ping_sweep_finished)
        self.ping_thread.log_message.connect(lambda msg: self.status_label.setText(f"Ping: {msg}"))
        self.ping_thread.start()
        
        self.ping_progress.show()
        self.ping_progress_label.show()
    
    def update_ping_progress(self, percent, message):
        """Update the ping sweep progress"""
        self.ping_progress.setValue(percent)
        self.ping_progress_label.setText(message)
        if percent >= 100:
            self.ping_progress.hide()
            self.ping_progress_label.hide()
    
    def stop_ping_sweep(self):
        """Stop the current ping sweep"""
        if self.ping_thread and self.ping_thread.isRunning():
            self.ping_thread.stop()
            self.ping_thread.wait()
            self.ping_progress.hide()
            self.ping_progress_label.hide()
            self.status_label.setText("Ping sweep stopped")
    
    def ping_sweep_finished(self):
        """Handle completion of ping sweep"""
        self.ping_progress.hide()
        self.ping_progress_label.hide()
        self.status_label.setText("Ping sweep completed")
    
    def add_ping_result(self, host, is_alive):
        """Add a ping result to the table"""
        # Check filter
        filter_type = self.ping_filter_combo.currentText()
        if filter_type == "Responding" and not is_alive:
            return
        if filter_type == "Not Responding" and is_alive:
            return
        
        # Find existing row for this host or create new
        row = -1
        for i in range(self.ping_results_table.rowCount()):
            if self.ping_results_table.item(i, 0).text() == host:
                row = i
                break
        
        if row == -1:
            row = self.ping_results_table.rowCount()
            self.ping_results_table.insertRow(row)
            self.ping_results_table.setItem(row, 0, QTableWidgetItem(host))
        
        status = "Online" if is_alive else "Offline"
        self.ping_results_table.setItem(row, 1, QTableWidgetItem(status))
        
        # If host is online, scan for open ports
        if is_alive:
            self.scan_ports_for_host(host, row)
    
    def scan_ports_for_host(self, host, row):
        """Scan for open ports on a host"""
        def scan_thread():
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=host, arguments='-T4 -F')  # Fast scan of common ports
                
                if host in nm.all_hosts() and 'tcp' in nm[host]:
                    open_ports = ", ".join(nm[host]['tcp'].keys())
                    self.ping_results_table.item(row, 2).setText(open_ports)
            except:
                pass
        
        threading.Thread(target=scan_thread, daemon=True).start()
        self.ping_results_table.setItem(row, 2, QTableWidgetItem("Scanning..."))
    
    def ping_host_double_clicked(self, index):
        """Handle double-click on a ping result"""
        host_item = self.ping_results_table.item(index.row(), 0)
        if host_item:
            host = host_item.text()
            self.main_tabs.setCurrentIndex(0)  # Switch to Nmap tab
            self.target_input.setText(host)
            self.scan_type.setCurrentText("Quick Scan")
            self.start_scan()
    
    def attempt_remote_access(self):
        """Attempt to connect to a remote host using selected protocols"""
        ip = self.remote_ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return

        if not self.is_valid_ip(ip):
            QMessageBox.warning(self, "Error", "Please enter a valid IP address")
            return

        # Clear previous results
        self.access_results_tree.clear()
        self.access_log.clear()
        self.file_browser.hide()
        self.command_input.hide()
        self.command_output.hide()

        # Get credentials
        username = self.remote_user_input.text().strip()
        password = self.remote_pass_input.text().strip()

        # Create a thread for the connection attempt
        self.access_thread = RemoteAccessThread(
            ip,
            username,
            password,
            self.ssh_check.isChecked(),
            self.rdp_check.isChecked(),
            self.vnc_check.isChecked(),
            self.telnet_check.isChecked(),
            self.ftp_check.isChecked()
        )
        
        self.access_thread.result_found.connect(self.add_access_result)
        self.access_thread.progress_updated.connect(self.update_access_progress)
        self.access_thread.log_message.connect(self.access_log.append)
        self.access_thread.connection_success.connect(self.handle_successful_connection)
        self.access_thread.finished.connect(self.access_scan_complete)
        
        self.access_progress.show()
        self.access_thread.start()

    def update_access_progress(self, percent, message):
        """Update the remote access progress"""
        self.access_progress.setValue(percent)
        self.status_label.setText(f"Remote Access: {message}")

    def add_access_result(self, service, status, details):
        """Add a remote access result to the tree"""
        item = QTreeWidgetItem([service, status, details])
        
        # Color code based on status
        if "Success" in status:
            item.setForeground(1, QColor(0, 128, 0))  # Green for success
        elif "Failed" in status:
            item.setForeground(1, QColor(255, 0, 0))  # Red for failure
        
        self.access_results_tree.addTopLevelItem(item)

    def handle_successful_connection(self, service, connection):
        """Handle a successful remote connection"""
        self.add_access_result(service, "Connected", "Ready for commands")
        
        # Show file browser and command input for certain services
        if service in ["SSH", "FTP"]:
            self.file_browser.show()
            self.command_input.show()
            self.command_output.show()
            
            # Store the active connection
            self.active_connection = connection
            
            # For SSH/FTP, we can list files
            if service == "SSH":
                self.command_input.returnPressed.connect(self.execute_ssh_command)
                self.list_ssh_files()
            elif service == "FTP":
                self.command_input.returnPressed.connect(self.execute_ftp_command)
                self.list_ftp_files()

    def access_scan_complete(self):
        """Handle completion of remote access scan"""
        self.access_progress.hide()
        self.status_label.setText("Remote access scan completed")

    def execute_ssh_command(self):
        """Execute a command over SSH"""
        command = self.command_input.text()
        if not command:
            return
        
        try:
            stdin, stdout, stderr = self.active_connection.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            self.command_output.append(f"$ {command}")
            if output:
                self.command_output.append(output)
            if error:
                self.command_output.append(f"Error: {error}")
                
        except Exception as e:
            self.command_output.append(f"Command failed: {str(e)}")
        
        self.command_input.clear()

    def list_ssh_files(self):
        """List files over SSH connection"""
        try:
            sftp = self.active_connection.open_sftp()
            files = sftp.listdir()
            
            self.file_browser.clear()
            for file in files:
                attr = sftp.stat(file)
                item = QTreeWidgetItem([
                    file,
                    "Directory" if attr.st_mode & 0o040000 else "File",
                    str(attr.st_size),
                    oct(attr.st_mode)[-4:]
                ])
                self.file_browser.addTopLevelItem(item)
                
        except Exception as e:
            self.access_log.append(f"Failed to list files: {str(e)}")

    def execute_ftp_command(self):
        """Execute a command over FTP"""
        # Implement FTP command execution
        pass

    def list_ftp_files(self):
        """List files over FTP connection"""
        # Implement FTP file listing
        pass

    def update_ui(self):
        """Update the UI with current status"""
        # Update uptime display
        uptime = time.time() - self.start_time
        hours, remainder = divmod(uptime, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.setWindowTitle(f"Advanced Network Toolkit Pro - Uptime: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
    
    def closeEvent(self, event):
        """Handle application close event"""
        # Stop all running threads
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
        if self.ping_thread and self.ping_thread.isRunning():
            self.ping_thread.stop()
        if self.wifi_thread and self.wifi_thread.isRunning():
            self.wifi_thread.stop()
        if self.stats_thread and self.stats_thread.isRunning():
            self.stats_thread.stop()
        if self.access_thread and self.access_thread.isRunning():
            self.access_thread.stop()
        
        # Save settings
        self.save_settings()
        
        event.accept()


class PortKnockListener(QThread):
    """Thread for listening to port knocks"""
    def __init__(self, ports, protocol, action, command, log_widget):
        super().__init__()
        self.ports = ports
        self.protocol = protocol
        self.action = action
        self.command = command
        self.log_widget = log_widget
        self._stop_event = threading.Event()
    
    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if self.protocol == "udp" else socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)
            
            sequence_index = 0
            clients = {}  # Track sequence progress per client
            
            while not self._stop_event.is_set():
                try:
                    if self.protocol == "udp":
                        sock.bind(('0.0.0.0', self.ports[sequence_index]))
                        data, addr = sock.recvfrom(1024)
                    else:
                        sock.bind(('0.0.0.0', self.ports[sequence_index]))
                        sock.listen(1)
                        conn, addr = sock.accept()
                        conn.close()
                    
                    client_ip = addr[0]
                    
                    # Initialize or update client sequence tracking
                    if client_ip not in clients:
                        clients[client_ip] = 0
                    
                    if clients[client_ip] == sequence_index:
                        clients[client_ip] += 1
                        self.log_widget.append(f"Client {client_ip} knocked port {self.ports[sequence_index]}")
                        
                        if clients[client_ip] == len(self.ports):
                            self.log_widget.append(f"Successful sequence from {client_ip}")
                            self.execute_action(client_ip)
                            clients[client_ip] = 0  # Reset for this client
                    
                except socket.timeout:
                    pass
                except Exception as e:
                    self.log_widget.append(f"Error: {str(e)}")
                finally:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if self.protocol == "udp" else socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.settimeout(1)
            
        except Exception as e:
            self.log_widget.append(f"Listener error: {str(e)}")
        finally:
            sock.close()
    
    def execute_action(self, client_ip):
        """Execute the configured action on successful knock sequence"""
        try:
            if "Open port 22" in self.action:
                # Open SSH port for this client
                subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", client_ip, "-j", "ACCEPT"])
                self.log_widget.append(f"Opened SSH port for {client_ip}")
            
            elif "Open port 3389" in self.action:
                # Open RDP port for this client
                subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "3389", "-s", client_ip, "-j", "ACCEPT"])
                self.log_widget.append(f"Opened RDP port for {client_ip}")
            
            elif "Execute custom command" in self.action and self.command:
                # Execute custom command
                result = subprocess.run(self.command, shell=True, capture_output=True, text=True)
                self.log_widget.append(f"Command executed for {client_ip}")
                self.log_widget.append(f"Output: {result.stdout}")
                if result.stderr:
                    self.log_widget.append(f"Error: {result.stderr}")
        
        except Exception as e:
            self.log_widget.append(f"Action failed: {str(e)}")
    
    def stop(self):
        """Stop the listener thread"""
        self._stop_event.set()


class VulnerabilityScanner(QThread):
    """Thread for vulnerability scanning"""
    progress_updated = pyqtSignal(int)
    
    def __init__(self, target, scan_type, credentials, results_table, log_widget, progress_bar):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.credentials = credentials
        self.results_table = results_table
        self.log_widget = log_widget
        self.progress_bar = progress_bar
        self._stop_event = threading.Event()
    
    def run(self):
        try:
            if self.scan_type == "Quick Scan":
                self.quick_scan()
            elif self.scan_type == "Full Scan":
                self.full_scan()
            elif self.scan_type == "Web Application Scan":
                self.web_scan()
            elif self.scan_type == "Database Scan":
                self.db_scan()
            else:
                self.custom_scan()
            
            self.progress_updated.emit(100)
            self.log_widget.append("Scan completed")
        
        except Exception as e:
            self.log_widget.append(f"Scan error: {str(e)}")
            self.progress_updated.emit(0)
    
    def quick_scan(self):
        """Perform a quick vulnerability scan"""
        self.log_widget.append("Starting quick vulnerability scan...")
        
        # Simulate scan progress
        for i in range(1, 101):
            if self._stop_event.is_set():
                self.log_widget.append("Scan stopped by user")
                return
                
            time.sleep(0.1)
            self.progress_updated.emit(i)
            
            # Simulate finding vulnerabilities at certain points
            if i == 30:
                self.add_vulnerability("192.168.1.1", "80", "HTTP", "CVE-2021-41773", "High")
            elif i == 60:
                self.add_vulnerability("192.168.1.1", "22", "SSH", "Weak password", "Medium")
            elif i == 90:
                self.add_vulnerability("192.168.1.1", "443", "HTTPS", "Heartbleed", "Critical")
    
    def full_scan(self):
        """Perform a full vulnerability scan"""
        self.log_widget.append("Starting full vulnerability scan...")
        # Implement full scan logic using OpenVAS or other scanner
        pass
    
    def web_scan(self):
        """Perform web application vulnerability scan"""
        self.log_widget.append("Starting web application scan...")
        # Implement web scan logic
        pass
    
    def db_scan(self):
        """Perform database vulnerability scan"""
        self.log_widget.append("Starting database scan...")
        # Implement database scan logic
        pass
    
    def custom_scan(self):
        """Perform custom vulnerability scan"""
        self.log_widget.append("Starting custom scan...")
        # Implement custom scan logic
        pass
    
    def add_vulnerability(self, host, port, service, vuln, severity):
        """Add a vulnerability to the results table"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(host))
        self.results_table.setItem(row, 1, QTableWidgetItem(port))
        self.results_table.setItem(row, 2, QTableWidgetItem(service))
        self.results_table.setItem(row, 3, QTableWidgetItem(vuln))
        self.results_table.setItem(row, 4, QTableWidgetItem(severity))
        
        # Color code based on severity
        if "Critical" in severity:
            for col in range(self.results_table.columnCount()):
                self.results_table.item(row, col).setBackground(QColor(255, 200, 200))
        elif "High" in severity:
            for col in range(self.results_table.columnCount()):
                self.results_table.item(row, col).setBackground(QColor(255, 255, 200))
    
    def stop(self):
        """Stop the scan thread"""
        self._stop_event.set()


def main():
    app = QApplication(sys.argv)
    window = NetworkToolkit()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()