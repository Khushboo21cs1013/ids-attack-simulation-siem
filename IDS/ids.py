import os
import hashlib
import requests
import psutil
import smtplib
from email.mime.text import MIMEText
import scapy.all as scapy
from tqdm import tqdm
import time
import threading
import logging
import yaml
import json
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from datetime import datetime
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import signal
import sys
from dataclasses import dataclass, field


@dataclass
class AlertConfig:
    email_from: str
    email_to: List[str]
    smtp_server: str
    smtp_port: int
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    alert_threshold: int = 3
    alert_cooldown: int = 3600
    severity_levels: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    min_severity_to_email: str = "HIGH"

@dataclass
class IDSConfig:
    virus_total_api_key: str
    monitoring_interval: int
    max_cpu_threshold: float
    max_memory_threshold: float
    suspicious_ports: Set[int]
    allowed_ips: Set[str]
    blocked_ips: Set[str]
    alert_config: AlertConfig
    log_file: str
    database_file: str

class DatabaseManager:
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.init_database()

    def init_database(self):
        with sqlite3.connect(self.db_file) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT,
                    severity TEXT,
                    message TEXT,
                    details TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    file_path TEXT,
                    hash TEXT,
                    scan_result TEXT
                )
            ''')

    def log_alert(self, alert_type: str, severity: str, message: str, details: str):
        with sqlite3.connect(self.db_file) as conn:
            conn.execute(
                'INSERT INTO alerts (alert_type, severity, message, details) VALUES (?, ?, ?, ?)',
                (alert_type, severity, message, details)
            )

    def log_scan(self, file_path: str, file_hash: str, scan_result: str):
        with sqlite3.connect(self.db_file) as conn:
            conn.execute(
                'INSERT INTO scans (file_path, hash, scan_result) VALUES (?, ?, ?)',
                (file_path, file_hash, scan_result)
            )

class AlertManager:
    def __init__(self, config: AlertConfig, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.alert_count = {}
        self._validate_smtp_config()
        
    def _validate_smtp_config(self):
        """Validate SMTP configuration and test connection during initialization."""
        try:
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port, timeout=10) as server:
                # Try EHLO first
                server.ehlo()
                
                # Check if server supports TLS and enable it if available
                if server.has_extn('STARTTLS'):
                    server.starttls()
                    server.ehlo()  # Re-identify ourselves over TLS
                
                # Check if authentication is required and supported
                if self.config.smtp_username and self.config.smtp_password:
                    if server.has_extn('AUTH'):
                        server.login(self.config.smtp_username, self.config.smtp_password)
                    else:
                        logging.warning("SMTP server does not support authentication. Will attempt to send without auth.")
                
                logging.info("SMTP configuration validated successfully")
                
        except Exception as e:
            logging.error(f"SMTP configuration validation failed: {e}")
            logging.warning("Email alerts will be logged but not sent")

    def send_alert(self, alert_type: str, severity: str, message: str, details: str = ""):
        # Log to database
        self.db_manager.log_alert(alert_type, severity, message, details)
        
        # Check if severity meets minimum threshold for email
        severity_index = self.config.severity_levels.index(severity)
        min_severity_index = self.config.severity_levels.index(self.config.min_severity_to_email)
        if severity_index > min_severity_index:
            logging.info(f"Alert severity {severity} below minimum threshold {self.config.min_severity_to_email}")
            return
        
        # Check alert threshold
        current_time = time.time()
        self.alert_count = {k: v for k, v in self.alert_count.items() 
                           if current_time - v['timestamp'] < self.config.alert_cooldown}
        
        alert_key = f"{alert_type}:{message}"
        if alert_key not in self.alert_count:
            self.alert_count[alert_key] = {'count': 0, 'timestamp': current_time}
        
        self.alert_count[alert_key]['count'] += 1
        
        if self.alert_count[alert_key]['count'] >= self.config.alert_threshold:
            self._send_email_alert(severity, message, details)
            self.alert_count[alert_key]['count'] = 0

    def _send_email_alert(self, severity: str, message: str, details: str):
        msg = MIMEText(f"""
Severity: {severity}
Time: {datetime.now()}
Message: {message}
Details: {details}
        """)
        msg['Subject'] = f'IDS Alert: {severity} - {message[:50]}'
        msg['From'] = self.config.email_from
        msg['To'] = ', '.join(self.config.email_to)

        try:
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port, timeout=10) as server:
                # First try EHLO
                server.ehlo()
                
                # Enable TLS if supported
                if server.has_extn('STARTTLS'):
                    server.starttls()
                    server.ehlo()
                
                # Only attempt authentication if supported
                if self.config.smtp_username and self.config.smtp_password:
                    if server.has_extn('AUTH'):
                        server.login(self.config.smtp_username, self.config.smtp_password)
                    else:
                        logging.info("SMTP server does not support authentication, sending without auth")
                
                server.send_message(msg)
                logging.info(f"Alert email sent: {message}")
                
        except smtplib.SMTPAuthenticationError as e:
            logging.error(f"SMTP authentication failed: {e}")
        except smtplib.SMTPException as e:
            logging.error(f"Failed to send alert email (SMTP error): {e}")
        except Exception as e:
            logging.error(f"Failed to send alert email (general error): {e}")
        finally:
            # Always log the alert to the database, even if email fails
            self.db_manager.log_alert(
                "email_alert",
                severity,
                f"Alert email: {message}",
                f"Email delivery attempted to: {', '.join(self.config.email_to)}"
            )

class NetworkMonitor:
    def __init__(self, config: IDSConfig, alert_manager: AlertManager):
        self.config = config
        self.alert_manager = alert_manager
        self.packet_stats = {}
        self.stop_flag = threading.Event()

    def start_monitoring(self):
        threading.Thread(target=self._monitor_network_traffic, daemon=True).start()
        threading.Thread(target=self._monitor_connections, daemon=True).start()

    def stop_monitoring(self):
        self.stop_flag.set()

    def _monitor_network_traffic(self):
        def packet_callback(packet):
            if self.stop_flag.is_set():
                return
            
            if packet.haslayer(scapy.IP):
                ip_src = packet[scapy.IP].src
                ip_dst = packet[scapy.IP].dst

                # Check against blocked IPs
                if ip_src in self.config.blocked_ips or ip_dst in self.config.blocked_ips:
                    self.alert_manager.send_alert(
                        "network",
                        "HIGH",
                        f"Blocked IP detected",
                        f"Source: {ip_src}, Destination: {ip_dst}"
                    )

                # Check for suspicious ports
                if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                    dport = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport
                    if dport in self.config.suspicious_ports:
                        self.alert_manager.send_alert(
                            "network",
                            "MEDIUM",
                            f"Suspicious port activity detected",
                            f"Port: {dport}, Source: {ip_src}"
                        )

        try:
            scapy.sniff(prn=packet_callback, store=0, stop_filter=lambda _: self.stop_flag.is_set())
        except Exception as e:
            logging.error(f"Error in network monitoring: {e}")

    def _monitor_connections(self):
        while not self.stop_flag.is_set():
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.raddr and conn.raddr.ip:
                        if conn.raddr.ip in self.config.blocked_ips:
                            self.alert_manager.send_alert(
                                "network",
                                "HIGH",
                                "Connection to blocked IP detected",
                                f"Local: {conn.laddr.ip}:{conn.laddr.port} -> Remote: {conn.raddr.ip}:{conn.raddr.port}"
                            )
                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                logging.error(f"Error monitoring connections: {e}")
                time.sleep(5)

class SystemMonitor:
    def __init__(self, config: IDSConfig, alert_manager: AlertManager):
        self.config = config
        self.alert_manager = alert_manager
        self.stop_flag = threading.Event()

    def start_monitoring(self):
        threading.Thread(target=self._monitor_system_resources, daemon=True).start()

    def stop_monitoring(self):
        self.stop_flag.set()

    def _monitor_system_resources(self):
        while not self.stop_flag.is_set():
            try:
                # Monitor CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.config.max_cpu_threshold:
                    self.alert_manager.send_alert(
                        "system",
                        "MEDIUM",
                        "High CPU usage detected",
                        f"Current CPU usage: {cpu_percent}%"
                    )

                # Monitor memory usage
                memory = psutil.virtual_memory()
                if memory.percent > self.config.max_memory_threshold:
                    self.alert_manager.send_alert(
                        "system",
                        "MEDIUM",
                        "High memory usage detected",
                        f"Current memory usage: {memory.percent}%"
                    )

                # Monitor suspicious processes
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        if proc.info['cpu_percent'] > self.config.max_cpu_threshold:
                            self.alert_manager.send_alert(
                                "process",
                                "HIGH",
                                f"Suspicious process activity",
                                f"Process: {proc.info['name']} (PID: {proc.info['pid']}) - CPU: {proc.info['cpu_percent']}%"
                            )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                logging.error(f"Error monitoring system resources: {e}")
                time.sleep(5)

class FileMonitor:
    def __init__(self, config: IDSConfig, alert_manager: AlertManager, db_manager: DatabaseManager):
        self.config = config
        self.alert_manager = alert_manager
        self.db_manager = db_manager
        self.known_hashes = set()

    def scan_file(self, file_path: str) -> None:
        try:
            file_hash = self._calculate_hash(file_path)
            self.db_manager.log_scan(file_path, file_hash, "pending")
            
            # Check with VirusTotal
            if self._check_virustotal(file_hash):
                self.alert_manager.send_alert(
                    "file",
                    "HIGH",
                    "Malicious file detected",
                    f"File: {file_path}\nHash: {file_hash}"
                )
                self.db_manager.log_scan(file_path, file_hash, "malicious")
            else:
                self.db_manager.log_scan(file_path, file_hash, "clean")
                
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            self.db_manager.log_scan(file_path, "", f"error: {str(e)}")

    def _calculate_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _check_virustotal(self, file_hash: str) -> bool:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.config.virus_total_api_key}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                stats = result['data']['attributes']['last_analysis_stats']
                return stats['malicious'] > 0
            return False
        except Exception as e:
            logging.error(f"Error checking VirusTotal: {e}")
            return False
        
class IDS:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        self.db_manager = DatabaseManager(self.config.database_file)
        self.alert_manager = AlertManager(self.config.alert_config, self.db_manager)
        self.network_monitor = NetworkMonitor(self.config, self.alert_manager)
        self.system_monitor = SystemMonitor(self.config, self.alert_manager)
        self.file_monitor = FileMonitor(self.config, self.alert_manager, self.db_manager)

    def _load_config(self, config_path: str) -> IDSConfig:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        alert_config = AlertConfig(**config_data['alert_config'])
        return IDSConfig(
            virus_total_api_key=config_data['virus_total_api_key'],
            monitoring_interval=config_data['monitoring_interval'],
            max_cpu_threshold=config_data['max_cpu_threshold'],
            max_memory_threshold=config_data['max_memory_threshold'],
            suspicious_ports=set(config_data['suspicious_ports']),
            allowed_ips=set(config_data['allowed_ips']),
            blocked_ips=set(config_data['blocked_ips']),
            alert_config=alert_config,
            log_file=config_data['log_file'],
            database_file=config_data['database_file']
        )

    def _setup_logging(self):
        logging.basicConfig(
            filename=self.config.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        # Also log to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(console_handler)

    def start(self):
        logging.info("Starting IDS...")
        self.network_monitor.start_monitoring()
        self.system_monitor.start_monitoring()
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        logging.info("Shutting down IDS...")
        self.network_monitor.stop_monitoring()
        self.system_monitor.stop_monitoring()
        logging.info("IDS shutdown complete.")
        sys.exit(0)       
class IDSCommandLine:
    def __init__(self, ids_instance: IDS):
        self.ids = ids_instance
        self.commands = {
            '1': ('Network Scan', self.network_scan),
            '2': ('Process Scan', self.process_scan),
            '3': ('Connection Scan', self.connection_scan),
            '4': ('File Scan', self.file_scan),
            '5': ('Show Statistics', self.show_stats),
            '6': ('Show Recent Alerts', self.show_alerts),
            'h': ('Help', self.show_help),
            'q': ('Quit', self.quit_ids)
        }
        self.running = True

    def start_cli(self):
        """Start the command line interface loop"""
        print("\nIDS Command Line Interface")
        self.show_help()
        
        while self.running:
            try:
                command = input("\nEnter command (h for help): ").lower().strip()
                if command in self.commands:
                    self.commands[command][1]()
                else:
                    print("Invalid command. Press 'h' for help.")
            except KeyboardInterrupt:
                print("\nUse 'q' to quit properly.")
            except Exception as e:
                logging.error(f"Error executing command: {e}")

    def show_help(self):
        """Display available commands"""
        print("\nAvailable Commands:")
        for key, (description, _) in self.commands.items():
            print(f"{key}: {description}")

    def network_scan(self):
        """Perform a network scan"""
        print("\nPerforming network scan...")
        try:
            # Get current network connections
            connections = psutil.net_connections(kind='inet')
            print("\nActive Network Connections:")
            print(f"{'Local Address':<25} {'Remote Address':<25} {'Status':<15} {'PID':<10}")
            print("-" * 75)
            
            for conn in connections:
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                print(f"{local:<25} {remote:<25} {conn.status:<15} {conn.pid or 'N/A':<10}")
        
        except Exception as e:
            print(f"Error during network scan: {e}")

    def process_scan(self):
        """Scan running processes"""
        print("\nScanning running processes...")
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']))
            processes.sort(key=lambda x: x.info['cpu_percent'], reverse=True)
            
            print(f"\n{'PID':<10} {'Name':<30} {'CPU %':<10} {'Memory %':<10} {'Age (min)':<10}")
            print("-" * 70)
            
            current_time = time.time()
            for proc in processes[:20]:  # Show top 20 processes
                try:
                    age = int((current_time - proc.info['create_time']) / 60)
                    print(f"{proc.info['pid']:<10} {proc.info['name'][:30]:<30} "
                          f"{proc.info['cpu_percent']:<10.1f} {proc.info['memory_percent']:<10.1f} "
                          f"{age:<10}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"Error during process scan: {e}")

    def connection_scan(self):
        """Scan and analyze current network connections"""
        print("\nAnalyzing network connections...")
        try:
            connections = psutil.net_connections(kind='inet')
            ports_count = {}
            remote_ips = set()
            
            for conn in connections:
                if conn.raddr:
                    remote_ips.add(conn.raddr.ip)
                    ports_count[conn.raddr.port] = ports_count.get(conn.raddr.port, 0) + 1
            
            print(f"\nTotal unique remote IPs: {len(remote_ips)}")
            print("\nMost active ports:")
            for port, count in sorted(ports_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"Port {port}: {count} connections")
            
            print("\nChecking for suspicious connections...")
            for ip in remote_ips:
                if ip in self.ids.config.blocked_ips:
                    print(f"WARNING: Detected connection to blocked IP: {ip}")
        
        except Exception as e:
            print(f"Error during connection analysis: {e}")

    def file_scan(self):
        """Scan a file or directory"""
        try:
            path = input("\nEnter file or directory path to scan: ").strip()
            if not os.path.exists(path):
                print("Path does not exist!")
                return
            
            if os.path.isfile(path):
                print(f"Scanning file: {path}")
                self.ids.file_monitor.scan_file(path)
            elif os.path.isdir(path):
                print(f"Scanning directory: {path}")
                for root, _, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        print(f"Scanning: {full_path}")
                        self.ids.file_monitor.scan_file(full_path)
        
        except Exception as e:
            print(f"Error during file scan: {e}")

    def show_stats(self):
        """Show IDS statistics"""
        try:
            with sqlite3.connect(self.ids.config.database_file) as conn:
                cursor = conn.cursor()
                
                # Get alert statistics
                cursor.execute("""
                    SELECT severity, COUNT(*) as count
                    FROM alerts
                    GROUP BY severity
                    ORDER BY count DESC
                """)
                alert_stats = cursor.fetchall()
                
                # Get scan statistics
                cursor.execute("""
                    SELECT scan_result, COUNT(*) as count
                    FROM scans
                    GROUP BY scan_result
                    ORDER BY count DESC
                """)
                scan_stats = cursor.fetchall()
                
                print("\nAlert Statistics:")
                print("-" * 30)
                for severity, count in alert_stats:
                    print(f"{severity:<15} {count:>10}")
                
                print("\nScan Statistics:")
                print("-" * 30)
                for result, count in scan_stats:
                    print(f"{result:<15} {count:>10}")
        
        except Exception as e:
            print(f"Error fetching statistics: {e}")

    def show_alerts(self):
        """Show recent alerts"""
        try:
            with sqlite3.connect(self.ids.config.database_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp, severity, alert_type, message
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 10
                """)
                alerts = cursor.fetchall()
                
                print("\nRecent Alerts:")
                print("-" * 80)
                for timestamp, severity, alert_type, message in alerts:
                    print(f"{timestamp} | {severity:<8} | {alert_type:<10} | {message}")
        
        except Exception as e:
            print(f"Error fetching alerts: {e}")

    def quit_ids(self):
        """Quit the IDS"""
        print("\nShutting down IDS...")
        self.running = False
        self.ids._handle_shutdown(signal.SIGTERM, None)
class IDSCommandLine:
    def __init__(self, ids_instance: IDS):
        self.ids = ids_instance
        self.commands = {
            '1': ('Network Scan', self.network_scan),
            '2': ('Process Scan', self.process_scan),
            '3': ('Connection Scan', self.connection_scan),
            '4': ('File Scan', self.file_scan),
            '5': ('Show Statistics', self.show_stats),
            '6': ('Show Recent Alerts', self.show_alerts),
            'h': ('Help', self.show_help),
            'q': ('Quit', self.quit_ids)
        }
        self.running = True

    def start_cli(self):
        """Start the command line interface loop"""
        print("\nIDS Command Line Interface")
        self.show_help()
        
        while self.running:
            try:
                command = input("\nEnter command (h for help): ").lower().strip()
                if command in self.commands:
                    self.commands[command][1]()
                else:
                    print("Invalid command. Press 'h' for help.")
            except KeyboardInterrupt:
                print("\nUse 'q' to quit properly.")
            except Exception as e:
                logging.error(f"Error executing command: {e}")

    def show_help(self):
        """Display available commands"""
        print("\nAvailable Commands:")
        for key, (description, _) in self.commands.items():
            print(f"{key}: {description}")

    def network_scan(self):
        """Perform a network scan"""
        print("\nPerforming network scan...")
        try:
            # Get current network connections
            connections = psutil.net_connections(kind='inet')
            print("\nActive Network Connections:")
            print(f"{'Local Address':<25} {'Remote Address':<25} {'Status':<15} {'PID':<10}")
            print("-" * 75)
            
            for conn in connections:
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                print(f"{local:<25} {remote:<25} {conn.status:<15} {conn.pid or 'N/A':<10}")
        
        except Exception as e:
            print(f"Error during network scan: {e}")

    def process_scan(self):
        """Scan running processes"""
        print("\nScanning running processes...")
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']))
            processes.sort(key=lambda x: x.info['cpu_percent'], reverse=True)
            
            print(f"\n{'PID':<10} {'Name':<30} {'CPU %':<10} {'Memory %':<10} {'Age (min)':<10}")
            print("-" * 70)
            
            current_time = time.time()
            for proc in processes[:20]:  # Show top 20 processes
                try:
                    age = int((current_time - proc.info['create_time']) / 60)
                    print(f"{proc.info['pid']:<10} {proc.info['name'][:30]:<30} "
                          f"{proc.info['cpu_percent']:<10.1f} {proc.info['memory_percent']:<10.1f} "
                          f"{age:<10}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"Error during process scan: {e}")

    def connection_scan(self):
        """Scan and analyze current network connections"""
        print("\nAnalyzing network connections...")
        try:
            connections = psutil.net_connections(kind='inet')
            ports_count = {}
            remote_ips = set()
            
            for conn in connections:
                if conn.raddr:
                    remote_ips.add(conn.raddr.ip)
                    ports_count[conn.raddr.port] = ports_count.get(conn.raddr.port, 0) + 1
            
            print(f"\nTotal unique remote IPs: {len(remote_ips)}")
            print("\nMost active ports:")
            for port, count in sorted(ports_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"Port {port}: {count} connections")
            
            print("\nChecking for suspicious connections...")
            for ip in remote_ips:
                if ip in self.ids.config.blocked_ips:
                    print(f"WARNING: Detected connection to blocked IP: {ip}")
        
        except Exception as e:
            print(f"Error during connection analysis: {e}")

    def file_scan(self):
        """Scan a file or directory"""
        try:
            path = input("\nEnter file or directory path to scan: ").strip()
            if not os.path.exists(path):
                print("Path does not exist!")
                return
            
            if os.path.isfile(path):
                print(f"Scanning file: {path}")
                self.ids.file_monitor.scan_file(path)
            elif os.path.isdir(path):
                print(f"Scanning directory: {path}")
                for root, _, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        print(f"Scanning: {full_path}")
                        self.ids.file_monitor.scan_file(full_path)
        
        except Exception as e:
            print(f"Error during file scan: {e}")

    def show_stats(self):
        """Show IDS statistics"""
        try:
            with sqlite3.connect(self.ids.config.database_file) as conn:
                cursor = conn.cursor()
                
                # Get alert statistics
                cursor.execute("""
                    SELECT severity, COUNT(*) as count
                    FROM alerts
                    GROUP BY severity
                    ORDER BY count DESC
                """)
                alert_stats = cursor.fetchall()
                
                # Get scan statistics
                cursor.execute("""
                    SELECT scan_result, COUNT(*) as count
                    FROM scans
                    GROUP BY scan_result
                    ORDER BY count DESC
                """)
                scan_stats = cursor.fetchall()
                
                print("\nAlert Statistics:")
                print("-" * 30)
                for severity, count in alert_stats:
                    print(f"{severity:<15} {count:>10}")
                
                print("\nScan Statistics:")
                print("-" * 30)
                for result, count in scan_stats:
                    print(f"{result:<15} {count:>10}")
        
        except Exception as e:
            print(f"Error fetching statistics: {e}")

    def show_alerts(self):
        """Show recent alerts"""
        try:
            with sqlite3.connect(self.ids.config.database_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp, severity, alert_type, message
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 10
                """)
                alerts = cursor.fetchall()
                
                print("\nRecent Alerts:")
                print("-" * 80)
                for timestamp, severity, alert_type, message in alerts:
                    print(f"{timestamp} | {severity:<8} | {alert_type:<10} | {message}")
        
        except Exception as e:
            print(f"Error fetching alerts: {e}")

    def quit_ids(self):
        """Quit the IDS"""
        print("\nShutting down IDS...")
        self.running = False
        self.ids._handle_shutdown(signal.SIGTERM, None)
        
def main():
    if len(sys.argv) != 2:
        print("Usage: python ids.py <config_file>")
        sys.exit(1)

    config_file = sys.argv[1]
    ids = IDS(config_file)
    ids.start()

    # Start CLI in the main thread
    cli = IDSCommandLine(ids)
    cli.start_cli()

if __name__ == '__main__':
    main()