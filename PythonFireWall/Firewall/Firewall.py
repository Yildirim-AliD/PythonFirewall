from pickle import PROTO
from symtable import Class

from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QPushButton,
                             QTextEdit, QLineEdit, QLabel, QWidget, QHBoxLayout, QMessageBox,
                             QTableWidget, QTableWidgetItem, QHeaderView, QListWidget, QScrollBar
                             )
from PyQt5.QtCore import QThread, pyqtSignal, QLine
from PyQt5.QtGui import QIcon
from collections import defaultdict
import time
import sys
import os
import pydivert
import socket
import logging


logging.basicConfig(
    filename="firewall_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_to_file(message,level="info"):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.info(message)
    elif level == "error":
        logging.info(message)


class FirewallWorker(QThread):
    log_signal =pyqtSignal(str,str,str)
    rules_signal =pyqtSignal(str)

    PROTOCOL_MAP = {
        1: "ICMP", #Internet Control Message Protocol
        2: "IGMP", #Internet Group Management Protocol
        6: "TCP", #Transmission Control Protocol
        8: "EGP", #Exterior Gateway Protocol
        9: "IGP", #Interior GateWay Protocol
        17: "UDP", #User Datagram Protocol
        41: "IPv6", #Internet Protocol version 6
        50: "ESP (Encapsulation Security Payload)", #Security Protocol
        51: "AH (Authentication Header)", #Security Protocol
        58: "ICMPv6", #Internet Control Message Protocol version 6
        89: "OSPF (Open Shortest Path First)", #Routing Protocol
        112: "VRRP (Virtual Router Redundancy Protocol)",
        132: "SCTP (Stream Control Transmission Protocol)",
        137: "MPLS-in-IP",
        143: "EtherIP", #Ethernet over IP
        255: "Experimental (Reserved)",
    }

    def __init__(self,rules,website_filter):
        super().__init__()
        self.rules = rules
        self.website_filter = website_filter
        self.running = True
        self.traffic_tracker = defaultdict(list)
        self.blacklist = set()
        self.whitelist = ["127.0.0.1","::1"]


    def resolve_url_to_ip(self,url):

        try:
            return socket.gethostbyname(url)
        except socket.gaierror:
            return None

    def get_protocol_name(self,protocol):

        if isinstance(protocol,tuple):
            protocol = protocol[0]
        return self.PROTOCOL_MAP.get(protocol,f"Unknown ({protocol})")
    def run(self):
        try:
            with pydivert.WinDivert("tcp or udp") as w:
                for packet in w:
                    if not self.running:
                        break

                    src_ip = packet.src_addr
                    dst_ip =packet.dst_addr
                    protocol = self.get_protocol_name(packet.protocol)
                    current_time = time.time()
                    if src_ip in self.whitelist:
                        w.send(packet)
                        continue
                    if src_ip in self.blacklist:
                        self.rules_signal.emit(f"IP in Blacklist: {src_ip}")
                        continue
                    if dst_ip in self.website_filter:
                        self.rules_signal.emit(f"Blocked: {dst_ip} (Web Site)")
                        continue
                    self.traffic_tracker[src_ip].append(current_time)

                    short_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <=1]
                    long_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <=10]
                    short_count = len(short_window)
                    long_count = len(long_window)

                    if short_count > 10000 or long_count > 50000:
                        self.rules_signal.emit(f"DDos Attack Detected: {src_ip} (1s: {short_count}, 10s{long_count}")
                        self.blacklist.add(src_ip)
                        log_to_file(f"DDoS Detected and Blocked: {src_ip}",level="warning")
                        continue
                    self.log_signal.emit(src_ip,dst_ip,protocol)
                    log_to_file(f"Packet: {src_ip}:{packet.src_port} -> {dst_ip}:{packet.dst_port}")
                    blocked = False
                    for rule in self.rules:
                        if "tcp" in rule and protocol.lower() == "tcp":
                            self.rules_signal.emit("TCP Packet Blocked. ")
                            blocked = True
                            break
                        elif "udp" in rule and protocol.lower() == "udp":
                            self.rules_signal.emit("UDP Packet Blocked. ")
                            blocked = True
                            break
                        if rule in  f"{packet.src_addr}:{packet.src_port}" or rule in f"{packet.dst_addr}:{packet.dst_port}":
                            self.rules_signal.emit(f"Packet Blocked: {rule}")
                            log_to_file(f"Rule Blocked: {rule}",level="warning")
                            blocked = True
                            break
                        if not blocked:
                            w.send(packet)
        except Exception as e:
            self.rules_signal.emit(f"Error: {str(e)}")

    def stop(self):
        self.running =False

class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall")
        self.setWindowIcon(QIcon("icon.ico"))
        screen = QApplication.primaryScreen()
        screen_size = screen.size()
        self.resize(screen_size.width()//2,screen_size.height()//2)

        self.main_widget =QWidget()
        self.setCentralWidget(self.main_widget)
        layout = QVBoxLayout()

        self.start_button = QPushButton("Firewall started successfully.")
        self.start_button.clicked.connect(self.start_firewall)
        self.stop_button = QPushButton("Firewall stopped successfully.")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_firewall)


        rule_layout =QVBoxLayout()
        self.rule_label = QLabel("Rules: ")
        self.rule_list = QListWidget()
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("Enter a Port or IP rule (ör. 192.168.1.1:80)...")
        self.add_rule_button = QPushButton("Add Rule")
        self.add_rule_button.clicked.connect(self.add_rule)
        rule_layout.addWidget(self.rule_input)
        rule_layout.addWidget(self.add_rule_button)
        self.delete_rule_button = QPushButton("Delete Selected Rule")
        self.delete_rule_button.clicked.connect(self.delete_rule)

        self.network_label = QLabel("Network Traffic")
        self.log_area = QTableWidget()
        self.log_area.setColumnCount(3)
        self.log_area.setHorizontalHeaderLabels(["Source","Target","Protokol"])
        self.log_area.setEditTriggers(QTableWidget.NoEditTriggers)
        header = self.log_area.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        self.rules_label = QLabel("Applied Rules: ")
        self.rules_area = QTextEdit()
        self.rules_area.setReadOnly(True)


        self.web_label = QLabel("Blocked Websites: ")
        self.web_list = QListWidget()


        website_layout = QHBoxLayout()
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("Enter the URL of the website to be blocked (ör. www.example.com)...")
        self.add_website_button = QPushButton("Add Website")
        self.add_website_button.clicked.connect(self.add_website)
        website_layout.addWidget(self.website_input)
        website_layout.addWidget(self.add_website_button)

        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.rule_label)
        layout.addWidget(self.rule_list)
        layout.addLayout(rule_layout)
        layout.addWidget(self.delete_rule_button)
        layout.addWidget(self.network_label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.rules_label)
        layout.addWidget(self.rules_area)
        layout.addWidget(self.web_label)
        layout.addWidget(self.web_list)
        layout.addLayout(website_layout)
        self.main_widget.setLayout(layout)
        self.tema()
        self.firewall_worker = None
        self.rules = []
        self.website_filter = set()

    def add_to_traffic_table(self,src,dst,protocol):
        row_position = self.log_area.rowCount()
        self.log_area.insertRow(row_position)
        self.log_area.setItem(row_position,0,QTableWidgetItem(src))
        self.log_area.setItem(row_position,1,QTableWidgetItem(dst))
        self.log_area.setItem(row_position,2,QTableWidgetItem(protocol))
    def add_rule(self):
        rule = self.rule_input.text()
        if rule:
            self.rules.append(rule)
            self.rule_list.addItem(rule)
            self.rule_input.clear()
            self.rules_area.append(f"Rule Added: {rule}")
        else:
            QMessageBox.warning(self,"Warning", "Enter a valid rule!")
    def delete_rule(self):
        selected_item = self.rule_list.currentItem()
        if selected_item:
            rule = selected_item.text()
            self.rules.remove(rule)
            self.rule_list.takeItem(self.rule_list.row(selected_item))
            self.rules_area.append(f"Rule Deleted: {rule}")
        else:
            QMessageBox.warning(self,"Warning", "Select a Rule to Delete")
    def start_firewall(self):
        if not self.firewall_worker:
            self.firewall_worker = FirewallWorker(self.rules,self.website_filter)
            self.firewall_worker.log_signal.connect(self.add_to_traffic_table)
            self.firewall_worker.rules_signal.connect(self.rules_area.append)
            self.firewall_worker.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

    def add_website(self):
        url = self.website_input.text()
        if url:
            ip = self.firewall_worker.resolve_url_to_ip(url)
            if ip:
                self.website_filter.add(ip)
                self.web_list.addItem(f"{url} ({ip})")
                self.website_input.clear()
                self.rules_area.append(f"Added to Website Filter: {url} ({ip})")
            else:
                QMessageBox.warning(self,"Warning", "Enter a valid URL!")
        else:
            QMessageBox.warning(self,"Warning", "Enter a URL!")
    def stop_firewall(self):
        if self.firewall_worker:
            self.firewall_worker.stop()
            self.firewall_worker.quit()
            self.firewall_worker.wait()
            self.firewall_worker = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.rules_area.append("Firewall stopped. ")
    def tema(self):
        style_sheet = """
        QWidget {
            background-color: #1e1e2e;
            color: #ffffff;
            font-family: 'Segoe UI', sans-serif;
            font-size: 14px;
        }
    
        QPushButton {
            background-color: #2d2d44;
            color: #ffffff;
            border: 2px solid #3b3b3b; 
            border-radius: 6px;
        }
    
        QLineEdit {
            background-color: #2d2d44;
            color: #ffffff;
            border: 2px solid #3b3b3b; 
            border-radius: 4px;
            padding: 5px;
        }
    
        QHeaderView::section {
            background-color: #3b3b5c;
            color: #ffffff;
            padding: 4px;
            border: 1px solid #3b3b3b; 
        }
    
        QLabel {
            color: #c7c7ff;
        }
    
        QGroupBox {
            background-color: #2a2a3c;
            border: 2px solid #3b3b3b;
            border-radius: 6px;
        }
    
    
        QScrollBar:vertical {
            background-color: #2d2d44;
            width: 10px;
            margin: 0;
            border-radius: 5px;
        }
    
        QScrollBar::handle:vertical {
            background-color: #4e4e7c;
            border-radius: 5px;
        }
    
        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {
            background-color: #2d2d44;
            height: 0;
        }
    
        QScrollBar::add-page:vertical,
        QScrollBar::sub-page:vertical {
            background-color: none;
        }
    
        QScrollBar:horizontal {
            background-color: #2d2d44;
            height: 10px;
            margin: 0;
            border-radius: 5px;
        }
    
        QScrollBar::handle:horizontal {
            background-color: #4e4e7c;
            border-radius: 5px;
        }
    
        QScrollBar::add-line:horizontal,
        QScrollBar::sub-line:horizontal {
            background-color: #2d2d44;
            width: 0px;
        }
    
        QScrollBar::add-page:horizontal,
        QScrollBar::sub-page:horizontal {
            background-color: none;
        }
        """
        self.setStyleSheet(style_sheet)

if  __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = FirewallGUI()
    gui.show()
    sys.exit(app.exec_())
