import sys
from PyQt6 import uic, QtGui
from PyQt6.QtGui import QFont, QAction
from PyQt6.QtCore import Qt, QTimer, QCoreApplication
from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QFileDialog, QMessageBox, QTableWidgetItem, QDialog, QVBoxLayout, QMenu, QInputDialog ,QWidget, QTableWidget, QHeaderView, QTabWidget
from PyQt6.QtWebEngineWidgets import QWebEngineView
import threading
import time
import psutil
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
import plotly.io as pio
import plotly.graph_objects as go
from scipy.spatial import distance
from scapy.all import *
from scapy.utils import hexdump
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6
from scapy.all import ARP, ICMP, ICMPv6ND_NS, Raw
from ModelAI import ModelAI
import requests
import webbrowser
from PyQt6 import QtWidgets, QtGui
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QTableWidgetItem, QDialog, QScrollArea,QVBoxLayout, QMenu,QVBoxLayout, QLabel, QDialog
import socket
from collections import defaultdict
from datetime import datetime
from PyQt6.QtWidgets import *
warnings.filterwarnings("ignore")


def get_mac_vendor(mac_address):
    """Tra cứu vendor của MAC Address từ API"""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=3)
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except:
        return "Unknown Vendor"

# Hàm lấy thông tin vị trí địa lý của IP
def get_ip_geolocation(ip_address):
    """Lấy thông tin vị trí địa lý của IP bằng ipinfo.io"""
    try:
        response = requests.get(f"http://ipinfo.io/{ip_address}/json", timeout=3)
        data = response.json()
        
        return {
            "City": data.get("city", "Unknown"),
            "Region": data.get("region", "Unknown"),
            "Country": data.get("country", "Unknown"),
            "Location": data.get("loc", "Unknown"),
            "ISP": data.get("org", "Unknown")
        }
    except:
        return {"City": "Unknown", "Region": "Unknown", "Country": "Unknown", "Location": "Unknown", "ISP": "Unknown"}
def is_http_packet(pkt):
    return pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and bytes(pkt[TCP].payload)

def parse_http_payload(pkt):
    try:
        payload = bytes(pkt[TCP].payload)
        http_text = payload.decode("utf-8", errors="replace")
        return http_text
    except Exception as e:
        print(f"Lỗi giải mã HTTP: {e}")
        return None
    
class InfoDialog(QDialog):
    def __init__(self, ip_src, ip_dst, protocol, mac_src, mac_dst, src_port, dst_port,  parent=None):
        super().__init__(parent)
        self.setWindowTitle("Thông tin tổng quan nhanh")

        # Tạo layout và thêm các label cho thông tin
        layout = QVBoxLayout()
        src_geo, dst_geo, src_vendor, dst_vendor=get_ip_geolocation(ip_src),get_ip_geolocation(ip_dst),get_mac_vendor(mac_src),get_mac_vendor(mac_dst)
        # Thêm thông tin IP và vị trí
        layout.addWidget(QLabel(f"📡 Source IP: {ip_src} ({src_geo['City']}, {src_geo['Country']} - {src_geo['ISP']})"))
        layout.addWidget(QLabel(f"🎯 Destination IP: {ip_dst} ({dst_geo['City']}, {dst_geo['Country']} - {dst_geo['ISP']})"))
        layout.addWidget(QLabel(f"📦 Protocol: {protocol}"))

        # Thêm thông tin MAC và nhà cung cấp
        layout.addWidget(QLabel(f"🔗 Source MAC: {mac_src} ({src_vendor}) → Destination MAC: {mac_dst} ({dst_vendor})"))
        
        # Thêm thông tin cổng nguồn và đích
        layout.addWidget(QLabel(f"🔗 Source Port: {src_port} → Destination Port: {dst_port}"))

        # Thiết lập layout cho dialog
        self.setLayout(layout)
        self.resize(400, 300)

class HTTPDialog(QDialog):
    def __init__(self, http_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Thông tin chi tiết gói tin HTTP")

        layout = QVBoxLayout()

        # Hiển thị nội dung HTTP Request
        http_text_label = QLabel(f"<pre>{http_text}</pre>")
        http_text_label.setWordWrap(True)

        # Đặt HTTP request vào trong một scroll area nếu nội dung dài
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(http_text_label)

        layout.addWidget(scroll_area)

        # Thiết lập layout cho dialog
        self.setLayout(layout)
        self.resize(600, 400)
        
last_time = None
last_size = None
# connection_states, src_dport_counts, dst_sport_counts, dst_src_counts
connection_states = {}  # You can define this as a dictionary or list, depending on your needs
src_dport_counts = {}  # Example initialization
dst_sport_counts = {}  # Example initialization
dst_src_counts = {}    # Example initialization
        
class NetSentinel(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi("untitled.ui", self)  # Đường dẫn tới file UI
        self.setWindowTitle("NetSentinel")
        self.tableWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tableWidget.customContextMenuRequested.connect(self.show_table_context_menu)
        self.tableWidget.cellDoubleClicked.connect(self.on_item_double_click)
        # setup ban đầu
        self.stop_button.setEnabled(False)
        self.sniffing = False
        self.packets = []
        self.tableWidget.cellClicked.connect(self.on_table_row_clicked)
        self.textEdit.setReadOnly(True)
        self.flow_table = defaultdict(lambda: {
            'start_time': None,
            'last_time': None,
            'last_seen': None,
            'spkts': 0, 'dpkts': 0,
            'sbytes': 0, 'dbytes': 0,
            'sttl': 0, 'dttl': 0,
            'synack': 0.0,
            'protocol': None,
            'state': 'INT',
            'src_ip': None, 'dst_ip': None,
            'src_port': 0, 'dst_port': 0
        })
        self.FLOW_TIMEOUT = 5.0  # Giây (chu kỳ kiểm tra DoS)
        self.last_cleanup_time = time.time()
        # ✅ MỚI
        # Khởi tạo AI với 3 file mới nhất
        self.AI = ModelAI(
            model_path="DoS_Model.pkl",
            features_path="features_config.pkl",
            threshold_path="best_threshold.pkl"
        )
        print("✅ AI đã được khởi tạo thành công - Sẵn sàng dự đoán sau 5 giây")



        # Điều chỉnh 1 tí giao diện
        font = QFont()
        font.setBold(True)
        header = self.tableWidget.horizontalHeader()
        header.setFont(font)
        self.tableWidget.setColumnWidth(0, 20)  
        self.tableWidget.setColumnWidth(1, 60) 
        self.tableWidget.setColumnWidth(2, 100) 
        self.tableWidget.setColumnWidth(3, 100) 
        self.tableWidget.setColumnWidth(4, 60) 
        self.tableWidget.setColumnWidth(5, 80) 
        self.tableWidget.setColumnWidth(6, 540) 


        self.comboBox.addItems(self.get_network_interfaces())
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.save_button.clicked.connect(self.save_pcap)
        self.load_button.clicked.connect(self.load_pcap)
        self.reset_button.clicked.connect(self.reset_sniffing)

       # Tạo menu cho nút Thống kê
        self.stats_menu = QMenu(self)
        self.stats_menu.addAction("Thống kê nguồn", self.show_source_stats)
        self.stats_menu.addAction("Thống kê đích", self.show_destination_stats)
        self.stats_menu.addAction("Thống kê giao thức", self.show_protocol_stats)
        self.stats_menu.addAction("Thống kê kích thước", self.show_packet_size_stats)  # Tách riêng cho kích thước
        self.stats_menu.addAction("Cuộc hội thoại", self.show_conversation_stats_table)
        
        
        self.stats_button.setMenu(self.stats_menu)  # Gắn menu vào nút
        self.pushButton_9.clicked.connect(self.filter_packets)
        self.show_io_graph_button.clicked.connect(self.show_io_graphs)
        self.packets = []
        self.packets_filter=[]
        self.sniffing = False
        self.start_time = None
        self.packet_counts = {} # Dictionary để lưu trữ số lượng gói tin theo thời gian
        self.tcp_error_counts = {} 
        
    def on_item_double_click(self, row,column):
        if 0 <= row < len(self.packets_filter):
            packet = self.packets_filter[row]
            ip_src, ip_dst, protocol = "Unknown", "Unknown", "Unknown"
            mac_src, mac_dst = "Unknown MAC", "Unknown MAC"
            src_port, dst_port = "N/A", "N/A"
    
    # Kiểm tra nếu gói tin có lớp Ethernet để lấy địa chỉ MAC
            if Ether in packet:
                mac_src = packet[Ether].src
                mac_dst = packet[Ether].dst

    # Kiểm tra nếu gói tin có lớp IP để lấy thông tin IP và giao thức
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
            

    # Kiểm tra nếu gói tin là TCP hoặc UDP để lấy cổng
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
          
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
        
            protocol=self.identify_protocol(packet)
            info_dialog = InfoDialog(ip_src, ip_dst, protocol, mac_src, mac_dst, src_port, dst_port)
            info_dialog.exec()
    


    def show_conversation_stats_table(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo cửa sổ thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Conversation Statistics")
        stats_window.resize(1100, 600)

        layout = QVBoxLayout(stats_window)
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        protocols = {
            "IPv4": lambda pkt: IP in pkt,
            "IPv6": lambda pkt: IPv6 in pkt,
            "TCP": lambda pkt: TCP in pkt,
            "UDP": lambda pkt: UDP in pkt
        }

        for proto_name, condition in protocols.items():
            filtered_packets = [pkt for pkt in self.packets if condition(pkt)]

            # Lấy dữ liệu conversation
            conversation_data = {}

            for pkt in filtered_packets:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif IPv6 in pkt:
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                elif Ether in pkt:
                    src = pkt[Ether].src
                    dst = pkt[Ether].dst
                else:
                    continue

                length = len(pkt)
                key = tuple(sorted([src, dst]))

                if key not in conversation_data:
                    conversation_data[key] = {
                        "A": src,
                        "B": dst,
                        "packets_A_B": 0,
                        "packets_B_A": 0,
                        "bytes_A_B": 0,
                        "bytes_B_A": 0,
                        "start_time": pkt.time,
                        "end_time": pkt.time
                    }

                entry = conversation_data[key]
                if src == entry["A"] and dst == entry["B"]:
                    entry["packets_A_B"] += 1
                    entry["bytes_A_B"] += length
                else:
                    entry["packets_B_A"] += 1
                    entry["bytes_B_A"] += length

                entry["start_time"] = min(entry["start_time"], pkt.time)
                entry["end_time"] = max(entry["end_time"], pkt.time)

            rows = []
            for conv in conversation_data.values():
                duration = conv["end_time"] - conv["start_time"]
                bits_a_b = (conv["bytes_A_B"] * 8 / duration) if duration > 0 else 0
                bits_b_a = (conv["bytes_B_A"] * 8 / duration) if duration > 0 else 0

                rows.append({
                    "Address A": conv["A"],
                    "Address B": conv["B"],
                    "Total Packets": conv["packets_A_B"] + conv["packets_B_A"],
                    "Packets A → B": conv["packets_A_B"],
                    "Bytes A → B": int(conv["bytes_A_B"]),
                    "Packets B → A": conv["packets_B_A"],
                    "Bytes B → A": int(conv["bytes_B_A"]),
                    "Duration (s)": round(duration, 4),
                    "Bits/s A → B": int(bits_a_b),
                    "Bits/s B → A": int(bits_b_a)
                })

            df = pd.DataFrame(rows)

            tab = QWidget()
            tab_layout = QVBoxLayout(tab)

            table = QTableWidget(len(df), len(df.columns))
            table.setHorizontalHeaderLabels(df.columns.tolist())

            for i, row in df.iterrows():
                for j, val in enumerate(row):
                    item = QTableWidgetItem(str(val))
                    table.setItem(i, j, item)

            table.resizeColumnsToContents()
            table.setSortingEnabled(True)
            table.horizontalHeader().setSortIndicatorShown(True)
            table.horizontalHeader().setSectionsClickable(True)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

            # Sort toggle logic
            sort_order = {}

            def make_sort_handler(tbl, local_order):
                def on_header_clicked(index):
                    local_order[index] = not local_order.get(index, True)
                    order = Qt.SortOrder.AscendingOrder if local_order[index] else Qt.SortOrder.DescendingOrder
                    tbl.sortItems(index, order)
                    tbl.horizontalHeader().setSortIndicator(index, order)
                return on_header_clicked

            table.horizontalHeader().sectionClicked.connect(make_sort_handler(table, sort_order))
            tab_layout.addWidget(table)
            tab_widget.addTab(tab, proto_name)

        stats_window.setLayout(layout)
        stats_window.exec()

   
        
    def show_io_graphs(self):
        if not self.packets:
            QMessageBox.warning(self, "Warning", "No packets captured to show I/O graphs.")
            return

        self.io_graph_window = QtWidgets.QMainWindow(self)
        self.io_graph_window.setWindowTitle("I/O Graphs")
        central_widget = QWidget()
        self.io_graph_window.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Tính toán số lượng gói tin theo thời gian
        time_series = {}
        tcp_errors = {}
        for packet in self.packets:
            timestamp = int(packet.time - self.start_time)
            time_series[timestamp] = time_series.get(timestamp, 0) + 1
            if packet.haslayer(TCP) and hasattr(packet[TCP], 'flags') and packet[TCP].flags & 0x01: # Kiểm tra cờ FIN (ví dụ về một loại "lỗi" hoặc sự kiện kết thúc)
                tcp_errors[timestamp] = tcp_errors.get(timestamp, 0) + 1

        times = sorted(time_series.keys())
        all_packets_count = [time_series.get(t, 0) for t in times]
        tcp_error_count = [tcp_errors.get(t, 0) for t in times]

        # Tạo figure và axes
        self.figure = plt.figure(figsize=(10, 6))
        self.axes = self.figure.add_subplot(111)

        # Vẽ biểu đồ
        self.axes.plot(times, all_packets_count, label='All Packets')
        self.axes.bar(times, tcp_error_count, label='TCP Errors', color='red', alpha=0.7)

        self.axes.set_xlabel("Time (s)")
        self.axes.set_ylabel("Packets/sec")
        self.axes.set_title("I/O Graphs")
        self.axes.legend()
        self.axes.grid(True)

        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        self.toolbar = NavigationToolbar(self.canvas, self.io_graph_window)
        layout.addWidget(self.toolbar)

        self.io_graph_window.setGeometry(200, 200, 800, 600)
        self.io_graph_window.show()
    
    def show_table_context_menu(self, position):
        index = self.tableWidget.indexAt(position)
        if not index.isValid(): return
        row = index.row()
        if row >= len(self.packets_filter): return

        packet = self.packets_filter[row]
        menu = QMenu(self)

        # Chỉ giữ lại 4 chức năng cơ bản
        action_info = QAction("🔍 Xem Info (Wireshark-style)", self)
        action_hexdump = QAction("📄 Hex Dump", self)
        action_full = QAction("🧬 Chi tiết đầy đủ", self)
        action_http = QAction("🧬 Xem gói tin http", self)
        
        action_info.triggered.connect(lambda: self.show_packet_info(packet))
        action_hexdump.triggered.connect(lambda: self.show_packet_hexdump(packet))
        action_full.triggered.connect(lambda: self.show_packet_details(packet))
        action_http.triggered.connect(lambda: self.show_packet_http(packet))
        
        menu.addAction(action_info)
        menu.addAction(action_hexdump)
        menu.addAction(action_full)
        
        # Chỉ hiện nút Xem gói tin http nếu gói đó thực sự là HTTP
        if is_http_packet(packet):
            menu.addAction(action_http)
        
        menu.exec(self.tableWidget.viewport().mapToGlobal(position))

    def show_packet_info(self, packet):
        info = self.generate_packet_info(packet) 
        self.textEdit.setPlainText(info)

    def show_packet_hexdump(self, packet):
        from scapy.utils import hexdump
        hex_str = hexdump(packet, dump=True)
        self.textEdit.setPlainText(hex_str)

    def show_packet_details(self, packet):
        details = packet.show(dump=True)
        self.textEdit.setPlainText(details)

    def get_network_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            return list(interfaces.keys())  
        except Exception as e:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return []
        
    from PyQt6.QtWidgets import QMessageBox, QFileDialog

    def start_sniffing(self):
        self.start_time = time.time()
        iface = str(self.comboBox.currentText())
        if not iface:
            QMessageBox.critical(self, "Error", "Please select an interface!")
            return

        # Nếu đã có dữ liệu trước đó → hỏi có muốn lưu hay không
        if hasattr(self, "packets") and self.packets:
            reply = QMessageBox.question(
                self,
                "Save Capture?",
                "Bạn có muốn lưu lại dữ liệu gói tin trước đó (PCAP)?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                file_path, _ = QFileDialog.getSaveFileName(self, "Lưu File", "", "PCAP Files (*.pcap)")
                if file_path:
                    self.save_pcap = True
                    self.pcap_file_path = file_path
                    from scapy.utils import wrpcap
                    wrpcap(file_path, self.packets)
                    QMessageBox.information(self, "Đã Lưu", f"Đã lưu file tại:\n{file_path}")
                else:
                    QMessageBox.information(self, "Không Lưu", "Không chọn đường dẫn lưu file. Dữ liệu sẽ bị xóa.")
            # Dù chọn Yes hay No, nếu tới đây là tiếp tục bắt gói → xóa dữ liệu cũ
            self.packets = []
            self.packets_filter=[]

        # Nếu chưa có gì, hoặc vừa xử lý xong lưu → bắt đầu lại
        self.save_pcap = False
        self.pcap_file_path = None

        self.sniffing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.tableWidget.setRowCount(0)
        self.packet_counts = {}
        self.tcp_error_counts = {}

        threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True).start()


    def generate_packet_info(self, packet):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = packet.sprintf("%TCP.flags%")
            payload_len = len(packet[Raw]) if packet.haslayer(Raw) else 0
            return f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={payload_len}"

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            payload_len = len(packet[Raw]) if packet.haslayer(Raw) else 0
            return f"{udp.sport} → {udp.dport} Len={payload_len}"

        elif packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                if dns.qd and dns.qd.qname:
                    return f"DNS Query: {dns.qd.qname.decode(errors='ignore')}"
                else:
                    return "DNS Query"
            elif dns.qr == 1:  # Response
                if dns.an:
                    try:
                        answers = []
                        if isinstance(dns.an, list):
                            for ans in dns.an:
                                if hasattr(ans, "rdata"):
                                    answers.append(str(ans.rdata))
                        else:
                            if hasattr(dns.an, "rdata"):
                                answers.append(str(dns.an.rdata))
                        return "DNS Response: " + ", ".join(answers) if answers else "DNS Response"
                    except Exception:
                        return "DNS Response"
                else:
                    return "DNS Response"

        elif packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            method = http.Method.decode() if http.Method else "?"
            host = http.Host.decode() if http.Host else "?"
            path = http.Path.decode() if http.Path else "/"
            return f"HTTP {method} http://{host}{path}"

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            return f"ICMP Type={icmp.type} Code={icmp.code}"

        else:
            return "Unknown or unsupported protocol"
    def filter_packets(self):
        """
        Lọc gói tin dựa trên danh sách `self.packets` và bộ lọc nhập vào.
        """
        filter_text = self.plainTextEdit_4.toPlainText().strip()  # Lấy bộ lọc từ ô nhập liệu
        self.tableWidget.setRowCount(0)  # Xóa dữ liệu cũ trong bảng
        ctest = 0  # Biến đếm số gói tin phù hợp
        self.packets_filter=[]    

        # Xử lý các gói tin trong danh sách self.packets
        try:
            for i, packet in enumerate(self.packets):
                try:
                    # Lấy thông tin gói tin: IP, thời gian, chiều dài, giao thức
                    src_ip = packet[IP].src if packet.haslayer(IP) else (packet[Ether].src if packet.haslayer(Ether) else "Unknown")
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else (packet[Ether].dst if packet.haslayer(Ether) else "Unknown")
                    length = len(packet)
                    timestamp = packet.time
                    protocol = self.identify_protocol(packet)

                    # Sao chép gói tin để tránh thay đổi gói gốc
                    packet_copy = Ether(raw(packet))

                    # Nếu có filter và gói tin không khớp, bỏ qua
                    if filter_text and not self.packet_matches_filter(packet_copy, filter_text):
                        continue

                    # Nếu gói tin phù hợp với filter, thêm vào mảng packets_filter
                    self.packets_filter.append(packet)
                    ctest += 1

                    # Thêm gói tin vào bảng
                    row = self.tableWidget.rowCount()
                    self.tableWidget.insertRow(row)
                    self.tableWidget.setItem(row, 0, self.make_item(str(i + 1)))  # STT
                    self.tableWidget.setItem(row, 1, self.make_item(str(timestamp)))  # Thời gian
                    self.tableWidget.setItem(row, 2, self.make_item(src_ip))  # Nguồn
                    self.tableWidget.setItem(row, 3, self.make_item(dst_ip))  # Đích
                    self.tableWidget.setItem(row, 4, self.make_item(protocol))  # Giao thức
                    self.tableWidget.setItem(row, 5, self.make_item(str(length)))  # Chiều dài
                    self.tableWidget.setItem(row, 6, self.make_item(self.generate_packet_info(packet)))  # Thông tin

                except Exception as e_inner:
                    print(f"Lỗi xử lý gói tin: {e_inner}")

        except Exception as e_outer:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lọc gói tin: {str(e_outer)}")
    def packet_matches_filter(self, packet, filter_text):
        """
        Kiểm tra xem gói tin có khớp với bộ lọc không.
        Hỗ trợ lọc theo IP nguồn, IP đích, giao thức, độ dài gói tin, nội dung, cờ TCP và các giao thức DNS, HTTP, ICMP.
        """
        src_ip = packet[IP].src if packet.haslayer(IP) else (packet[Ether].src if packet.haslayer(Ether) else "Unknown")
        dst_ip = packet[IP].dst if packet.haslayer(IP) else (packet[Ether].dst if packet.haslayer(Ether) else "Unknown")
        packet_length = len(packet)
        protocol=self.identify_protocol(packet)
        try:
            if "ip.src==" in filter_text:
                ip_src_filter = filter_text.split("ip.src==")[1].strip()
                if src_ip == ip_src_filter:
                    return True

            if "ip.dst==" in filter_text:
                ip_dst_filter = filter_text.split("ip.dst==")[1].strip()
                if dst_ip == ip_dst_filter:
                    return True

            if "tcp" in filter_text.lower() and protocol=="TCP":
                return True
            if "tls" in filter_text.lower() and protocol=="TLSv1.2":
                return True
            if "udp" in filter_text.lower() and protocol=="UDP":
                return True
            
            if "icmp" in filter_text.lower() and protocol=="ICMP":
                return True
            
            if "dns" in filter_text.lower() and protocol=="DNS":
                return True
            
            if "http" in filter_text.lower() and  protocol=="HTTP" :
                if is_http_packet(packet):
                    return True
            
            if "frame.len>" in filter_text:
                length_threshold = int(filter_text.split("frame.len>")[1].strip())
                if packet_length > length_threshold:
                    return True
            
            if "frame contains" in filter_text:
                keyword = filter_text.split("frame contains")[1].strip().strip('"')
                if keyword.encode() in bytes(packet):
                    return True
            
            
            if "tcp.flags" in filter_text:
                flag_type = filter_text.split("tcp.flags==")[1].strip()
                if packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    if flag_type.lower() == "syn" and flags & 0x02:
                        return True
                    if flag_type.lower() == "ack" and flags & 0x10:
                        return True
                    if flag_type.lower() == "fin" and flags & 0x01:
                        return True
                    if flag_type.lower() == "rst" and flags & 0x04:
                        return True
                    if flag_type.lower() == "psh" and flags & 0x08:
                        return True
            
        except Exception as e:
            print(f"Lỗi khi kiểm tra bộ lọc: {e}")
            return False
        
        return False
    
 
 
    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.process_packet, store=True)

    def make_item(self,text):
        item = QTableWidgetItem(str(text))
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        return item
  
    def update_connection_counts(self,packet, src_ip, dst_ip, src_port, dst_port, proto):
        global connection_states, src_dport_counts, dst_sport_counts, dst_src_counts

        # Cập nhật số lượng kết nối theo giao thức
        if proto == 6:  # TCP
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer:
                flags = tcp_layer.sprintf('%TCP.flags%')
                connection_states[(src_ip, dst_ip)] = flags
                src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
                dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
                dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1

                # Cập nhật các bộ đếm thời gian tồn tại của kết nối
                ttl = packet[IP].ttl if IP in packet else 0
                connection_states[(src_ip, dst_ip, "ct_state_ttl")] = ttl
                connection_states[(src_ip, dst_ip, "ct_src_dport_ltm")] = tcp_layer.sport
                connection_states[(src_ip, dst_ip, "ct_dst_sport_ltm")] = tcp_layer.dport
                connection_states[(src_ip, dst_ip, "ct_dst_src_ltm")] = dst_src_counts[(src_ip, dst_ip)]

        elif proto == 17:  # UDP
            connection_states[(src_ip, dst_ip)] = 0  # Trạng thái 0 cho UDP
            src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
            dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
            dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1
        elif proto == 1:  # ICMP
            connection_states[(src_ip, dst_ip)] = 0  # Trạng thái 0 cho ICMP
            src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
            dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
            dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1

    def calculate_dload(self,packet):
        global last_time, last_size
        current_time = time.time()
        size = len(packet)
        if last_time is None:
            last_time = current_time
            last_size = size
            return 0.0
        else:
            # Tính tốc độ tải xuống tính bằng bit/giây
            dload = abs((size - last_size) / (current_time - last_time))
            last_time = current_time
            last_size = size
            return dload
    
    

    def process_packet(self, packet):
        """Hàm xử lý gói tin: Kết hợp Rule-based (Volume) và AI (Probability)"""
        if not self.sniffing:
            return

        try:
            # ----------------------------------------------------------------
            # 1. HIỂN THỊ LÊN TABLE UI (Giữ nguyên logic cũ)
            # ----------------------------------------------------------------
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            else:
                src = dst = "Unknown"

            timestamp = f"{packet.time - self.start_time:.6f}"
            info = self.generate_packet_info(packet)
            protocol_str = self.identify_protocol(packet)

            row_pos = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row_pos)
            self.tableWidget.setItem(row_pos, 0, self.make_item(str(row_pos + 1)))
            self.tableWidget.setItem(row_pos, 1, self.make_item(timestamp))
            self.tableWidget.setItem(row_pos, 2, self.make_item(src))
            self.tableWidget.setItem(row_pos, 3, self.make_item(dst))
            self.tableWidget.setItem(row_pos, 4, self.make_item(protocol_str))
            self.tableWidget.setItem(row_pos, 5, self.make_item(len(packet)))
            self.tableWidget.setItem(row_pos, 6, self.make_item(info))

            self.packets.append(packet)
            self.packets.append(packet)
            self.packets_filter.append(packet) # Thêm dòng này để đồng bộ dữ liệu hiển thị
            # ----------------------------------------------------------------
            # 2. QUẢN LÝ LUỒNG
            # ----------------------------------------------------------------
            if IP not in packet:
                return

            key = self.get_flow_key(packet)
            if not key:
                return

            self.update_flow(packet, key)
            flow = self.flow_table[key]
            current_time = time.time()
            
            # Tăng bộ đếm gói tin trong cửa sổ 2 giây
            flow['window_pkt_count'] = flow.get('window_pkt_count', 0) + 1

            if 'last_predict_time' not in flow:
                flow['last_predict_time'] = current_time

            time_since_last_predict = current_time - flow['last_predict_time']

            # ----1------------------------------------------------------------
            # 3. KIỂM TRA ĐIỀU KIỆN & DỰ ĐOÁN AI (MỖI 2 GIÂY)
            # ----------------------------------------------------------------
            if time_since_last_predict >= 2:
                pkt_in_2s = flow.get('window_pkt_count', 0)
                c = 1  
                if c==0  :
                    print(f"✅ [NORMAL] {key[0]} -> {key[1]} | Pkts/2s: {pkt_in_2s}")
                else:
                    # Trích xuất 16 đặc trưng
                    features = self.compute_features_from_flow(key)
                    # Gọi AI đánh giá
                    result = self.AI.predict_flow(features)
                    prob = result.get('probability', 0.0)

                    if prob >= 0.85:
                        # 1. Tạo nội dung cảnh báo
                        features_str = " | ".join([f"{k}: {v:.2f}" for k, v in features.items()])
                        alert_msg = (
                            f"🚨 [CẢNH BÁO DOS] Luồng: {key[0]}:{key[2]} -> {key[1]}:{key[3]}\n"
                            f"   LƯU LƯỢNG CAO: {pkt_in_2s} gói/2s | Xác suất AI: {prob:.4f}\n"
                            f"   Đặc trưng: [ {features_str} ]"
                        )

                        # 2. In ra màn hình console (Terminal)
                        print("\n" + "!"*80)
                        print(alert_msg)
                        print("!"*80 + "\n")

                        # 3. Ghi log vào file LogCanhBao.txt
                        try:
                            # Lấy thời gian thực tại thời điểm xảy ra cảnh báo
                            current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            with open("LogCanhBao.txt", "a", encoding="utf-8") as log_file:
                                log_file.write(f"[{current_time_str}]\n")
                                log_file.write(alert_msg + "\n")
                                log_file.write("-" * 80 + "\n")
                        except Exception as e_log:
                            print(f"❌ Lỗi khi ghi file log: {e_log}")

                        # 4. Bôi đỏ dòng vi phạm trên giao diện UI
                        try:
                            for col in range(self.tableWidget.columnCount()):
                                item = self.tableWidget.item(row_pos, col)
                                if item:
                                    item.setBackground(QtGui.QColor("#8B0000"))
                                    item.setForeground(QtGui.QColor("#FFDD00"))
                        except: pass
                    else:
                        # [NHÁNH 2: LƯU LƯỢNG CAO NHƯNG AI BẢO BÌNH THƯỜNG]
                    # In ra để soi xem tại sao AI không bắt (có thể do sload chưa đủ lớn hoặc dload vẫn cao)
                        print(f"✅ [NORMAL-AI] {key[0]} -> {key[1]} | Pkts/2s: {pkt_in_2s} ")
                        
                        # In 16 features hàng ngang để Phi dễ đối chiếu dữ liệu
                        features_horizontal = " | ".join([f"{k}: {v:.2f}" for k, v in features.items()])
                        print(f"   Đặc trưng: [ {features_horizontal} ]")
                        print("-" * 80)

                # --- RESET CHO CHU KỲ MỚI ---
                flow['window_pkt_count'] = 0
                flow['last_predict_time'] = current_time

            # 4. Cleanup
            if current_time - self.last_cleanup_time > 5:
                self.cleanup_old_flows()
                self.last_cleanup_time = current_time

        except Exception as e:
            pass

    def cleanup_old_flows(self):
        now = time.time()
        to_delete = []
        for key, flow in list(self.flow_table.items()):
            if now - flow.get('last_seen', 0) > self.FLOW_TIMEOUT * 2:
                to_delete.append(key)
        for key in to_delete:
            self.flow_table.pop(key, None)
        self.last_cleanup_time = now

    def identify_protocol(self , packet): 
        if packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(TCP):
            dport = packet[TCP].dport if packet.haslayer(TCP) else 0
            sport = packet[TCP].sport if packet.haslayer(TCP) else 0
            if is_http_packet(packet) :
                return "HTTP"
            if dport == 21:
                return "FTP"
            elif dport == 110:
                return "POP3"
            elif dport == 25:
                return "SMTP"
            elif dport == 23:
                return "Telnet"
            elif dport == 22:
                return "SSH"
            elif dport == 445:
                return "SMB"
            elif dport == 443 or sport==443:
                return "TLSv1.2"
            elif dport == 853:
                return "DNS over TLS"
            elif dport == 4433 or dport == 784 or dport == 8443:
                return "QUIC"
            elif dport == 1883:
                return "MQTT"
            return "TCP"
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport if packet.haslayer(UDP) else 0
            if dport == 123:
                return "NTP"
            elif dport == 5353:
                return "MDNS"
            elif dport == 1900:
                return "SSDP"
            elif dport == 3702:
                return "WS-Discovery"
            elif dport == 5683:
                return "CoAP"
            elif dport == 1812:
                return "RADIUS"
            elif dport == 4789:
                return "VXLAN"
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ICMPv6ND_NS):
            return "ICMPv6"
        elif packet.haslayer(IP):
            proto = packet[IP].proto
            if proto == 41:
                return "IPv6"
            elif proto == 2:
                return "IGMP"
            elif proto == 89:
                return "OSPF"
            return "Other IP"
        elif packet.haslayer(IPv6):
            return "IPv6"
        elif packet.haslayer(Ether):
            return "Ethernet"
        return "Other"

    def stop_sniffing(self):
        self.sniffing = False
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)

    def save_pcap(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Packet Capture",
            "",
            "PCAP files (*.pcap)"
        )
        if file_path:
            try:
                wrpcap(file_path, self.packets)
                QMessageBox.information(self, "Save", "Packets saved successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file:\n{e}")

    def load_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP File",
            "",
            "PCAP files (*.pcap)"
        )
        if file_path:
            try:
                self.packets = rdpcap(file_path)
                self.packets_filter=rdpcap(file_path)
              
                # self.tableWidget.setRowCount(0)  # Xoá hết dữ liệu cũ
                self.filter_packets()
                self.start_time = self.packets_filter[0].time if self.packets_filter else time.time()

                QMessageBox.information(self, "Load", "Packets loaded successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file:\n{e}")

    def reset_sniffing(self):
        self.stop_sniffing()
        self.packets.clear()
        self.packets_filter.clear()
        # Xoá bảng gói tin
        self.tableWidget.setRowCount(0)

        # Xoá nội dung text (nếu có vùng hiển thị chi tiết gói tin)
        self.textEdit.clear()

        # Bật lại nút Start
        self.start_button.setEnabled(True)

        QMessageBox.information(self, "Reset", "Sniffer đã được reset thành công!")

    def show_packet_size_stats(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Lấy danh sách kích thước gói tin
        packet_sizes = [len(packet) for packet in self.packets]

        # Tạo cửa sổ mới
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Kích thước Gói tin")
        stats_window.resize(600, 400)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.hist(packet_sizes, bins=30, color="blue", alpha=0.7)
        ax.set_title("Phân phối Kích thước Gói tin")
        ax.set_xlabel("Kích thước (bytes)")
        ax.set_ylabel("Số lượng")

        # Gắn biểu đồ vào canvas PyQt
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        stats_window.exec()

    def show_destination_stats(self):
    # Kiểm tra nếu không có gói tin
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Lọc các gói tin có lớp IP và lấy địa chỉ đích
        destination_ips = [p[IP].dst for p in self.packets if p.haslayer(IP)]
        
        if not destination_ips:
            QMessageBox.information(self, "Thông báo", "Không có gói tin có lớp IP.")
            return

        # Tạo DataFrame từ danh sách địa chỉ đích
        df = pd.DataFrame({
            "Destination": destination_ips
        })

        # Đếm tần suất địa chỉ đích
        destination_frequency = df["Destination"].value_counts()

        # Lọc địa chỉ có tần suất >= 10
        destination_frequency = destination_frequency[destination_frequency >= 10]

        # Kiểm tra nếu không có địa chỉ đích nào thỏa mãn
        if destination_frequency.empty:
            QMessageBox.information(self, "Thông báo", "Không có địa chỉ đích nào có tần suất trên 10!")
            return

        # Tạo cửa sổ hiển thị thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Địa chỉ Đích")
        stats_window.resize(800, 500)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ với các tùy chỉnh tốt hơn
        fig, ax = plt.subplots(figsize=(10, 5))
        destination_frequency.plot(kind="bar", color="skyblue", ax=ax)

        ax.set_xlabel("Địa chỉ đích", fontsize=12)
        ax.set_ylabel("Tần suất", fontsize=12)
        ax.set_title("Tần suất các địa chỉ đích xuất hiện", fontsize=14)
        
        # Thay đổi hướng nhãn trục X để chúng hiển thị theo chiều ngang
        ax.tick_params(axis='x', rotation=0, labelsize=10)  # rotation=0 để hiển thị ngang
        ax.grid(True, axis='y', linestyle='--', alpha=0.7)

        # Thêm chú thích cho mỗi cột trên biểu đồ
        for i, v in enumerate(destination_frequency):
            ax.text(i, v + 0.5, str(v), ha='center', va='bottom', fontsize=10)

        # Thêm vào canvas PyQt
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        # Hiển thị cửa sổ thống kê
        stats_window.exec()

    def show_source_stats(self):
    # Kiểm tra nếu không có gói tin
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Lọc các gói tin có lớp IP và lấy địa chỉ nguồn
        source_ips = [p[IP].src for p in self.packets if p.haslayer(IP)]
        
        if not source_ips:
            QMessageBox.information(self, "Thông báo", "Không có gói tin có lớp IP.")
            return

        # Tạo DataFrame từ danh sách địa chỉ nguồn
        df = pd.DataFrame({
            "Source": source_ips
        })

        # Thống kê tần suất địa chỉ nguồn
        source_frequency = df["Source"].value_counts()

        # Lọc địa chỉ có tần suất >= 20
        source_frequency = source_frequency[source_frequency >= 20]

        # Kiểm tra nếu không có địa chỉ nguồn nào thỏa mãn
        if source_frequency.empty:
            QMessageBox.information(self, "Thông báo", "Không có địa chỉ nguồn nào có tần suất trên 20!")
            return

        # Tạo cửa sổ hiển thị thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Địa chỉ Nguồn")
        stats_window.resize(800, 500)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ với các tùy chỉnh tốt hơn
        fig, ax = plt.subplots(figsize=(10, 5))
        source_frequency.plot(kind="bar", color="lightcoral", ax=ax)

        ax.set_xlabel("Địa chỉ nguồn", fontsize=12)
        ax.set_ylabel("Tần suất", fontsize=12)
        ax.set_title("Tần suất các địa chỉ nguồn xuất hiện", fontsize=14)
        
        # Thay đổi hướng nhãn trục X để chúng hiển thị theo chiều ngang
        ax.tick_params(axis='x', rotation=0, labelsize=10)  # rotation=0 để hiển thị ngang
        ax.grid(True, axis='y', linestyle='--', alpha=0.7)

        # Thêm chú thích cho mỗi cột trên biểu đồ
        for i, v in enumerate(source_frequency):
            ax.text(i, v + 0.5, str(v), ha='center', va='bottom', fontsize=10)

        # Thêm vào canvas PyQt
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        # Hiển thị cửa sổ thống kê
        stats_window.exec()
    
    def show_protocol_stats(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo DataFrame chứa tên giao thức
        df = pd.DataFrame({
            "protocol": [self.identify_protocol(p) for p in self.packets]
        })

        protocol_counts = df["protocol"].value_counts()

        # Tạo cửa sổ thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Giao thức")
        stats_window.resize(600, 400)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(6, 4))
        protocol_counts.plot(kind="bar", ax=ax, color="skyblue")
        ax.set_title("Phân phối Giao thức")
        ax.set_xlabel("Giao thức")
        ax.set_ylabel("Số lượng")
        ax.set_xticklabels(ax.get_xticklabels(), rotation=0, ha="center")

        # Gắn biểu đồ vào PyQt
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        stats_window.exec()

    def on_table_row_clicked(self, row, column):
        # Kiểm tra row có hợp lệ không
        if 0 <= row < len(self.packets_filter):
            packet = self.packets_filter[row]
            
            # Sử dụng dump=True để trả về chuỗi thay vì in ra console
            try:
                from scapy.utils import hexdump
                hex_str = hexdump(packet, dump=True)
                self.textEdit.setPlainText(hex_str)
            except Exception as e:
                self.textEdit.setPlainText(f"Lỗi hiển thị: {str(e)}")
                    

    def show_packet_http(self, packet):
        if is_http_packet(packet):
            http_text = parse_http_payload(packet)
            if http_text:
                dialog = HTTPDialog(http_text)
                dialog.exec()
            else:
                print("Không tìm thấy HTTP request trong gói tin này.")
        else:
            print("Đây không phải là gói HTTP.")
    
    def get_flow_key(self, packet):
        if IP not in packet:
            return None
        ip = packet[IP]
        proto = ip.proto
        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
        else:
            sport = dport = 0

        if (ip.src, sport) > (ip.dst, dport):
            return (ip.dst, ip.src, dport, sport, proto)
        return (ip.src, ip.dst, sport, dport, proto)

    def update_flow(self, packet, key):
        flow = self.flow_table[key] 
        now = float(packet.time)
        current_real_time = time.time()

        if flow['start_time'] is None:
            flow['start_time'] = now
            flow['src_ip'], flow['dst_ip'], flow['src_port'], flow['dst_port'], flow['protocol'] = key
            flow['sttl'] = packet[IP].ttl if IP in packet else 0
            flow['dttl'] = 0  
            
            #Khởi tạo trạng thái mặc định là INT (Incomplete)
            flow['state'] = 'INT' 

            flow['last_predict_time'] = current_real_time

        flow['last_time'] = now
        flow['last_seen'] = current_real_time

        if packet[IP].src == flow['src_ip']:
            flow['spkts'] += 1
            flow['sbytes'] += len(packet)
        else:
            flow['dpkts'] += 1
            flow['dbytes'] += len(packet)
            
            # Fix DTTL cho môi trường VMWare
            if flow.get('dttl', 0) == 0 and IP in packet:
                if packet[IP].ttl == 64:
                    flow['dttl'] = 252
                else:
                    flow['dttl'] = packet[IP].ttl

        # Bắt trạng thái TCP và thời gian thực hiện bắt tay (Handshake timing)
        if TCP in packet:
            flags = packet[TCP].flags
            if packet[IP].src == flow['src_ip']:
                flow['swin'] = packet[TCP].window
            else:
                flow['dwin'] = packet[TCP].window
                
            if flags & 0x04: # RST
                flow['state'] = 'RST'
            elif flags & 0x01: # FIN
                flow['state'] = 'FIN'
            elif flags & 0x02 and flags & 0x10: # SYN-ACK
                flow['state'] = 'CON'
                if flow.get('synack', 0) == 0:
                    flow['synack'] = now - flow['start_time']
            elif flags & 0x10 and flow.get('state') == 'CON': # ACK
                if flow.get('ackdat', 0) == 0:
                    flow['ackdat'] = now - flow['start_time'] - flow.get('synack', 0)

    def compute_features_from_flow(self, key):
        flow = self.flow_table[key]
        dur = max(flow['last_time'] - flow['start_time'], 1e-6)
        
        synack_val = float(flow.get('synack', 0))
        ackdat_val = float(flow.get('ackdat', 0))
        tcprtt_val = synack_val + ackdat_val if synack_val > 0 else 0.0

        return {
            #  Làm mềm feature bằng tỷ lệ thay vì hằng số chết 1.0
            "ct_state_ttl": float(flow['sttl'] / 255.0), 
            "dttl": float(flow.get('dttl', flow['sttl'])),
            "sttl": float(flow['sttl']),
            "dload": (flow['dbytes'] * 8.0) / dur,
            
            # Dùng số lượng gói tin làm proxy mô phỏng số kết nối (động đậy theo traffic)
            "ct_dst_src_ltm": float(min(flow.get('spkts', 1) + 1, 50)),
            
            "dbytes": float(flow['dbytes']),
            "sbytes": float(flow['sbytes']),
            "sload": (flow['sbytes'] * 8.0) / dur,
            "tcprtt": tcprtt_val,
            "synack": synack_val,
            "ackdat": ackdat_val,
            "dwin": float(flow.get('dwin', 0)),
            "swin": float(flow.get('swin', 0)),
            "proto_tcp": 1.0 if flow['protocol'] == 6 else 0.0,
            "proto_udp": 1.0 if flow['protocol'] == 17 else 0.0,
            "state_INT": 1.0 if flow['state'] == "INT" else 0.0,
        }

    def cleanup_old_flows(self):
        now = time.time()
        to_delete = [key for key, flow in self.flow_table.items() 
                     if now - flow.get('last_seen', 0) > self.FLOW_TIMEOUT * 2]
        for key in to_delete:
            self.flow_table.pop(key, None)
        self.last_cleanup_time = now

if __name__ == "__main__":
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    app = QApplication(sys.argv)
    window = NetSentinel()
    window.show()
    sys.exit(app.exec())
