import pandas as pd
import numpy as np
import joblib
import time
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve

# Danh sách 4 file dữ liệu
DATA_FILES = ["UNSW-NB15_1.csv", "UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv"]

# 16 Features mục tiêu của bạn (Map chính xác theo tên cột bạn vừa gửi)
FEATURES = [
    'ct_state_ttl', 'dttl', 'sttl', 'dload', 'ct_dst_src_ltm', 'dbytes', 
    'sbytes', 'sload', 'tcprtt', 'synack', 'ackdat', 'dwin', 'swin', 
    'proto_tcp', 'proto_udp', 'state_INT'
]

# Tên tất cả 49 cột theo thứ tự bạn đã cung cấp
COL_NAMES = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 
    'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 
    'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 
    'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 
    'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 
    'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 
    'attack_cat', 'Label'
]

def train_model():
    start_all = time.time()
    
    # [1/9] Đọc và gộp dữ liệu
    print("[1/9] 📂 Đang nạp dữ liệu từ 4 file CSV (Mode: No Header)...")
    data_list = []
    for file in DATA_FILES:
        if os.path.exists(file):
            print(f"   + Đang đọc {file}...")
            # Đọc không header và gán COL_NAMES
            temp_df = pd.read_csv(file, header=None, names=COL_NAMES, low_memory=False) 
            data_list.append(temp_df)
    
    df = pd.concat(data_list, ignore_index=True)
    print(f"✅ Tổng số bản ghi nạp được: {len(df):,}")

    # [2/9] Tiền xử lý dữ liệu (Preprocessing)
    print("[2/9] 🛠️ Đang xử lý đặc trưng (Mapping Features)...")
    
    # Chuyển đổi các cột phân loại (proto, state) sang nhị phân cho 16 features
    df['proto_tcp'] = df['proto'].apply(lambda x: 1 if str(x).lower() == 'tcp' else 0)
    df['proto_udp'] = df['proto'].apply(lambda x: 1 if str(x).lower() == 'udp' else 0)
    df['state_INT'] = df['state'].apply(lambda x: 1 if str(x).upper() == 'INT' else 0)
    
    # Các cột số (Sload, Dload trong data gốc viết hoa chữ đầu, cần map về sload, dload của bạn)
    df['sload'] = pd.to_numeric(df['Sload'], errors='coerce').fillna(0)
    df['dload'] = pd.to_numeric(df['Dload'], errors='coerce').fillna(0)
    
    # Đảm bảo các cột khác là dạng số
    for col in ['ct_state_ttl', 'dttl', 'sttl', 'ct_dst_src_ltm', 'dbytes', 'sbytes', 
                'tcprtt', 'synack', 'ackdat', 'dwin', 'swin']:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # [3/9] Lọc mẫu theo yêu cầu: Hết DoS + 24k Normal
    print(f"[3/9] ✂️ Đang lọc: Toàn bộ mẫu DoS và 24,000 mẫu Bình thường...")
    
    # Lọc DoS dựa trên attack_cat (xóa khoảng trắng thừa)
    df['attack_cat_clean'] = df['attack_cat'].astype(str).str.strip()
    df_dos = df[df['attack_cat_clean'].str.contains('DoS', case=False, na=False)]
    
    # Lọc Bình thường dựa trên Label = 0
    df_normal = df[df['Label'] == 0].sample(n=24000, random_state=42)
    
    df_train = pd.concat([df_dos, df_normal]).sample(frac=1, random_state=42)
    print(f"✅ Đã lọc xong: {len(df_dos)} mẫu DoS, {len(df_normal)} mẫu Bình thường.")

    # [4/9] Chuẩn bị X, y
    X = df_train[FEATURES]
    y = df_train['Label']

    # [5/9] Chia dữ liệu 70/15/15
    print("[5/9] 🧱 Chia dữ liệu: 70% Train - 15% Val - 15% Test...")
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42)

    # [6/9] Huấn luyện Random Forest
    print("[6/9] 🚀 Đang huấn luyện Random Forest (200 trees)...")
    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)

    # [7/9] Tìm ngưỡng tối ưu trên tập Validation
    y_val_probs = rf.predict_proba(X_val)[:, 1]
    p, r, t = precision_recall_curve(y_val, y_val_probs)
    f1 = 2*p*r/(p+r+1e-10)
    best_threshold = t[np.argmax(f1)]
    print(f"🔥 Ngưỡng (Threshold) tối ưu: {best_threshold:.6f}")

    # [8/9] Đánh giá trên tập Test
    print("[8/9] 📝 Kết quả trên tập TEST (Dữ liệu hoàn toàn mới):")
    y_test_probs = rf.predict_proba(X_test)[:, 1]
    y_test_pred = (y_test_probs > best_threshold).astype(int)
    
    print("\n" + "="*45)
    print("=== FINAL CLASSIFICATION REPORT ===")
    print(classification_report(y_test, y_test_pred, digits=4))
    print("=== CONFUSION MATRIX ===")
    print(confusion_matrix(y_test, y_test_pred))
    print("="*45 + "\n")

    # [9/9] Lưu mô hình
    print("[9/9] 💾 Đang ghi đè file model pkl...")
    joblib.dump(rf, "RF_DoS_Model_Balanced_800K.pkl")
    joblib.dump(FEATURES, "features_config.pkl")
    joblib.dump(best_threshold, "best_threshold.pkl")

    print(f"✅ HOÀN TẤT! Tổng thời gian xử lý: {time.time() - start_all:.2f}s")

if __name__ == "__main__":
    train_model()