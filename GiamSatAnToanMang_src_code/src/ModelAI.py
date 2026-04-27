import joblib
import pandas as pd
import numpy as np

class ModelAI:
    def __init__(self, 
                 model_path="DoS_Model.pkl",
                 features_path="features_config.pkl",
                 threshold_path="best_threshold.pkl"):
        
        print("="*50)
        print("🚀 Đang nạp Model Random Forest DoS ...")
        try:
            # Nạp bộ não, danh sách tính năng và ngưỡng tối ưu
            self.model = joblib.load(model_path)
            self.features = joblib.load(features_path)
            self.threshold = joblib.load(threshold_path)
            
            print(f"✅ Nạp model thành công!")
            print(f"   • Model path     : {model_path}")
            print(f"   • Số features    : {len(self.features)}")
            print("="*50)
            
        except FileNotFoundError as e:
            print(f"❌ Không tìm thấy file hệ thống: {e}")
            print("Vui lòng đảm bảo các file .pkl nằm cùng thư mục với main.py")
            self.model = None
        except Exception as e:
            print(f"❌ Lỗi nghiêm trọng khi khởi tạo AI: {e}")
            self.model = None

    def predict_flow(self, flow_dict):
        """Dự đoán một luồng có phải DoS không dựa trên 16 đặc trưng trích xuất"""
        if self.model is None:
            return {"is_anomaly": False, "label": "LỖI MODEL", "probability": 0.0}

        try:
            # 1. Sắp xếp dữ liệu đầu vào ĐÚNG THỨ TỰ mà model đã học
            # Ép kiểu float32 để đồng bộ với quá trình training
            input_values = []
            for feat in self.features:
                val = flow_dict.get(feat, 0.0)
                input_values.append(float(val))

            # 2. Chuyển thành định dạng numpy array hoặc DataFrame
            # Sử dụng DataFrame để giữ lại tên cột (tránh cảnh báo của scikit-learn)
            X = pd.DataFrame([input_values], columns=self.features).astype('float32')
            
            # 3. Thực hiện dự đoán xác suất
            # [0, 1] là xác suất của class 1 (DoS)
            probs = self.model.predict_proba(X)[0]
            prob_dos = probs[1]
            
            # 4. So sánh với ngưỡng tự động (Threshold Tuning)
            is_dos = prob_dos > self.threshold
            
            return {
                "is_anomaly": bool(is_dos),
                "label": "🚨 BẤT THƯỜNG (DoS)" if is_dos else "✅ BÌNH THƯỜNG",
                "probability": round(float(prob_dos), 4),
                "threshold": self.threshold,
                "attack_type": "DoS" if is_dos else "BENIGN"
            }

        except Exception as e:
            print(f"❌ Lỗi thực thi dự đoán: {e}")
            return {"is_anomaly": False, "label": "LỖI DỰ ĐOÁN", "probability": 0.0}