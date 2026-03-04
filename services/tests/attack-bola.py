import requests
import time

BASE_URL = "http://localhost:8000/api/v1/orders"
HEADERS = {"apikey": "key-user-A"}

def test_bola():
    print("\n--- BẮT ĐẦU KIỂM THỬ LỖ HỔNG BOLA ---")
    print("[*] Đang đóng vai User A, cố gắng truy cập đơn hàng '102' của User B...")
    
    target_url = f"{BASE_URL}/102"
    response = requests.get(target_url, headers=HEADERS)
    
    if response.status_code == 200:
        print("[!] TẤN CÔNG BOLA THÀNH CÔNG! Dữ liệu bị rò rỉ:")
        print(response.json())
    else:
        print(f"[-] Hệ thống an toàn. Bị chặn với mã lỗi: {response.status_code}")

def test_rate_limiting():
    print("\n--- BẮT ĐẦU KIỂM THỬ RATE LIMITING (DDoS/Spam) ---")
    print("[*] Gửi 15 request liên tục (Giới hạn của hệ thống là 10 req/phút)...")
    
    for i in range(1, 16):
        res = requests.get(f"{BASE_URL}/101", headers=HEADERS)
        if res.status_code == 429:
            print(f"[{i}] Request bị Gateway CHẶN! (429 Too Many Requests)")
            break
        else:
            print(f"[{i}] Request thành công (200 OK)")
        time.sleep(0.1)

if __name__ == "__main__":
    test_bola()
    test_rate_limiting()