# Giao diện quản lý
ui = true

# Khai báo nơi lưu trữ dữ liệu
storage "consul" {
  address = "consul-storage:8500"
  path    = "vault/"
}

# Cấu hình Listener
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = 0
  tls_cert_file = "/vault/certs/vault-bundle.crt"
  tls_key_file  = "/vault/certs/vault.key"
  tls_ca_file   = "/vault/certs/ca.crt"
}

# 👇 FIX VẤN ĐỀ 3: Thêm địa chỉ tự định danh cho Cluster
api_addr     = "https://vault-server:8200"
cluster_addr = "https://vault-server:8201"

# Vô hiệu hóa mlock (Cần ghi chú tradeoff này vào báo cáo)
disable_mlock = true