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
  
  tls_key_file  = "/dev/shm/vault-clear.key"
  
  # XÓA HẲN 2 dòng tls_ca_file và tls_key_file_password đi
}

# Thêm địa chỉ tự định danh cho Cluster
api_addr     = "https://vault-server:8200"
cluster_addr = "https://vault-server:8201"

# Vô hiệu hóa mlock
disable_mlock = true