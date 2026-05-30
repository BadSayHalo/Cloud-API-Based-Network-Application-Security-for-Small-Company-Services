# Giao diện quản lý
ui = true

# Khai báo nơi lưu trữ dữ liệu (Consul)
storage "consul" {
  address = "consul-storage:8500"
  path    = "vault/"
}

# Cấu hình Listener (Cổng giao tiếp)
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/vault/certs/vault-bundle.crt"
  tls_key_file  = "/vault/certs/vault.key"
  tls_ca_file   = "/vault/certs/ca.crt"
}

# Vô hiệu hóa mlock (nếu Docker không cấp quyền RAM)
disable_mlock = true