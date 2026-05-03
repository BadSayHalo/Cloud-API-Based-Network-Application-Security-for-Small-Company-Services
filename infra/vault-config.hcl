# Giao diện quản lý
ui = true

# Khai báo nơi lưu trữ dữ liệu (Consul)
storage "consul" {
  address = "consul-storage:8500"
  path    = "vault/"
}

# Cấu hình Listener (Cổng giao tiếp)
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1 # Chạy HTTP nội bộ cho đơn giản, SSL đã có Kong lo
}

# Vô hiệu hóa mlock (nếu Docker không cấp quyền RAM)
disable_mlock = true