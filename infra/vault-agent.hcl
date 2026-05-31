auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/etc/vault-ids/role-id"
      secret_id_file_path = "/etc/vault-ids/secret-id"
      
      # 👇 FIX VẤN ĐỀ 5: Đọc xong Secret ID là phải xóa ngay để chống lộ lọt
      remove_secret_id_file_after_reading = true
    }
  }

  sink "file" {
    config = {
      path = "/app/vault-token-share/.vault-token"
    }
  }
}

vault {
  address = "https://vault-server:8200"
  ca_cert = "/vault/certs/ca.crt"
  
  # 👇 FIX VẤN ĐỀ 1: Phải trỏ đúng tên miền của Vault Server
  tls_server_name = "vault-server" 
}

# 👇 FIX VẤN ĐỀ 4: Gộp chung thành 1 template JSON cho Order Service
template {
  destination = "/vault/certs/order-bundle.json"
  contents = <<EOF
{{- with secret "pki/issue/microservices" "common_name=backend-order-api" "alt_names=localhost" "ip_sans=127.0.0.1" "ttl=24h" -}}
{{ .Data | toJSON }}
{{- end -}}
EOF
}

# 👇 FIX VẤN ĐỀ 4: Gộp chung thành 1 template JSON cho Product Service
template {
  destination = "/vault/certs/product-bundle.json"
  contents = <<EOF
{{- with secret "pki/issue/microservices" "common_name=backend-product-api" "alt_names=localhost" "ip_sans=127.0.0.1" "ttl=24h" -}}
{{ .Data | toJSON }}
{{- end -}}
EOF
}