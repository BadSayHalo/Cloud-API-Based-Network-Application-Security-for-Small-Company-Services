auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/etc/vault-ids/role-id"
      secret_id_file_path = "/etc/vault-ids/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "file" {
    config = {
      path = "/app/vault-token-share/.vault-token"
    }
  }
}

# CẬP NHẬT PHẦN NÀY ĐỂ KẾT NỐI HTTPS
vault {
  address = "https://vault-server:8200"
  ca_cert = "/vault/certs/ca.crt"
  tls_server_name = "localhost"
}

exit_after_auth = false