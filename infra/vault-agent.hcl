auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/etc/vault/role-id"
      secret_id_file_path = "/etc/vault/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "file" {
    config = {
      path = "/app/vault-token-share/.vault-token"
    }
  }
}
vault {
  address = "http://vault-server:8200"
}
exit_after_auth = false