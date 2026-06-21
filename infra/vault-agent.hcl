auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/etc/vault-ids/role-id"
      secret_id_file_path = "/etc/vault-ids/secret-id"
      
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
  
  tls_server_name = "vault-server" 
}

template {
  destination = "/vault/certs/order-bundle.json"
  contents = <<EOF
{{- with secret "pki/issue/microservices" "common_name=backend-order-api" "alt_names=localhost" "ip_sans=127.0.0.1" "ttl=24h" -}}
{{ .Data | toJSON }}
{{- end -}}
EOF
}

template {
  destination = "/vault/certs/product-bundle.json"
  contents = <<EOF
{{- with secret "pki/issue/microservices" "common_name=backend-product-api" "alt_names=localhost" "ip_sans=127.0.0.1" "ttl=24h" -}}
{{ .Data | toJSON }}
{{- end -}}
EOF
}