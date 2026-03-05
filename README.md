# Cloud-API-Based-Network-Application-Security-for-Small-Company-Services
project-root/
  ├─ infra/              # Container orchestration details
  │  ├─ docker-compose.yml 
  │  └─ setup.sh         # Helper script for initialization
  ├─ services/           # Backend microservices logic
  │  ├─ user/            # (Future logic placeholder)
  │  ├─ admin/           # (Future logic placeholder)
  │  └─ order-service/   # Target application
  │     ├─ Dockerfile
  │     ├─ index.js      # App code embodying vulnerabilities
  │     └─ package.json
  ├─ gateway/            # Security layer implementations
  │  └─ kong.yml         # Defines API policies and constraints
  ├─ idp/                # Identity configurations
  │  └─ realm-export.json
  ├─ tests/              # Security validation scripts
  │  ├─ attack_bola.py   # Penetration script
  │  └─ requirements.txt
  └─ docs/               # Architecture logic and outcomes
     └─ final_report.md  # Where you log outcomes (e.g., SSRF results)
