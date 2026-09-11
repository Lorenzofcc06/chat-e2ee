from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "Chat E2EE"
    debug: bool = True
    database_url: str = "postgresql://chat_api_user:senha_forte_api_123@localhost:5432/chat_e2ee_db"
    
    # Segurança e Autenticação JWT
    secret_key: str = "super_secret_e2ee_token_key_change_in_production_987654321"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440  # 24 horas

    # Defesa contra Exaustão de Recursos (DoS)
    rate_limit_login_per_minute: int = 10
    rate_limit_general_per_minute: int = 120
    max_payload_size_bytes: int = 65536  # 64 KB

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
