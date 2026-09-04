from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "Chat E2EE"
    debug: bool = True
    database_url: str = "postgresql://seu_usuario:sua_senha@localhost:5432/chat_e2ee_db"

    class Config:
        env_file = ".env"

settings = Settings()
