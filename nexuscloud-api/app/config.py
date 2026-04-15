from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    nexuscloud_db_host: str = "postgres"
    nexuscloud_db_port: int = 5432
    nexuscloud_db_name: str = "nexuscloud"
    nexuscloud_db_user: str = "nexus"
    nexuscloud_db_password: str = "nexus_secret_2024"
    nexuscloud_secret_key: str = "nc-jwt-secret-key-change-in-prod"
    redis_url: str = "redis://redis:6379/0"

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.nexuscloud_db_user}:{self.nexuscloud_db_password}@{self.nexuscloud_db_host}:{self.nexuscloud_db_port}/{self.nexuscloud_db_name}"

    class Config:
        env_file = ".env"

settings = Settings()
