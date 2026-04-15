from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    sentinel_db_host: str = "postgres"
    sentinel_db_port: int = 5432
    sentinel_db_name: str = "sentinel"
    sentinel_db_user: str = "sentinel"
    sentinel_db_password: str = "sentinel_secret_2024"
    sentinel_redis_url: str = "redis://redis:6379/0"
    sentinel_nexuscloud_url: str = "http://nexuscloud-api:8000"
    sentinel_prometheus_url: str = "http://prometheus:9090"
    anthropic_api_key: str = ""

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.sentinel_db_user}:{self.sentinel_db_password}@{self.sentinel_db_host}:{self.sentinel_db_port}/{self.sentinel_db_name}"

    class Config:
        env_file = ".env"

settings = Settings()
