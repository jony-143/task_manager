from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    TITLE: str = "Task Manager API"
    DATABASE_URL: str
    TEST_DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    USER_DEFAULT_LIMIT: int = 100
    USER_MAX_LIMIT: int = 1000
    TASK_DEFAULT_LIMIT: int = 100
    TASK_MAX_LIMIT: int = 1000
    MAX_OFFSET: int = 10000
    model_config = SettingsConfigDict(env_file=Path(__file__).parent / ".env")


settings = Settings()  # type: ignore
