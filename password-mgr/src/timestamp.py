from db import DataBase

from fastapi import HTTPException


class TimestampHandler:
    def __init__(self) -> None:
        self.timestamps = self.get_persisted_timestamps()

    def get_persisted_timestamps(self) -> dict[str, float]:
        return {}

    def check_valid_timestamp(self, signing_key: str, timestamp: float) -> None:
        if timestamp <= self.timestamps.get(signing_key, 0):
            raise HTTPException(403, 'Old request detected, cannot send again')

    def persist_timestamp(self, signing_key: str, timestamp: float) -> None:
        self.timestamps[signing_key] = timestamp


class DataBaseTimestampHandler(TimestampHandler):
    def __init__(self, db: DataBase) -> None:
        self.db = db
        super().__init__()

    def get_persisted_timestamps(self) -> dict[str, float]:
        return self.db.get_all_timestamps()

    def persist_timestamp(self, signing_key: str, timestamp: float) -> None:
        super().persist_timestamp(signing_key, timestamp)
        self.db.update_last_timestamp(signing_key, timestamp)
