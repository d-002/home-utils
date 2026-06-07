import os

from db import DataBase
from api import setup_api


def get_db_path() -> str:
    path = os.getenv('DB_PATH')
    if path is None:
        raise ValueError('Please specify the DB_PATH environment variable')
    if os.path.isdir(path):
        raise ValueError(f'Specified database file is a directory: {path}')

    return path


db = DataBase(get_db_path())
app = setup_api(db)
