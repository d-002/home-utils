import sqlite3

from fastapi import HTTPException


class DataBase:
    def __init__(self, path: str, reset: bool = False) -> None:
        self.path = path
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()

        if reset:
            self.reset_db()
        self.init_db()

    def reset_db(self) -> None:
        self.cur.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        """)
        tables_names = [col[0] for col in self.cur.fetchall()]

        for table_name in tables_names:
            self.cur.execute(f'DROP TABLE IF EXISTS {table_name}')
        self.con.commit()
        self.init_db()

    def init_db(self) -> None:
        self.cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            signing_key TEXT,
            password_hash TEXT
        )
        """)
        self.cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            website TEXT,
            username TEXT,
            password TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)
        self.con.commit()

    def close(self) -> None:
        self.con.close()

    def add_user(self, signing_key: str, password_hash: str):
        self.cur.execute(
            """
        SELECT id
        FROM users
        WHERE users.signing_key = ?
        """,
            [signing_key],
        )
        if self.cur.fetchone() is not None:
            raise HTTPException(400, 'user already exists')

        self.cur.execute(
            """
        INSERT INTO users (signing_key, password_hash)
        VALUES (?, ?)
        """,
            [signing_key, password_hash],
        )
        self.con.commit()

    def delete_user(self, signing_key: str):
        self.cur.execute(
            """
        SELECT id
        FROM users
        WHERE users.signing_key = ?
        """,
            [signing_key],
        )
        col = self.cur.fetchone()
        if col is None:
            raise HTTPException(404, 'user does not exist')
        user_id: int = col[0]

        # first delete all passwords from this user
        self.cur.execute("""
        DELETE FROM passwords
        WHERE passwords.user_id = ?
        """, [user_id])

        # then delete the actual user
        self.cur.execute(
            """
        DELETE FROM users
        WHERE users.signing_key = ?
        """,
            [signing_key],
        )
        self.con.commit()

    def add_password(
        self, signing_key: str, website: str, username: str, password: str
    ):
        self.cur.execute(
            """
        SELECT id
        FROM users
        WHERE users.signing_key = ?
        """,
            [signing_key],
        )
        col = self.cur.fetchone()
        if col is None:
            raise HTTPException(404, 'user does not exist')
        user_id: int = col[0]

        self.cur.execute(
            """
        INSERT INTO passwords (user_id, website, username, password)
        VALUES (?, ?, ?, ?)
        """,
            [user_id, website, username, password],
        )
        self.con.commit()

    def get_password_hash(self, signing_key: str) -> dict:
        self.cur.execute("""
        SELECT password_hash
        FROM users
        WHERE users.signing_key = ?
        """, [signing_key])

        col = self.cur.fetchone()
        if col is None:
            raise HTTPException(404, 'user does not exist')
        return {'password_hash': col[0]}

    def delete_password(
        self, signing_key: str, website: str, username: str, password: str
    ):
        self.cur.execute(
            """
        SELECT id
        FROM users
        WHERE users.signing_key = ?
        """,
            [signing_key],
        )
        col = self.cur.fetchone()
        if col is None:
            raise HTTPException(404, 'user does not exist')
        user_id: int = col[0]

        self.cur.execute(
            """
        DELETE FROM passwords
        WHERE passwords.user_id = ?
        AND passwords.website = ?
        AND passwords.username = ?
        AND passwords.password = ?
        """,
            [user_id, website, username, password],
        )
        self.con.commit()

        if self.cur.rowcount == 0:
            raise HTTPException(404, 'password entry does not exist')

    def patch_password(
        self,
        signing_key: str,
        website_old: str,
        website_new: str,
        username_old: str,
        password_old: str,
        username_new: str,
        password_new: str,
    ):
        self.delete_password(
            signing_key, website_old, username_old, password_old
        )
        self.add_password(signing_key, website_new, username_new, password_new)

    def _res_to_json(self, res: list[tuple]):
        entries = []
        for id, website, username, password in res:
            entries.append(
                {
                    'id': id,
                    'website': website,
                    'username': username,
                    'password': password,
                }
            )
        return {'passwords': entries}

    def all_passwords(self, signing_key: str) -> dict:
        self.cur.execute(
            """
        SELECT
            passwords.id,
            passwords.website,
            passwords.username,
            passwords.password
        FROM passwords
        JOIN users
        ON passwords.user_id = users.id
        WHERE users.signing_key = ?
        """,
            [signing_key],
        )

        res = self.cur.fetchall()
        if res is None:
            raise HTTPException(404, 'passwords not found for user')

        return self._res_to_json(res)

    def website_passwords(self, signing_key: str, website: str) -> dict:
        self.cur.execute(
            """
        SELECT
            passwords.id,
            passwords.website,
            passwords.username,
            passwords.password
        FROM passwords
        JOIN users
        ON passwords.user_id = users.id
        WHERE users.signing_key = ?
        AND passwords.website = ?
        """,
            [signing_key, website],
        )

        res = self.cur.fetchall()
        if res is None:
            raise HTTPException(404, 'passwords not found for user and website')

        return self._res_to_json(res)
