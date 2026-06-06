import sqlite3

class DataBase:
    def __init__(self, path):
        self.path = path
        self.con = sqlite3.connect(path)
        self.con.row_factory = sqlite3.Row
        self.cur = self.con.cursor()

        self.init_db()

    def reset_db(self):
        for table_name in []:
            self.cur.execute('DROP TABLE IF EXISTS ?', [table_name])
        self.init_db()

    def init_db(self):
        pass

    def close(self):
        self.con.close()
