import mysql.connector
from mysql.connector import Error

class Database:
    def __init__(self):
        try:
            self.conn = mysql.connector.connect(
                host='localhost',
                user='root',
                password='',  
                database='health_tracking_db'
            )
            self.cursor = self.conn.cursor(dictionary=True)
            print("Successfully connected to the database.")
        except Error as e:
            print(f"Error connecting to database: {e}")
            raise

    def execute_query(self, query, params=None):
        try:
            self.cursor.execute(query, params or ())
            return self.cursor
        except Error as e:
            print(f"Error executing query: {e}")
            raise

    def commit(self):
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()