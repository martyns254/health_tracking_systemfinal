import hashlib
import os

class Auth:
    def __init__(self, db):
        self.db = db

    def register_user(self, username, password, email):
        try:
            # Hash the password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            query = """
                INSERT INTO users (username, password_hash, email)
                VALUES (%s, %s, %s)
            """
            self.db.execute_query(query, (username, password_hash, email))
            self.db.commit()
            return True
        except Exception as e:
            print(f"Error registering user: {e}")
            return False