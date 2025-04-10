import mysql.connector

try:
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",  # Default XAMPP password is empty
        database="health_tracking_db"
    )
    if connection.is_connected():
        print("Successfully connected to the database!")
        cursor = connection.cursor()
        cursor.execute("SELECT DATABASE()")
        db = cursor.fetchone()
        print("You're connected to database:", db)

except mysql.connector.Error as err:
    print(f"Error: {err}")

finally:
    if 'connection' in locals() and connection.is_connected():
        cursor.close()
        connection.close()
        print("MySQL connection is closed")