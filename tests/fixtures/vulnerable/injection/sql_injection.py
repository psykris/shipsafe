# Intentionally vulnerable: SQL injection via string formatting
import sqlite3

conn = sqlite3.connect("app.db")
cursor = conn.cursor()


def get_user(username):
    # VULNERABLE: f-string interpolation in SQL
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()


def search_products(name):
    # VULNERABLE: .format() in SQL
    query = "SELECT * FROM products WHERE name = '{}'".format(name)
    cursor.execute(query)
    return cursor.fetchall()


def delete_record(record_id):
    # VULNERABLE: % formatting in SQL execute
    cursor.execute("SELECT * FROM records WHERE id = %s" % (record_id,))
