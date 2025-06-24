import hashlib
import sqlite3
import os
import binascii

# Create user db
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Create user table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT,
    salt TEXT
)
''')
conn.commit()

def generate_salt():
    """Generate random salt."""
    return binascii.hexlify(os.urandom(16)).decode()

def hash_password(password, salt):
    """ Hash password with provided salt."""
    salted_password = password + salt
    md5_hash = hashlib.md5(salted_password.encode()).hexdigest()
    return md5_hash

def register_user(username, password):
    """Register a new user."""
    # Generate a unique salt for this user
    salt = generate_salt()

    # Hash the password with the salt
    password_hash = hash_password(password, salt)

    try:
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password_hash, salt))
        conn.commit()
        print(f"User {username} registered successfully.")
    except sqlite3.IntegrityError:
        print(f"Username {username} already exists.")

def authenticate_user(username, password):
    """Authenticate user."""
    cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if not result:
        print("Authentication failed: Invalid username")
        return False

    salt = result[0]

    # Hash password with retrieved salt
    password_hash = hash_password(password, salt)

    # Check if calculated hash matches stored hash
    cursor.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?",
                  (username, password_hash))
    user = cursor.fetchone()

    if user:
        print(f"Authentication successful for user: {username}")
        return True
    else:
        print("Authentication failed: Invalid password")
        return False

# Example usage
if __name__ == "__main__":
    # Register some users
    register_user("user1", "password123")
    register_user("user2", "password123")

    # Query db
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    print("\nUsers in database:")
    for user in users:
        print(f"Username: {user[0]}, Password Hash: {user[1]}, Salt: {user[2]}")

    # Authenticate test
    authenticate_user("user1", "password123")
    authenticate_user("user1", "wrongpass")

    conn.close()
