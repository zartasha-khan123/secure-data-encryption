import streamlit as st
from cryptography.fernet import Fernet # type: ignore
import hashlib
import json
import os

# ------------------- Load Fernet Key -------------------
KEY_FILE = "key.key"

if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()

fernet = Fernet(key)

# ------------------- Load Stored Data -------------------
DATA_FILE = "data.json"

if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

failed_attempts = {}

# ------------------- Utility Functions -------------------
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=4)

# ------------------- Pages -------------------
def show_home():
    st.title("🔐 Secure Data Encryption System")
    choice = st.radio("Choose an action:", ["Insert Data", "Retrieve Data"])
    if choice == "Insert Data":
        show_insert()
    else:
        show_retrieve()

def show_insert():
    st.subheader("📝 Insert New Data")
    user_id = st.text_input("Enter a unique User ID")
    text = st.text_area("Enter the text to store securely")
    passkey = st.text_input("Enter a secure passkey", type="password")
    if st.button("Encrypt & Store"):
        if user_id and text and passkey:
            encrypted_text = encrypt_data(text)
            hashed_passkey = hash_passkey(passkey)
            stored_data[user_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data()
            st.success(f"Data for '{user_id}' stored securely!")
        else:
            st.error("All fields are required.")

def show_retrieve():
    st.subheader("🔍 Retrieve Your Data")
    user_id = st.text_input("User ID")
    passkey = st.text_input("Enter your passkey", type="password")

    if user_id not in failed_attempts:
        failed_attempts[user_id] = 0

    if failed_attempts[user_id] >= 3:
        st.warning("Too many failed attempts! Please reauthorize.")
        show_login(user_id)
        return

    if st.button("Decrypt"):
        if user_id not in stored_data:
            st.error("User ID not found.")
        else:
            hashed_input = hash_passkey(passkey)
            correct_hash = stored_data[user_id]["passkey"]
            if hashed_input == correct_hash:
                decrypted = decrypt_data(stored_data[user_id]["encrypted_text"])
                st.success(f"Decrypted Text: {decrypted}")
                failed_attempts[user_id] = 0
            else:
                failed_attempts[user_id] += 1
                st.error(f"Incorrect passkey. Attempt {failed_attempts[user_id]} of 3.")

def show_login(user_id):
    st.subheader("🔐 Reauthorization Required")
    login = st.text_input("Re-enter Admin Code", type="password")
    if st.button("Login"):
        if login == "admin123":
            failed_attempts[user_id] = 0
            st.success("Reauthorization successful. Try again.")
        else:
            st.error("Invalid admin code.")

# ------------------- Run App -------------------
show_home()

