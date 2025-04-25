import streamlit as st
import hashlib
import json
import os
import time
import base64
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# Constants
DATA_FILE = "data_store.json"
SESSION_TIMEOUT = 60  # seconds
MAX_ATTEMPTS = 3

# Session State Initialization
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = None
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False

# Load or initialize data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Save data function
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# Key generation using PBKDF2
def derive_key(passkey, salt):
    kdf = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.urlsafe_b64encode(kdf)

# Hash passkey with salt for storage
def hash_passkey(passkey, salt):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000).hex()

# Encrypt text
def encrypt_data(text, passkey):
    salt = secrets.token_bytes(16)
    key = derive_key(passkey, salt)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode()).decode()
    return encrypted_text, salt.hex()

# Decrypt text with validation
def decrypt_data(entry_id, passkey):
    if entry_id not in stored_data:
        return None, "Data ID not found."

    entry = stored_data[entry_id]
    salt = bytes.fromhex(entry['salt'])
    hashed_input_pass = hash_passkey(passkey, salt)

    if hashed_input_pass != entry['hashed_passkey']:
        st.session_state.failed_attempts += 1
        return None, "Incorrect passkey."

    key = derive_key(passkey, salt)
    cipher = Fernet(key)
    try:
        decrypted = cipher.decrypt(entry['encrypted_text'].encode()).decode()
        st.session_state.failed_attempts = 0
        return decrypted, None
    except Exception as e:
        st.session_state.failed_attempts += 1
        return None, "Decryption failed."

# Time lock check
def is_locked_out():
    if st.session_state.locked_until:
        if datetime.now() < st.session_state.locked_until:
            return True
        else:
            st.session_state.locked_until = None
            st.session_state.failed_attempts = 0
    return False

# Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.header("🏠 Welcome")
    st.write("Store and retrieve sensitive data with encryption and authentication.")

elif choice == "Store Data":
    st.header("📦 Store Data")
    entry_id = st.text_input("Enter Unique ID for Your Data")
    user_data = st.text_area("Enter Text to Encrypt")
    passkey = st.text_input("Enter a Passkey", type="password")

    if st.button("Encrypt & Store"):
        if entry_id in stored_data:
            st.error("ID already exists. Choose a different ID.")
        elif entry_id and user_data and passkey:
            encrypted_text, salt_hex = encrypt_data(user_data, passkey)
            hashed_pass = hash_passkey(passkey, bytes.fromhex(salt_hex))

            stored_data[entry_id] = {
                "encrypted_text": encrypted_text,
                "salt": salt_hex,
                "hashed_passkey": hashed_pass
            }
            save_data()
            st.success("✅ Data encrypted and saved!")
        else:
            st.warning("Please fill in all fields.")

elif choice == "Retrieve Data":
    st.header("🔎 Retrieve Data")

    if is_locked_out():
        st.error(f"🔒 Too many failed attempts. Try again later.")
    else:
        entry_id = st.text_input("Enter Your Data ID")
        passkey = st.text_input("Enter Your Passkey", type="password")

        if st.button("Decrypt"):
            if entry_id and passkey:
                result, error = decrypt_data(entry_id, passkey)
                if result:
                    st.success(f"🔓 Decrypted Data: {result}")
                else:
                    st.error(f"❌ {error}")
                    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                        st.session_state.locked_until = datetime.now() + timedelta(seconds=SESSION_TIMEOUT)
                        st.warning("🔒 Too many failed attempts. Temporarily locked.")
                        st.experimental_rerun()
            else:
                st.warning("Please provide both Data ID and Passkey.")

elif choice == "Login":
    st.header("🔐 Admin Login")
    master = st.text_input("Enter Master Password", type="password")

    if st.button("Login"):
        if master == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = None
            st.success("✅ Logged in. Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
