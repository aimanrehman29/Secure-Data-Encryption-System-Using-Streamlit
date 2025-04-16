import streamlit as st
import bcrypt
from cryptography.fernet import Fernet
import hashlib
import base64
import json
import os
from streamlit_option_menu import option_menu
from datetime import datetime, timedelta

# Session state setup
if 'user_credentials' not in st.session_state:
    st.session_state.user_credentials = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None

def hash_passkey(passkey):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(passkey.encode(), salt)

def check_password(stored_hash, passkey):
    return bcrypt.checkpw(passkey.encode(), stored_hash)

data_storage = {}
data_file = "encrypted_data.json"

if os.path.exists(data_file):
    with open(data_file, 'r') as file:
        data_storage = json.load(file)

# Sidebar menu
with st.sidebar:
    selected = option_menu("Secure Vault", ["Home", "Login", "Sign Up", "Encrypt", "Retrieve"],
                           icons=['house', 'box-arrow-in-right', 'person-plus', 'lock', 'unlock'],
                           menu_icon="shield-lock", default_index=0)

st.title("🔐 Secure Data Vault")

# Home Page
if selected == "Home":
    st.markdown("""
    ## Welcome to the Secure Data Vault
    - Secure message storage
    - Simple login and retrieval
    - Powered by Aiman Rehman
    """)

# Sign Up Page
elif selected == "Sign Up":
    st.header("Create a New Account")
    username = st.text_input("Enter a username:")
    password = st.text_input("Create a password:", type="password")
    confirm_password = st.text_input("Confirm your password:", type="password")

    if st.button("Sign Up"):
        if username and password and confirm_password:
            if password == confirm_password:
                hashed_password = hash_passkey(password)
                if username not in st.session_state.user_credentials:
                    st.session_state.user_credentials[username] = hashed_password
                    st.success("Account created successfully! You can now log in.")
                else:
                    st.error("Username already taken. Please choose a different one.")
            else:
                st.error("Passwords do not match.")
        else:
            st.warning("All fields are required!")

# Login Page
elif selected == "Login":
    st.header("Log In")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if st.session_state.lockout_time and datetime.now() < st.session_state.lockout_time:
            remaining_time = st.session_state.lockout_time - datetime.now()
            st.warning(f"Too many failed attempts. Please try again after {remaining_time}.")
        else:
            if username in st.session_state.user_credentials:
                stored_hash = st.session_state.user_credentials[username]
                if check_password(stored_hash, password):
                    st.session_state.failed_attempts = 0
                    st.session_state.authorized = True
                    st.session_state.current_user = username
                    st.session_state.lockout_time = None  # reset lockout time
                    st.success(f"Welcome, {username}!")
                else:
                    st.error("Incorrect password.")
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = datetime.now() + timedelta(minutes=1)
                        st.warning("Too many failed attempts. Please try again later.")
            else:
                st.error("Username not found.")

# Encrypt Page
elif selected == "Encrypt":
    if not st.session_state.authorized or not st.session_state.current_user:
        st.warning("Please log in first.")
    else:
        st.subheader("Encrypt Your Secret Message")
        message = st.text_area("Enter your message")
        pass_input = st.text_input("Re-enter your password to confirm", type="password")
        if st.button("Encrypt & Save"):
            if check_password(st.session_state.user_credentials[st.session_state.current_user], pass_input):
                key = base64.urlsafe_b64encode(hashlib.sha256(pass_input.encode()).digest())
                fernet = Fernet(key)
                encrypted = fernet.encrypt(message.encode()).decode()

                if st.session_state.current_user not in data_storage:
                    data_storage[st.session_state.current_user] = {}

                data_storage[st.session_state.current_user]["message"] = encrypted

                with open(data_file, 'w') as file:
                    json.dump(data_storage, file)

                st.success("Message encrypted and saved!")
                st.code(encrypted)

                st.write("Encrypted message for user:", st.session_state.current_user)
                st.write("Encrypted message:", encrypted)

                st.write("Data Storage (current user):", data_storage.get(st.session_state.current_user))

            else:
                st.error("Password confirmation failed.")

# Retrieve Page
elif selected == "Retrieve":
    if not st.session_state.authorized or not st.session_state.current_user:
        st.warning("Please log in first.")
    else:
        st.subheader("Retrieve Your Secret")
        pass_input = st.text_input("Re-enter your password to decrypt", type="password")
        if st.button("Decrypt Message"):
            if check_password(st.session_state.user_credentials[st.session_state.current_user], pass_input):
                encrypted = data_storage.get(st.session_state.current_user, {}).get("message")

                if encrypted:
                    key = base64.urlsafe_b64encode(hashlib.sha256(pass_input.encode()).digest())
                    fernet = Fernet(key)
                    try:
                        decrypted = fernet.decrypt(encrypted.encode()).decode()
                        st.text_area("Your decrypted message", decrypted, height=150)
                    except Exception as e:
                        st.error("Decryption failed. Possibly wrong password or corrupted data.")
                        st.exception(e)
                else:
                    st.info("No message found.")
            else:
                st.error("Password confirmation failed.")
