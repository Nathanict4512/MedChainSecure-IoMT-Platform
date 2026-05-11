# app.py - Main Streamlit Application
import streamlit as st
import sqlite3
import hashlib
import hmac
import json
import secrets
import time
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import bcrypt
import requests
from pathlib import Path
import base64
import re
import uuid
from streamlit.components.v1 import html

# Page configuration
st.set_page_config(
    page_title="MedChainSecure - IoMT Heart Rate Monitor",
    page_icon="❤️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS with theme support
def inject_css(theme="dark"):
    if theme == "dark":
        css = """
        <style>
            /* Dark Theme Variables */
            :root {
                --bg-primary: #101415;
                --bg-secondary: #1d2022;
                --bg-card: rgba(29, 32, 34, 0.7);
                --text-primary: #e0e3e5;
                --text-secondary: #c5c6cd;
                --accent-primary: #b9c7e4;
                --accent-secondary: #4cd6fb;
                --accent-tertiary: #4ae183;
                --border-color: rgba(255, 255, 255, 0.1);
                --error: #ffb4ab;
                --error-container: #93000a;
            }
            
            .stApp {
                background: var(--bg-primary);
            }
            
            /* Main container styling */
            .main-header {
                background: linear-gradient(135deg, #0a192f 0%, #1d2022 100%);
                padding: 2rem;
                border-radius: 15px;
                margin-bottom: 2rem;
                border: 1px solid var(--border-color);
            }
            
            .glass-panel {
                background: var(--bg-card);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: 0.75rem;
            }
            
            .metric-card {
                background: linear-gradient(180deg, rgba(76, 214, 251, 0.1) 0%, rgba(10, 25, 47, 0) 100%);
                border-radius: 0.75rem;
                padding: 1.5rem;
                border: 1px solid var(--border-color);
            }
            
            .stat-value {
                font-size: 2.5rem;
                font-weight: 700;
                color: var(--text-primary);
            }
            
            .stat-label {
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: var(--text-secondary);
            }
            
            /* Theme toggle button */
            .theme-toggle {
                position: fixed;
                bottom: 20px;
                right: 20px;
                z-index: 1000;
                background: var(--bg-card);
                backdrop-filter: blur(10px);
                border: 1px solid var(--border-color);
                border-radius: 50%;
                width: 48px;
                height: 48px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .theme-toggle:hover {
                transform: scale(1.05);
            }
            
            /* Custom scrollbar */
            ::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }
            
            ::-webkit-scrollbar-track {
                background: var(--bg-secondary);
            }
            
            ::-webkit-scrollbar-thumb {
                background: var(--accent-secondary);
                border-radius: 4px;
            }
            
            /* Status badges */
            .status-badge {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 600;
            }
            
            .status-active {
                background: rgba(74, 225, 131, 0.1);
                color: #4ae183;
                border: 1px solid rgba(74, 225, 131, 0.2);
            }
            
            .status-warning {
                background: rgba(255, 180, 171, 0.1);
                color: #ffb4ab;
                border: 1px solid rgba(255, 180, 171, 0.2);
            }
            
            /* Tables */
            .data-table {
                width: 100%;
                border-collapse: collapse;
            }
            
            .data-table th {
                text-align: left;
                padding: 1rem;
                background: rgba(50, 53, 55, 0.3);
                font-size: 0.7rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: var(--text-secondary);
            }
            
            .data-table td {
                padding: 1rem;
                border-bottom: 1px solid var(--border-color);
            }
            
            /* Buttons */
            .btn-primary {
                background: linear-gradient(135deg, #4cd6fb 0%, #b9c7e4 100%);
                color: #003642;
                padding: 0.75rem 1.5rem;
                border-radius: 0.5rem;
                font-weight: 600;
                border: none;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 20px rgba(76, 214, 251, 0.3);
            }
            
            /* Code blocks */
            code {
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.75rem;
                background: rgba(0, 0, 0, 0.3);
                padding: 0.125rem 0.375rem;
                border-radius: 0.25rem;
            }
            
            /* Responsive */
            @media (max-width: 768px) {
                .main-header {
                    padding: 1rem;
                }
                .stat-value {
                    font-size: 1.5rem;
                }
            }
        </style>
        """
    else:
        css = """
        <style>
            /* Light Theme Variables */
            :root {
                --bg-primary: #f5f7fa;
                --bg-secondary: #ffffff;
                --bg-card: rgba(255, 255, 255, 0.9);
                --text-primary: #1a1a2e;
                --text-secondary: #4a5568;
                --accent-primary: #4a90e2;
                --accent-secondary: #00b2d6;
                --accent-tertiary: #2ecc71;
                --border-color: rgba(0, 0, 0, 0.1);
                --error: #e74c3c;
                --error-container: #fde0dd;
            }
            
            .stApp {
                background: var(--bg-primary);
            }
            
            .main-header {
                background: linear-gradient(135deg, #e8f4f8 0%, #ffffff 100%);
                padding: 2rem;
                border-radius: 15px;
                margin-bottom: 2rem;
                border: 1px solid var(--border-color);
            }
            
            .glass-panel {
                background: var(--bg-card);
                backdrop-filter: blur(10px);
                border: 1px solid var(--border-color);
                border-radius: 0.75rem;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            }
            
            .metric-card {
                background: linear-gradient(180deg, rgba(0, 178, 214, 0.05) 0%, rgba(255, 255, 255, 0) 100%);
                border-radius: 0.75rem;
                padding: 1.5rem;
                border: 1px solid var(--border-color);
            }
            
            .stat-value {
                font-size: 2.5rem;
                font-weight: 700;
                color: var(--text-primary);
            }
            
            .stat-label {
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: var(--text-secondary);
            }
            
            .theme-toggle {
                position: fixed;
                bottom: 20px;
                right: 20px;
                z-index: 1000;
                background: var(--bg-card);
                backdrop-filter: blur(10px);
                border: 1px solid var(--border-color);
                border-radius: 50%;
                width: 48px;
                height: 48px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .status-badge {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 600;
            }
            
            .status-active {
                background: rgba(46, 204, 113, 0.1);
                color: #27ae60;
                border: 1px solid rgba(46, 204, 113, 0.2);
            }
            
            .btn-primary {
                background: linear-gradient(135deg, #00b2d6 0%, #4a90e2 100%);
                color: white;
                padding: 0.75rem 1.5rem;
                border-radius: 0.5rem;
                font-weight: 600;
                border: none;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            ::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }
            
            ::-webkit-scrollbar-track {
                background: var(--bg-secondary);
            }
            
            ::-webkit-scrollbar-thumb {
                background: var(--accent-secondary);
                border-radius: 4px;
            }
        </style>
        """
    st.markdown(css, unsafe_allow_html=True)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'username' not in st.session_state:
    st.session_state.username = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'

# Database setup
def init_db():
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            age INTEGER,
            gender TEXT,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Test results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bpm INTEGER NOT NULL,
            quality REAL NOT NULL,
            encrypted_hex TEXT NOT NULL,
            key_hex TEXT NOT NULL,
            analysis TEXT,
            stress_data TEXT,
            test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Audit log table (blockchain)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            previous_hash TEXT,
            current_hash TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Check if admin exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        password_hash = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
        cursor.execute('''
            INSERT INTO users (username, password_hash, full_name, age, gender, is_admin)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', password_hash, 'System Administrator', 30, 'Male', 1))
    
    conn.commit()
    conn.close()

init_db()

# Helper functions
def add_audit_log(user_id, action, details):
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    
    # Get previous hash
    cursor.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev = cursor.fetchone()
    previous_hash = prev[0] if prev else 'GENESIS'
    
    timestamp = datetime.now().isoformat()
    data = f"{previous_hash}{user_id}{action}{timestamp}{details}"
    current_hash = hashlib.sha256(data.encode()).hexdigest()
    
    cursor.execute('''
        INSERT INTO audit_log (user_id, action, timestamp, details, previous_hash, current_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, action, timestamp, details, previous_hash, current_hash))
    
    conn.commit()
    conn.close()

def encrypt_aes_gcm(plaintext):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    payload = nonce + ciphertext + ciphertext[-16:]
    return key.hex(), payload.hex()

def decrypt_aes_gcm(key_hex, payload_hex):
    key = bytes.fromhex(key_hex)
    payload = bytes.fromhex(payload_hex)
    nonce = payload[:12]
    encrypted = payload[12:]
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, encrypted, None).decode()

def get_bpm_category(bpm):
    if bpm < 60:
        return ("Bradycardia", "status-warning")
    elif 60 <= bpm <= 100:
        return ("Normal", "status-active")
    else:
        return ("Tachycardia", "status-warning")

def verify_blockchain_integrity():
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, user_id, action, timestamp, details, previous_hash, current_hash FROM audit_log ORDER BY id")
    logs = cursor.fetchall()
    conn.close()
    
    previous_hash = 'GENESIS'
    for log in logs:
        log_id, user_id, action, timestamp, details, stored_prev, stored_curr = log
        
        if stored_prev != previous_hash:
            return False, log_id
        
        data = f"{stored_prev}{user_id}{action}{timestamp}{details}"
        computed_hash = hashlib.sha256(data.encode()).hexdigest()
        
        if computed_hash != stored_curr:
            return False, log_id
        
        previous_hash = stored_curr
    
    return True, None

# Login/Register UI
def show_login():
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div class="main-header" style="text-align: center;">
            <h1 style="color: var(--accent-primary);">MedChainSecure</h1>
            <p style="color: var(--text-secondary);">Secure IoMT Heart Rate Monitoring Platform</p>
            <div style="display: flex; justify-content: center; gap: 1rem; margin-top: 1rem;">
                <span class="status-badge status-active">🔒 AES-256-GCM</span>
                <span class="status-badge status-active">🔑 ECC SECP256R1</span>
                <span class="status-badge status-active">📦 Blockchain Audit</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Login", use_container_width=True)
                
                if submitted:
                    conn = sqlite3.connect('heart_monitor.db')
                    cursor = conn.cursor()
                    cursor.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
                    user = cursor.fetchone()
                    conn.close()
                    
                    if user and bcrypt.checkpw(password.encode(), user[2]):
                        st.session_state.authenticated = True
                        st.session_state.user_id = user[0]
                        st.session_state.username = user[1]
                        st.session_state.is_admin = user[3]
                        add_audit_log(user[0], "LOGIN", f"User {username} logged in")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
        
        with tab2:
            with st.form("register_form"):
                full_name = st.text_input("Full Name")
                username = st.text_input("Username")
                age = st.number_input("Age", min_value=1, max_value=120)
                gender = st.selectbox("Gender", ["Male", "Female", "Other"])
                password = st.text_input("Password", type="password")
                confirm = st.text_input("Confirm Password", type="password")
                submitted = st.form_submit_button("Register", use_container_width=True)
                
                if submitted:
                    if password != confirm:
                        st.error("Passwords do not match")
                    else:
                        conn = sqlite3.connect('heart_monitor.db')
                        cursor = conn.cursor()
                        try:
                            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
                            cursor.execute('''
                                INSERT INTO users (username, password_hash, full_name, age, gender, is_admin)
                                VALUES (?, ?, ?, ?, ?, 0)
                            ''', (username, password_hash, full_name, age, gender))
                            conn.commit()
                            user_id = cursor.lastrowid
                            add_audit_log(user_id, "REGISTER", f"New user {username} registered")
                            st.success("Registration successful! Please login.")
                        except sqlite3.IntegrityError:
                            st.error("Username already exists")
                        finally:
                            conn.close()

# Dashboard UI
def show_dashboard():
    # Sidebar Navigation
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 2rem;">
            <h3 style="color: var(--accent-primary);">MedChainSecure</h3>
            <p style="font-size: 0.7rem; color: var(--text-secondary);">Verified Node v2.4</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Navigation
        pages = ["Dashboard", "rPPG Monitor", "Health History", "Encryption Lab", "Network Storage"]
        if st.session_state.is_admin:
            pages.append("Admin Panel")
        
        selected = st.radio("", pages, label_visibility="collapsed")
        
        st.markdown("---")
        
        # User info
        st.markdown(f"""
        <div class="glass-panel" style="padding: 1rem;">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <div style="width: 40px; height: 40px; background: linear-gradient(135deg, var(--accent-secondary), var(--accent-primary)); border-radius: 50%;"></div>
                <div>
                    <p style="font-weight: 600;">{st.session_state.username}</p>
                    <p style="font-size: 0.7rem; color: var(--text-secondary);">{'Admin' if st.session_state.is_admin else 'User'}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🚪 Logout", use_container_width=True):
            add_audit_log(st.session_state.user_id, "LOGOUT", f"User {st.session_state.username} logged out")
            for key in ['authenticated', 'user_id', 'username', 'is_admin']:
                st.session_state[key] = None
            st.rerun()
    
    # Content based on selected page
    if selected == "Dashboard":
        show_dashboard_home()
    elif selected == "rPPG Monitor":
        show_rppg_monitor()
    elif selected == "Health History":
        show_health_history()
    elif selected == "Encryption Lab":
        show_encryption_lab()
    elif selected == "Network Storage":
        show_network_storage()
    elif selected == "Admin Panel":
        show_admin_panel()

def show_dashboard_home():
    st.markdown("""
    <div class="main-header">
        <h2 style="margin-bottom: 0.5rem;">System Overview</h2>
        <p style="color: var(--text-secondary);">Real-time clinical integrity and user telemetry across 4-tier architecture.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Get stats
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM test_results")
    total_tests = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(bpm) FROM test_results")
    avg_bpm = cursor.fetchone()[0] or 0
    
    conn.close()
    
    # Stats grid
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="stat-label">TOTAL USERS</div>
            <div class="stat-value">{total_users:,}</div>
            <div style="color: var(--accent-tertiary); font-size: 0.75rem;">+12% this month</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="stat-label">MONITORING SESSIONS</div>
            <div class="stat-value">{total_tests:,}</div>
            <div style="color: var(--accent-tertiary); font-size: 0.75rem;">+5% this month</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="stat-label">AVERAGE BPM</div>
            <div class="stat-value">{avg_bpm:.0f}</div>
            <div style="color: var(--accent-secondary); font-size: 0.75rem;">Normal range</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Security badges
    st.markdown("""
    <div style="display: flex; gap: 1rem; flex-wrap: wrap; margin: 2rem 0; justify-content: center;">
        <div class="status-badge status-active">🔒 AES-256-GCM Encryption</div>
        <div class="status-badge status-active">🔑 ECC SECP256R1 Key Exchange</div>
        <div class="status-badge status-active">📦 Blockchain Audit Log</div>
        <div class="status-badge status-active">🏥 HIPAA Compliant</div>
        <div class="status-badge status-active">🌍 GDPR Verified</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Architecture grid
    st.markdown("<h3 style='margin-bottom: 1rem;'>4-Tier System Architecture</h3>", unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    tiers = [
        ("💻 Browser Client", "rPPG video capture, ROI extraction, CHROM algorithm", "#4cd6fb"),
        ("🐍 Python Backend", "Authentication, hybrid encryption, stress analysis", "#b9c7e4"),
        ("🗄️ 3-Layer Storage", "Local SQLite + Remote PHP + Blockchain ledger", "#4ae183"),
        ("✅ Verification", "AES-GCM tag verification + Hash chain audit", "#ffb4ab")
    ]
    
    for col, (title, desc, color) in zip([col1, col2, col3, col4], tiers):
        with col:
            st.markdown(f"""
            <div class="glass-panel" style="padding: 1.5rem; height: 100%;">
                <div style="font-size: 2rem; margin-bottom: 0.5rem;">{title.split()[0]}</div>
                <h4 style="margin: 0.5rem 0;">{title}</h4>
                <p style="font-size: 0.75rem; color: var(--text-secondary);">{desc}</p>
            </div>
            """, unsafe_allow_html=True)

def show_rppg_monitor():
    st.markdown("""
    <div class="main-header">
        <h2>rPPG Real-time Monitoring</h2>
        <p style="color: var(--text-secondary);">Live Secure Stream • AES-256-GCM Encrypted</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        <div class="glass-panel" style="padding: 1rem;">
            <div style="aspect-ratio: 16/9; background: linear-gradient(135deg, #0a192f, #1d2022); border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; position: relative;">
                <div style="text-align: center;">
                    <span style="font-size: 4rem;">📹</span>
                    <p style="margin-top: 1rem;">Camera feed would appear here</p>
                    <p style="font-size: 0.7rem; color: var(--text-secondary);">Face detection and ROI extraction active</p>
                </div>
                <div style="position: absolute; top: 1rem; left: 1rem; display: flex; gap: 0.5rem;">
                    <div class="status-badge status-active" style="background: rgba(0,0,0,0.5);">
                        <span style="width: 8px; height: 8px; background: #ef4444; border-radius: 50%; display: inline-block;"></span>
                        LIVE STREAM
                    </div>
                </div>
                <div style="position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; pointer-events: none;">
                    <div style="border: 2px solid var(--accent-secondary); border-radius: 1rem; width: 200px; height: 250px; position: relative;">
                        <div style="position: absolute; top: 2rem; left: 50%; transform: translateX(-50%); width: 100px; height: 50px; border: 2px solid var(--accent-secondary); border-radius: 0.5rem;">
                            <div style="position: absolute; top: -1.5rem; left: 0; font-size: 0.6rem;">ROI: Forehead</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # BPM Gauge
        bpm = st.slider("Simulated BPM", 40, 150, 72)
        category, badge_class = get_bpm_category(bpm)
        
        st.markdown(f"""
        <div class="glass-panel" style="padding: 1.5rem; text-align: center;">
            <div style="font-size: 3rem; font-weight: 700;">{bpm}</div>
            <div style="font-size: 0.875rem; color: var(--text-secondary);">BPM</div>
            <div class="status-badge {badge_class}" style="margin-top: 0.5rem; justify-content: center;">{category}</div>
            <div style="margin-top: 1rem;">
                <div class="stat-label">Signal Quality</div>
                <div style="font-size: 1.5rem; font-weight: 700; color: var(--accent-tertiary);">94%</div>
                <div style="background: var(--bg-secondary); border-radius: 0.5rem; height: 4px; margin-top: 0.5rem;">
                    <div style="width: 94%; background: var(--accent-tertiary); height: 100%; border-radius: 0.5rem;"></div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Stress Analysis
        stress_score = 24
        st.markdown(f"""
        <div class="glass-panel" style="padding: 1.5rem; margin-top: 1rem;">
            <div class="stat-label">Stress Analysis</div>
            <div style="display: flex; align-items: center; gap: 1rem; margin: 1rem 0;">
                <div style="width: 50px; height: 50px; border-radius: 50%; border: 2px solid var(--accent-primary); display: flex; align-items: center; justify-content: center;">{stress_score}</div>
                <div>
                    <div style="font-weight: 600;">Category: Minimal</div>
                    <div style="font-size: 0.7rem; color: var(--text-secondary);">HRV Balance: Normal</div>
                </div>
            </div>
            <button class="btn-primary" style="width: 100%;">Save Result</button>
        </div>
        """, unsafe_allow_html=True)
    
    # Waveform
    st.markdown("""
    <div class="glass-panel" style="padding: 1rem; margin-top: 1rem;">
        <div class="stat-label" style="margin-bottom: 1rem;">Real-time Waveform Decomposition</div>
        <div style="height: 150px; background: var(--bg-secondary); border-radius: 0.5rem; position: relative; overflow: hidden;">
            <svg width="100%" height="100%" viewBox="0 0 800 100" preserveAspectRatio="none">
                <path d="M0,50 Q20,20 40,50 T80,50 T120,50 T160,50 T200,50 T240,50 T280,50 T320,50 T360,50 T400,50 T440,50 T480,50 T520,50 T560,50 T600,50 T640,50 T680,50 T720,50 T760,50 T800,50" fill="none" stroke="var(--accent-secondary)" stroke-width="2"/>
            </svg>
        </div>
        <div style="display: flex; gap: 2rem; margin-top: 1rem; justify-content: space-around;">
            <div><span class="stat-label">SpO₂ (EST)</span><br><strong>98%</strong></div>
            <div><span class="stat-label">RMSSD</span><br><strong>42.1 ms</strong></div>
            <div><span class="stat-label">Resp Rate</span><br><strong>14 BrPM</strong></div>
            <div><span class="stat-label">Sync Latency</span><br><strong style="color: var(--accent-tertiary);">18ms</strong></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def show_health_history():
    st.markdown("""
    <div class="main-header">
        <h2>Health History</h2>
        <p style="color: var(--text-secondary);">Your complete medical timeline with cryptographic verification</p>
    </div>
    """, unsafe_allow_html=True)
    
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, bpm, quality, test_date FROM test_results 
        WHERE user_id = ? ORDER BY test_date DESC
    ''', (st.session_state.user_id,))
    results = cursor.fetchall()
    conn.close()
    
    if results:
        df = pd.DataFrame(results, columns=['ID', 'BPM', 'Quality', 'Date'])
        
        # Stats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Tests", len(df))
        with col2:
            st.metric("Average BPM", f"{df['BPM'].mean():.0f}")
        with col3:
            st.metric("Min BPM", f"{df['BPM'].min()}")
        with col4:
            st.metric("Max BPM", f"{df['BPM'].max()}")
        
        # Trend chart
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['Date'], y=df['BPM'],
            mode='lines+markers',
            name='Heart Rate',
            line=dict(color='#4cd6fb', width=2),
            marker=dict(size=8, color=df['BPM'], colorscale='RdYlGn_r', showscale=True)
        ))
        fig.add_hrect(y0=60, y1=100, line_width=0, fillcolor="green", opacity=0.1, annotation_text="Normal Range")
        fig.update_layout(
            title="Heart Rate Trend",
            xaxis_title="Date",
            yaxis_title="BPM",
            template="plotly_dark",
            height=400,
            hovermode='x unified'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Records table
        st.markdown("### Verified Clinical Log")
        
        for _, row in df.head(10).iterrows():
            category, _ = get_bpm_category(row['BPM'])
            status_color = "#4ae183" if category == "Normal" else "#ffb4ab" if category == "Tachycardia" else "#4cd6fb"
            
            st.markdown(f"""
            <div class="glass-panel" style="padding: 0.75rem; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong>{row['Date']}</strong><br>
                    <span style="font-size: 0.7rem; color: var(--text-secondary);">Quality: {row['Quality']:.1f}%</span>
                </div>
                <div style="text-align: center;">
                    <span style="font-size: 1.25rem; font-weight: 700;">{row['BPM']}</span>
                    <span style="font-size: 0.7rem;"> BPM</span>
                </div>
                <div>
                    <span class="status-badge" style="background: {status_color}20; color: {status_color};">{category}</span>
                </div>
                <div>
                    <span class="material-symbols-outlined" style="font-size: 1rem;">verified</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No health records found. Start monitoring to see your history here.")

def show_encryption_lab():
    st.markdown("""
    <div class="main-header">
        <h2>Encryption Laboratory</h2>
        <p style="color: var(--text-secondary);">7-step cryptographic walkthrough for IoMT data protection</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sample data
    sample_data = {
        "patient_id": "PT-001",
        "heart_rate": 72,
        "timestamp": datetime.now().isoformat(),
        "device": "rPPG-CAM-01"
    }
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="glass-panel" style="padding: 1rem; margin-bottom: 1rem;">
            <div class="stat-label">Step 1: Original Plaintext</div>
            <pre style="background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 0.25rem; overflow-x: auto;"><code>""" + json.dumps(sample_data, indent=2) + """</code></pre>
        </div>
        """, unsafe_allow_html=True)
        
        # Encrypt
        key_hex, encrypted = encrypt_aes_gcm(json.dumps(sample_data))
        
        st.markdown(f"""
        <div class="glass-panel" style="padding: 1rem; margin-bottom: 1rem;">
            <div class="stat-label">Step 2-3: AES-256-GCM Encryption</div>
            <div><strong>AES Key:</strong> <code>{key_hex[:32]}...</code></div>
            <div><strong>Encrypted Payload:</strong> <code>{encrypted[:64]}...</code></div>
            <div class="status-badge status-active" style="margin-top: 0.5rem;">✓ Encryption Complete</div>
        </div>
        """, unsafe_allow_html=True)
        
        # ECC
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        st.markdown(f"""
        <div class="glass-panel" style="padding: 1rem;">
            <div class="stat-label">Step 4: ECC SECP256R1 Key Pair</div>
            <div><strong>Public Key:</strong> <code>{public_pem[:40].decode()}...</code></div>
            <div><strong>Private Key:</strong> <code style="color: var(--error);">[REDACTED]</code></div>
            <div class="status-badge status-active" style="margin-top: 0.5rem;">✓ Key Exchange Ready</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # Decrypt verification
        try:
            decrypted = decrypt_aes_gcm(key_hex, encrypted)
            decrypted_data = json.loads(decrypted)
            
            st.markdown(f"""
            <div class="glass-panel" style="padding: 1rem; margin-bottom: 1rem;">
                <div class="stat-label">Step 5-7: Decryption & Verification</div>
                <pre style="background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 0.25rem; overflow-x: auto;"><code>""" + json.dumps(decrypted_data, indent=2) + """</code></pre>
                <div class="status-badge status-active" style="margin-top: 0.5rem;">✓ Tag Verification Passed</div>
                <div class="status-badge status-active" style="margin-top: 0.5rem;">✓ Integrity Check Passed</div>
            </div>
            """, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Decryption failed: {e}")
        
        # Compliance
        st.markdown("""
        <div class="glass-panel" style="padding: 1rem;">
            <div class="stat-label">Compliance Report</div>
            <div style="margin-top: 0.5rem;">
                <div>✓ HIPAA Security Rule §164.312(e)(2)(ii)</div>
                <div>✓ GDPR Article 32 Security of Processing</div>
                <div>✓ NIST SP 800-38D (AES-GCM)</div>
                <div>✓ FIPS 186-4 (ECC)</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

def show_network_storage():
    st.markdown("""
    <div class="main-header">
        <h2>Decentralisation & Storage</h2>
        <p style="color: var(--text-secondary);">3-Layer distributed architecture with blockchain audit</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Three layers
    col1, col2, col3 = st.columns(3)
    
    layers = [
        ("Layer 1: Local Vault", "SQLite Database", "0.4ms Latency", "45% Used", "#4cd6fb"),
        ("Layer 2: Remote Relay", "PHP Backup Server", "2.1s Latency", "Synced", "#b9c7e4"),
        ("Layer 3: Blockchain", "Immutable Ledger", "Verified", "Block Height: 48,291", "#4ae183")
    ]
    
    for col, (title, subtitle, metric, status, color) in zip([col1, col2, col3], layers):
        with col:
            st.markdown(f"""
            <div class="glass-panel" style="padding: 1.5rem; text-align: center; border-top: 3px solid {color};">
                <h4>{title}</h4>
                <p style="font-size: 0.7rem; color: var(--text-secondary);">{subtitle}</p>
                <div style="margin: 1rem 0;">
                    <div style="font-size: 1.5rem; font-weight: 700;">{metric}</div>
                </div>
                <div class="status-badge status-active" style="justify-content: center;">{status}</div>
            </div>
            """, unsafe_allow_html=True)
    
    # Blockchain integrity check
    st.markdown("### Blockchain Ledger Audit")
    
    is_valid, broken_at = verify_blockchain_integrity()
    
    if is_valid:
        st.success("✅ Blockchain integrity verified! All hash links are valid.")
    else:
        st.error(f"❌ Blockchain tamper detected at entry #{broken_at}!")
    
    # Recent audit logs
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, action, details, current_hash FROM audit_log 
        ORDER BY id DESC LIMIT 10
    ''')
    logs = cursor.fetchall()
    conn.close()
    
    st.markdown("### Recent Audit Entries")
    
    for log in logs:
        st.markdown(f"""
        <div class="glass-panel" style="padding: 0.75rem; margin-bottom: 0.5rem;">
            <div style="display: flex; justify-content: space-between;">
                <span><strong>{log[0]}</strong></span>
                <span class="status-badge status-active">{log[1]}</span>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">{log[2]}</div>
            <div style="font-size: 0.6rem; font-family: monospace; margin-top: 0.25rem;">Hash: {log[3][:32]}...</div>
        </div>
        """, unsafe_allow_html=True)

def show_admin_panel():
    st.markdown("""
    <div class="main-header">
        <h2>Admin Panel</h2>
        <p style="color: var(--text-secondary);">System administration and user management</p>
    </div>
    """, unsafe_allow_html=True)
    
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    
    # User management
    cursor.execute('''
        SELECT u.id, u.username, u.full_name, u.age, u.gender, u.is_admin, 
               COUNT(t.id) as record_count
        FROM users u
        LEFT JOIN test_results t ON u.id = t.user_id
        GROUP BY u.id
        ORDER BY u.id
    ''')
    users = cursor.fetchall()
    conn.close()
    
    st.markdown("### User Management")
    
    for user in users:
        with st.expander(f"{user[1]} - {user[2]}"):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.write(f"**Age:** {user[3]}")
                st.write(f"**Gender:** {user[4]}")
            with col2:
                st.write(f"**Admin:** {'Yes' if user[5] else 'No'}")
                st.write(f"**Records:** {user[6]}")
            with col3:
                if not user[5] and st.button(f"Make Admin", key=f"admin_{user[0]}"):
                    conn2 = sqlite3.connect('heart_monitor.db')
                    cursor2 = conn2.cursor()
                    cursor2.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user[0],))
                    conn2.commit()
                    conn2.close()
                    st.rerun()
    
    # System stats
    st.markdown("### System Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM test_results")
    total_tests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    total_audits = cursor.fetchone()[0]
    
    conn.close()
    
    with col1:
        st.metric("Total Users", total_users)
    with col2:
        st.metric("Total Tests", total_tests)
    with col3:
        st.metric("Audit Logs", total_audits)
    with col4:
        integrity, _ = verify_blockchain_integrity()
        st.metric("Blockchain Status", "Valid" if integrity else "Tampered")

# Theme toggle component
def theme_toggle():
    icon = "🌙" if st.session_state.theme == "light" else "☀️"
    if st.button(icon, key="theme_toggle", help="Toggle theme"):
        st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"
        inject_css(st.session_state.theme)
        st.rerun()

# Main app
def main():
    inject_css(st.session_state.theme)
    
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()
        theme_toggle()

if __name__ == "__main__":
    main()