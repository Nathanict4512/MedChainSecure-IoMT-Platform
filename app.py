import streamlit as st
import streamlit.components.v1 as components
import sqlite3
import hashlib
import json
import secrets
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import bcrypt
from pathlib import Path

st.set_page_config(page_title="MedChainSecure", page_icon="❤️", layout="wide")

# ====================== DATABASE ======================
DB_PATH = Path("/tmp/heart_monitor.db").resolve()

def get_db_connection():
    return sqlite3.connect(str(DB_PATH))

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, 
        full_name TEXT, age INTEGER, gender TEXT, is_admin BOOLEAN DEFAULT 0)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS test_results(
        id INTEGER PRIMARY KEY, user_id INTEGER, bpm INTEGER, quality REAL,
        encrypted_hex TEXT, key_hex TEXT, ecc_public_key TEXT, 
        blockchain_hash TEXT, test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Default admin
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        pw_hash = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
        c.execute("INSERT INTO users(username,password_hash,full_name,age,gender,is_admin) VALUES(?,?,?,?,?,1)",
                  ('admin', pw_hash, 'System Administrator', 30, 'Male'))
    conn.commit()
    conn.close()

init_db()

# ====================== SESSION ======================
for key in ['authenticated', 'user_id', 'username', 'is_admin', 'saved_bpm', 'last_enc']:
    if key not in st.session_state:
        st.session_state[key] = False if key == 'authenticated' else None

# ====================== RPPG HTML ======================
# (Paste your full original RPPG_HTML here - keep it as is)
RPPG_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>/* Your full CSS and HTML from original */</style></head><body>
<!-- Your full body and script from original RPPG_HTML -->
<!-- Make sure the saveBtn.onclick has the postMessage -->
</body></html>"""

RELAY_SCRIPT = """
<script>
window.addEventListener('message', function(e) {
    if (e.data && e.data.type === 'rppg:save') {
        const url = new URL(window.location.href);
        url.searchParams.set('rppg_bpm', e.data.bpm);
        url.searchParams.set('rppg_q', e.data.quality);
        window.location.href = url.toString();
    }
});
</script>
"""

# ====================== CORE FUNCTIONS ======================
def add_audit_log(user_id, action, details):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev = c.fetchone()
    ph = prev[0] if prev else 'GENESIS'
    ts = datetime.now().isoformat()
    ch = hashlib.sha256(f"{ph}{user_id}{action}{ts}{details}".encode()).hexdigest()
    c.execute('INSERT INTO audit_log(user_id,action,timestamp,details,previous_hash,current_hash) VALUES(?,?,?,?,?,?)',
              (user_id, action, ts, details, ph, ch))
    conn.commit()
    conn.close()

def do_encrypt_and_save(bpm, quality):
    ts = datetime.now().isoformat()
    health_data = {
        "patient_id": f"PT-{st.session_state.user_id:04d}",
        "heart_rate": bpm,
        "signal_quality": round(quality, 2),
        "timestamp": ts,
        "user": st.session_state.username
    }
    plaintext = json.dumps(health_data, indent=2)

    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), None)
    payload = (nonce + ciphertext).hex()
    key_hex = aes_key.hex()

    # ECC
    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_key = priv_key.public_key()
    pub_pem = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    hmac_sig = hashlib.sha256(f"{payload}{key_hex}".encode()).hexdigest()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT blockchain_hash FROM test_results ORDER BY id DESC LIMIT 1")
    prev = c.fetchone()
    prev_hash = prev[0] if prev else 'GENESIS_BLOCK'
    block_hash = hashlib.sha256(f"{prev_hash}{st.session_state.user_id}{bpm}{quality}{ts}".encode()).hexdigest()

    c.execute('''INSERT INTO test_results 
        (user_id, bpm, quality, encrypted_hex, key_hex, ecc_public_key, blockchain_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (st.session_state.user_id, bpm, quality, payload, key_hex, pub_pem[:120], block_hash))
    conn.commit()
    record_id = c.lastrowid
    conn.close()

    add_audit_log(st.session_state.user_id, "SAVE_RESULT", f"BPM:{bpm}")
    return {"record_id": record_id, "bpm": bpm, "quality": quality, "ts": ts, "block_hash": block_hash}

# ====================== PAGES ======================
def show_login():
    st.title("❤️ MedChainSecure")
    tab1, tab2 = st.tabs(["Login", "Register"])
    with tab1:
        with st.form("login"):
            u = st.text_input("Username", "admin")
            p = st.text_input("Password", "Admin@123", type="password")
            if st.form_submit_button("Login"):
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("SELECT id,username,password_hash,is_admin FROM users WHERE username=?", (u,))
                user = c.fetchone()
                conn.close()
                if user and bcrypt.checkpw(p.encode(), user[2]):
                    st.session_state.authenticated = True
                    st.session_state.user_id = user[0]
                    st.session_state.username = user[1]
                    st.session_state.is_admin = bool(user[3])
                    st.rerun()
                else:
                    st.error("Invalid credentials")

def show_dashboard():
    with st.sidebar:
        st.title("MedChainSecure")
        page = st.radio("Menu", ["Dashboard", "rPPG Monitor", "Health History"])
        if st.button("Logout"):
            for k in st.session_state.keys():
                st.session_state[k] = None
            st.rerun()

    if page == "Dashboard":
        st.header(f"Welcome, {st.session_state.username}")
        st.success("System Ready")

    elif page == "rPPG Monitor":
        st.header("📹 rPPG Heart Rate Monitor")
        with st.expander("Tips"):
            st.write("Stay still, good lighting, face centered.")

        _, col, _ = st.columns([1,3,1])
        with col:
            components.html(RPPG_HTML, height=520)
            components.html(RELAY_SCRIPT, height=0)

        # Process saved reading
        params = st.query_params
        if params.get("rppg_bpm"):
            try:
                bpm = int(params.get("rppg_bpm"))
                q = float(params.get("rppg_q"))
                if st.session_state.saved_bpm != bpm:
                    with st.spinner("🔐 Encrypting and saving..."):
                        enc = do_encrypt_and_save(bpm, q)
                        st.session_state.last_enc = enc
                        st.session_state.saved_bpm = bpm
                    st.success(f"✅ Saved! BPM = {bpm}")
                    st.query_params.clear()
                    st.rerun()
            except:
                st.error("Error saving reading")

        if st.session_state.last_enc:
            st.success(f"Last reading: {st.session_state.last_enc['bpm']} BPM")

    elif page == "Health History":
        st.header("📋 Health History")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, bpm, quality, test_date FROM test_results WHERE user_id=? ORDER BY test_date DESC", 
                  (st.session_state.user_id,))
        rows = c.fetchall()
        conn.close()

        if rows:
            df = pd.DataFrame(rows, columns=['ID', 'BPM', 'Quality', 'Date'])
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No readings yet. Go to **rPPG Monitor** and take a reading.")

def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
