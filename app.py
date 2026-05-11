# app.py - MedChainSecure Complete Application
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

st.set_page_config(
    page_title="MedChainSecure - rPPG Heart Monitor",
    page_icon="❤️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
:root{--bg:#f8fafc;--card:#fff;--txt:#1e293b;--muted:#64748b;--border:#e2e8f0}
.stApp{background:var(--bg)}
.main-header{
  background:linear-gradient(135deg,#fff,#f1f5f9);
  padding:2rem;border-radius:1rem;margin-bottom:2rem;
  border:1px solid var(--border);text-align:center;
}
.main-header h1,.main-header h2{
  font-size:2rem;margin-bottom:.5rem;
  background:linear-gradient(135deg,#3b82f6,#06b6d4);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}
.main-header p{color:var(--muted);font-size:1rem}
.glass-panel{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1rem;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.metric-card{background:var(--card);border-radius:.75rem;padding:1.25rem;border:1px solid var(--border);text-align:center;transition:all .3s}
.metric-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.05)}
.stat-value{font-size:2rem;font-weight:700;color:var(--txt)}
.stat-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
.status-badge{display:inline-flex;align-items:center;gap:.5rem;padding:.35rem .85rem;border-radius:9999px;font-size:.75rem;font-weight:600}
.status-good{background:#d1fae5;color:#065f46}
.enc-preview{font-family:'Courier New',monospace;font-size:.7rem;background:#1e293b;color:#a5f3fc;padding:.75rem;border-radius:.5rem;overflow-x:auto;line-height:1.6}
.stButton>button{width:100%;border-radius:.5rem;font-weight:600;padding:.5rem 1rem}
.chain-block{background:linear-gradient(135deg,#1e293b,#0f172a);border-radius:.75rem;padding:1rem;margin-bottom:.5rem;color:#e2e8f0;font-family:'Courier New',monospace;font-size:.72rem;line-height:1.7;border:1px solid #334155}
.chain-link{text-align:center;color:#3b82f6;font-size:1.2rem;margin:.2rem 0}
</style>
""", unsafe_allow_html=True)

# ── Database Path (writable on Streamlit Cloud & Docker) ─────────────────────
DB_PATH = Path("/tmp/heart_monitor.db").resolve()

def get_db_connection():
    return sqlite3.connect(str(DB_PATH))

def init_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            age INTEGER,
            gender TEXT,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        c.execute('''CREATE TABLE IF NOT EXISTS test_results(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bpm INTEGER NOT NULL,
            quality REAL NOT NULL,
            encrypted_hex TEXT NOT NULL,
            key_hex TEXT NOT NULL,
            ecc_public_key TEXT,
            blockchain_hash TEXT,
            test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        c.execute('''CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            previous_hash TEXT,
            current_hash TEXT)''')

        # Create default admin
        c.execute("SELECT id FROM users WHERE username='admin'")
        if not c.fetchone():
            pw_hash = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
            c.execute('''INSERT INTO users 
                (username, password_hash, full_name, age, gender, is_admin)
                VALUES (?, ?, ?, ?, ?, ?)''',
                ('admin', pw_hash, 'System Administrator', 30, 'Male', 1))

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"❌ Database initialization failed: {e}")
        st.info(f"Path: {DB_PATH}")
        return False

# Initialize database
if not init_db():
    st.stop()

# ── Session State ─────────────────────────────────────────────────────────────
for k, v in [('authenticated', False), ('user_id', None), ('username', None),
             ('is_admin', False), ('saved_bpm', None), ('saved_quality', None),
             ('last_enc', None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# ── rPPG HTML (unchanged) ─────────────────────────────────────────────────────
RPPG_HTML = r"""<!DOCTYPE html> ... </html>"""   # (Your full RPPG_HTML code remains the same)

# Keep your original RPPG_HTML here (it's very long, so I'm not repeating it fully for brevity)
# Just paste your original RPPG_HTML back in this place.

RELAY_SCRIPT = """
<script>
(function(){
  window.addEventListener('message', function(e){
    if(!e.data || e.data.type !== 'rppg:save') return;
    const bpm = e.data.bpm;
    const q = e.data.quality;
    const url = new URL(window.location.href);
    url.searchParams.set('rppg_bpm', bpm);
    url.searchParams.set('rppg_q', q);
    window.location.href = url.toString();
  });
})();
</script>
"""

# ── Helper Functions ─────────────────────────────────────────────────────────
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
    return ch

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
    nonce_hex = nonce.hex()
    ct_hex = ciphertext.hex()

    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_key = priv_key.public_key()
    pub_pem = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    priv_pem = priv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()

    hmac_sig = hashlib.sha256(f"{payload}{key_hex}".encode()).hexdigest()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT blockchain_hash FROM test_results ORDER BY id DESC LIMIT 1")
    prev_block = c.fetchone()
    prev_hash = prev_block[0] if prev_block else 'GENESIS_BLOCK_0000000000000000000000000000000'

    block_hash = hashlib.sha256(f"{prev_hash}{st.session_state.user_id}{bpm}{quality}{ts}{hmac_sig}".encode()).hexdigest()

    c.execute('''INSERT INTO test_results
        (user_id,bpm,quality,encrypted_hex,key_hex,ecc_public_key,blockchain_hash)
        VALUES(?,?,?,?,?,?,?)''',
        (st.session_state.user_id, bpm, quality, payload, key_hex, pub_pem[:120], block_hash))
    conn.commit()
    record_id = c.lastrowid
    conn.close()

    add_audit_log(st.session_state.user_id, "SAVE_RESULT", f"BPM:{bpm} Q:{quality}%")

    return {
        "record_id": record_id, "bpm": bpm, "quality": quality, "ts": ts,
        "plaintext": plaintext, "aes_key": key_hex, "nonce": nonce_hex,
        "ciphertext": ct_hex, "payload": payload, "pub_pem": pub_pem,
        "priv_pem": priv_pem[:80] + "\n...(private — never transmitted)",
        "hmac": hmac_sig, "prev_hash": prev_hash, "block_hash": block_hash,
    }

# ── Rest of your functions (show_encryption_and_chain, show_login, show_dashboard) remain the same
# Just make sure to use get_db_connection() everywhere.

# (For brevity I didn't repeat the very long show_encryption_and_chain, show_login, etc.)
# Replace all remaining `sqlite3.connect('heart_monitor.db')` with `get_db_connection()`

def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
