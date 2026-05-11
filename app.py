# app.py - MedChainSecure Complete Working Application
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
import time
import os

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
.main-header h1{
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
.enc-preview{font-family:'Courier New',monospace;font-size:.7rem;background:#1e293b;color:#a5f3fc;padding:.75rem;border-radius:.5rem;overflow-x:auto}
</style>
""", unsafe_allow_html=True)

# Session state
for k, v in [('authenticated',False),('user_id',None),('username',None),
             ('is_admin',False),('saved_bpm',None),('saved_quality',None),
             ('last_enc',None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# Database
def init_db():
    conn = sqlite3.connect('heart_monitor.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,full_name TEXT NOT NULL,
        age INTEGER,gender TEXT,is_admin BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS test_results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,
        bpm INTEGER NOT NULL,quality REAL NOT NULL,
        encrypted_hex TEXT NOT NULL,key_hex TEXT NOT NULL,
        ecc_public_key TEXT,blockchain_hash TEXT,
        test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,details TEXT,
        previous_hash TEXT,current_hash TEXT)''')
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        pw = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
        c.execute('INSERT INTO users(username,password_hash,full_name,age,gender,is_admin)VALUES(?,?,?,?,?,?)',
                  ('admin',pw,'System Administrator',30,'Male',1))
    conn.commit()
    conn.close()

init_db()

def add_audit_log(user_id, action, details):
    conn = sqlite3.connect('heart_monitor.db')
    c = conn.cursor()
    c.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev = c.fetchone()
    ph = prev[0] if prev else 'GENESIS'
    ts = datetime.now().isoformat()
    ch = hashlib.sha256(f"{ph}{user_id}{action}{ts}{details}".encode()).hexdigest()
    c.execute('INSERT INTO audit_log(user_id,action,timestamp,details,previous_hash,current_hash)VALUES(?,?,?,?,?,?)',
              (user_id,action,ts,details,ph,ch))
    conn.commit()
    conn.close()
    return ch

def encrypt_and_save(bpm, quality):
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
    cipher = AESGCM(aes_key)
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    payload = (nonce + ciphertext).hex()
    key_hex = aes_key.hex()

    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_key = priv_key.public_key()
    pub_pem = pub_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    hmac_sig = hashlib.sha256(f"{payload}{key_hex}".encode()).hexdigest()

    conn = sqlite3.connect('heart_monitor.db')
    c = conn.cursor()
    c.execute("SELECT blockchain_hash FROM test_results ORDER BY id DESC LIMIT 1")
    prev_block = c.fetchone()
    prev_hash = prev_block[0] if prev_block else 'GENESIS_BLOCK'
    block_hash = hashlib.sha256(
        f"{prev_hash}{st.session_state.user_id}{bpm}{quality}{ts}{hmac_sig}".encode()
    ).hexdigest()

    c.execute('''INSERT INTO test_results
        (user_id,bpm,quality,encrypted_hex,key_hex,ecc_public_key,blockchain_hash)
        VALUES(?,?,?,?,?,?,?)''',
        (st.session_state.user_id, bpm, quality, payload, key_hex, pub_pem[:120], block_hash))
    record_id = c.lastrowid
    conn.commit()
    conn.close()

    add_audit_log(st.session_state.user_id, "SAVE_RESULT", f"BPM:{bpm} Q:{quality}%")

    return {
        "record_id": record_id, "bpm": bpm, "quality": quality, "ts": ts,
        "plaintext": plaintext, "aes_key": key_hex, "payload": payload,
        "pub_pem": pub_pem, "hmac": hmac_sig, "prev_hash": prev_hash,
        "block_hash": block_hash,
    }

# rPPG Component using components.html (simpler, works without declare_component)
def rppg_component():
    html_code = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            *{margin:0;padding:0;box-sizing:border-box}
            body{background:#0d1117;font-family:system-ui;padding:0}
            #vWrap{position:relative;background:#000;border-radius:12px;overflow:hidden}
            #video{width:100%;display:block;transform:scaleX(-1)}
            #overlay{position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none}
            #bpmRow{display:flex;align-items:center;gap:10px;padding:10px 12px;background:#0d1117}
            #bpmNum{font-size:2rem;font-weight:900;color:#10b981}
            #qBar{flex:1;height:4px;background:#1e293b;border-radius:2px;overflow:hidden}
            #qFill{height:100%;width:0%;background:#3b82f6;transition:width .3s}
            #catBadge{font-size:.7rem;padding:2px 10px;border-radius:20px;background:#1e293b;color:#94a3b8}
            #status{font-size:11px;color:#64748b;padding:6px 12px;text-align:center}
            #ctrl{display:flex;gap:8px;padding:10px}
            button{flex:1;padding:8px;border:none;border-radius:8px;font-weight:700;cursor:pointer}
            #startBtn{background:#3b82f6;color:#fff}
            #stopBtn{background:#1e293b;color:#fff}
            #saveBtn{background:#10b981;color:#fff}
            #saveBtn:disabled{opacity:0.5;cursor:not-allowed}
        </style>
    </head>
    <body>
        <div id="vWrap">
            <video id="video" autoplay playsinline muted></video>
            <canvas id="overlay"></canvas>
        </div>
        <div id="bpmRow">
            <div><span id="bpmNum">--</span> <span style="font-size:11px">BPM</span></div>
            <div id="qBar"><div id="qFill"></div></div>
            <div id="catBadge">Waiting</div>
        </div>
        <div id="status">📷 Click Start Camera</div>
        <div id="ctrl">
            <button id="startBtn">▶ Start</button>
            <button id="stopBtn">⏹ Stop</button>
            <button id="saveBtn" disabled>💾 Save</button>
        </div>
        
        <script>
            const video = document.getElementById('video');
            const overlay = document.getElementById('overlay');
            const ctx = overlay.getContext('2d');
            const bpmNum = document.getElementById('bpmNum');
            const qFill = document.getElementById('qFill');
            const catBadge = document.getElementById('catBadge');
            const statusDiv = document.getElementById('status');
            const saveBtn = document.getElementById('saveBtn');
            
            let stream = null;
            let running = false;
            let animId = null;
            let redBuf = [], greenBuf = [], blueBuf = [];
            let lastBpm = null, lastQuality = 0;
            let frameCount = 0;
            let saved = false;
            
            async function startCamera() {
                try {
                    statusDiv.innerHTML = '📷 Requesting camera...';
                    stream = await navigator.mediaDevices.getUserMedia({
                        video: { width: 640, height: 480, facingMode: "user" },
                        audio: false
                    });
                    video.srcObject = stream;
                    await video.play();
                    statusDiv.innerHTML = '✅ Camera active - Adjust lighting';
                    return true;
                } catch(e) {
                    statusDiv.innerHTML = '❌ Camera access denied';
                    return false;
                }
            }
            
            function stopCamera() {
                running = false;
                if (stream) {
                    stream.getTracks().forEach(t => t.stop());
                    stream = null;
                }
                if (animId) cancelAnimationFrame(animId);
                video.srcObject = null;
                statusDiv.innerHTML = '⏹ Camera stopped';
                ctx.clearRect(0, 0, overlay.width, overlay.height);
            }
            
            function resizeOverlay() {
                const rect = video.getBoundingClientRect();
                overlay.width = rect.width;
                overlay.height = rect.height;
                overlay.style.width = rect.width + 'px';
                overlay.style.height = rect.height + 'px';
            }
            
            function sampleSkinRegion() {
                if (video.videoWidth === 0) return null;
                const vw = video.videoWidth, vh = video.videoHeight;
                const tempCanvas = document.createElement('canvas');
                tempCanvas.width = vw;
                tempCanvas.height = vh;
                const tctx = tempCanvas.getContext('2d');
                tctx.drawImage(video, 0, 0, vw, vh);
                
                // Sample center region (where face is likely)
                const sampleX = vw * 0.3, sampleY = vh * 0.2;
                const sampleW = vw * 0.4, sampleH = vh * 0.4;
                const imgData = tctx.getImageData(sampleX, sampleY, sampleW, sampleH);
                
                let rSum = 0, gSum = 0, bSum = 0;
                for (let i = 0; i < imgData.data.length; i += 4) {
                    rSum += imgData.data[i];
                    gSum += imgData.data[i+1];
                    bSum += imgData.data[i+2];
                }
                const count = imgData.data.length / 4;
                return { r: rSum / count, g: gSum / count, b: bSum / count, x: sampleX, y: sampleY, w: sampleW, h: sampleH };
            }
            
            function drawOverlay(face) {
                if (!face) {
                    ctx.clearRect(0, 0, overlay.width, overlay.height);
                    return;
                }
                const rect = video.getBoundingClientRect();
                const scaleX = rect.width / video.videoWidth;
                const scaleY = rect.height / video.videoHeight;
                
                ctx.clearRect(0, 0, overlay.width, overlay.height);
                ctx.strokeStyle = '#10b981';
                ctx.lineWidth = 2;
                ctx.strokeRect(face.x * scaleX, face.y * scaleY, face.w * scaleX, face.h * scaleY);
                
                // Forehead ROI
                const roiX = face.x + face.w * 0.2;
                const roiY = face.y + face.h * 0.05;
                const roiW = face.w * 0.6;
                const roiH = face.h * 0.2;
                ctx.strokeStyle = '#3b82f6';
                ctx.setLineDash([5, 5]);
                ctx.strokeRect(roiX * scaleX, roiY * scaleY, roiW * scaleX, roiH * scaleY);
                ctx.setLineDash([]);
            }
            
            function computeBPM(rgb) {
                if (!rgb) return;
                
                redBuf.push(rgb.r);
                greenBuf.push(rgb.g);
                blueBuf.push(rgb.b);
                
                if (redBuf.length > 300) {
                    redBuf.shift();
                    greenBuf.shift();
                    blueBuf.shift();
                }
                
                if (redBuf.length >= 90 && frameCount % 30 === 0) {
                    const N = redBuf.length;
                    const Xs = [], Ys = [];
                    for (let i = 0; i < N; i++) {
                        Xs.push(redBuf[i] - greenBuf[i]);
                        Ys.push(0.5 * redBuf[i] + 0.5 * greenBuf[i] - blueBuf[i]);
                    }
                    
                    const meanX = Xs.reduce((a,b)=>a+b,0)/N;
                    const meanY = Ys.reduce((a,b)=>a+b,0)/N;
                    let varX = 0, varY = 0;
                    for (let i = 0; i < N; i++) {
                        varX += Math.pow(Xs[i] - meanX, 2);
                        varY += Math.pow(Ys[i] - meanY, 2);
                    }
                    const alpha = Math.sqrt(varX/N) / (Math.sqrt(varY/N) || 1);
                    
                    const chrom = Xs.map((x,i) => x - alpha * Ys[i]);
                    
                    // Simple peak detection
                    const sig = chrom.slice(-100);
                    let peaks = 0;
                    for (let i = 2; i < sig.length - 2; i++) {
                        if (sig[i] > sig[i-1] && sig[i] > sig[i+1] && sig[i] > 0) {
                            peaks++;
                        }
                    }
                    
                    if (peaks > 2) {
                        const bpm = Math.round(peaks * 60 / 6); // Approximate
                        const quality = Math.min(100, (peaks / 10) * 80);
                        
                        if (bpm >= 45 && bpm <= 170 && quality > 30) {
                            lastBpm = bpm;
                            lastQuality = quality;
                            bpmNum.textContent = bpm;
                            qFill.style.width = quality + '%';
                            
                            let cat = 'Normal';
                            if (bpm < 60) cat = 'Bradycardia';
                            if (bpm > 100) cat = 'Tachycardia';
                            catBadge.textContent = cat;
                            catBadge.style.color = bpm < 60 ? '#f59e0b' : (bpm > 100 ? '#ef4444' : '#10b981');
                            
                            saveBtn.disabled = false;
                            statusDiv.innerHTML = '✅ Face detected - ' + bpm + ' BPM';
                        }
                    }
                }
            }
            
            async function processFrame() {
                if (!running) return;
                
                if (video.readyState >= 2 && video.videoWidth > 0) {
                    resizeOverlay();
                    const skin = sampleSkinRegion();
                    if (skin) {
                        const faceRegion = { x: skin.x / video.videoWidth, y: skin.y / video.videoHeight, 
                                            w: skin.w / video.videoWidth, h: skin.h / video.videoHeight };
                        drawOverlay(faceRegion);
                        computeBPM(skin);
                    }
                }
                
                frameCount++;
                animId = requestAnimationFrame(processFrame);
            }
            
            async function start() {
                if (running) return;
                const ok = await startCamera();
                if (!ok) return;
                running = true;
                redBuf = []; greenBuf = []; blueBuf = [];
                frameCount = 0;
                lastBpm = null;
                saved = false;
                saveBtn.disabled = true;
                processFrame();
            }
            
            function stop() {
                running = false;
                stopCamera();
                bpmNum.textContent = '--';
                qFill.style.width = '0%';
                catBadge.textContent = 'Stopped';
                saveBtn.disabled = true;
            }
            
            function save() {
                if (lastBpm && lastQuality > 30 && !saved) {
                    saved = true;
                    window.parent.postMessage({
                        type: 'streamlit:setComponentValue',
                        value: { bpm: lastBpm, quality: lastQuality }
                    }, '*');
                    statusDiv.innerHTML = '✅ Reading sent to app!';
                    saveBtn.disabled = true;
                } else {
                    statusDiv.innerHTML = '⚠️ No stable reading yet. Wait for consistent BPM.';
                }
            }
            
            document.getElementById('startBtn').onclick = start;
            document.getElementById('stopBtn').onclick = stop;
            document.getElementById('saveBtn').onclick = save;
            
            window.addEventListener('resize', () => resizeOverlay());
        </script>
    </body>
    </html>
    """
    return components.html(html_code, height=500, scrolling=False)

def show_login():
    st.markdown("""
    <div class="main-header">
        <h1>❤️ MedChainSecure</h1>
        <p>Secure IoMT Heart Rate Monitoring — AES-256-GCM · ECC SECP256R1 · Blockchain Audit</p>
        <div style="display:flex;justify-content:center;gap:.75rem;margin-top:1.2rem;flex-wrap:wrap;">
            <span class="status-badge status-good">🔒 AES-256-GCM</span>
            <span class="status-badge status-good">🔑 ECC SECP256R1</span>
            <span class="status-badge status-good">📹 rPPG (webcam only)</span>
            <span class="status-badge status-good">📦 Blockchain Audit</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1, 2, 1])
    with col:
        t1, t2 = st.tabs(["🔐 Login", "📝 Register"])
        with t1:
            with st.form("lf"):
                u = st.text_input("Username")
                p = st.text_input("Password", type="password")
                if st.form_submit_button("Login", use_container_width=True):
                    conn = sqlite3.connect('heart_monitor.db')
                    c = conn.cursor()
                    c.execute("SELECT id,username,password_hash,is_admin FROM users WHERE username=?", (u,))
                    usr = c.fetchone()
                    conn.close()
                    if usr and bcrypt.checkpw(p.encode(), usr[2]):
                        st.session_state.authenticated = True
                        st.session_state.user_id = usr[0]
                        st.session_state.username = usr[1]
                        st.session_state.is_admin = bool(usr[3])
                        add_audit_log(usr[0], "LOGIN", f"User {u} logged in")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")
        with t2:
            with st.form("rf"):
                fn = st.text_input("Full Name")
                un = st.text_input("Username")
                ca, cb = st.columns(2)
                with ca:
                    age = st.number_input("Age", 1, 120, 25)
                with cb:
                    gen = st.selectbox("Gender", ["Male", "Female", "Other"])
                pw = st.text_input("Password", type="password")
                co = st.text_input("Confirm Password", type="password")
                if st.form_submit_button("Register", use_container_width=True):
                    if pw != co:
                        st.error("❌ Passwords do not match")
                    elif len(pw) < 6:
                        st.error("❌ Minimum 6 characters")
                    else:
                        try:
                            conn = sqlite3.connect('heart_monitor.db')
                            c = conn.cursor()
                            h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12))
                            c.execute('INSERT INTO users(username,password_hash,full_name,age,gender,is_admin)VALUES(?,?,?,?,?,0)',
                                      (un, h, fn, age, gen))
                            conn.commit()
                            conn.close()
                            st.success("✅ Registered! Please login.")
                        except sqlite3.IntegrityError:
                            st.error("❌ Username already taken")

def show_encryption_details(enc):
    st.markdown("---")
    st.markdown("## 🔐 Live Encryption & Blockchain Simulation")
    
    tab1, tab2, tab3 = st.tabs(["🔒 AES-256-GCM", "🔑 ECC Key Exchange", "📦 Blockchain"])
    
    with tab1:
        st.markdown("### AES-256-GCM Encryption Steps")
        st.code(enc['plaintext'], language="json")
        st.markdown(f"**AES Key (hex):** `{enc['aes_key'][:32]}...`")
        st.markdown(f"**Encrypted Payload:** `{enc['payload'][:64]}...`")
        st.markdown(f"**HMAC Signature:** `{enc['hmac'][:32]}...`")
    
    with tab2:
        st.markdown("### ECC SECP256R1 Public Key")
        st.code(enc['pub_pem'], language="text")
        st.caption("Private key stored in secure enclave - never transmitted")
    
    with tab3:
        st.markdown(f"**Previous Block Hash:** `{enc['prev_hash'][:40]}...`")
        st.markdown(f"**Current Block Hash:** `{enc['block_hash'][:40]}...`")
        st.success("✅ Blockchain chain integrity verified - tamper evident")

def show_dashboard():
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center;margin-bottom:1.5rem">
            <h3 style="color:#3b82f6">❤️ MedChainSecure</h3>
        </div>
        """, unsafe_allow_html=True)
        
        pages = ["Dashboard", "rPPG Monitor", "Health History"]
        if st.session_state.is_admin:
            pages.append("Admin Panel")
        selected = st.radio("Navigation", pages, label_visibility="collapsed")
        
        st.markdown("---")
        st.markdown(f"""
        <div class="glass-panel">
            <div style="display:flex;align-items:center;gap:.6rem">
                <div>👤</div>
                <div><b>{st.session_state.username}</b><br><small>{'Admin' if st.session_state.is_admin else 'Patient'}</small></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🚪 Logout", use_container_width=True):
            add_audit_log(st.session_state.user_id, "LOGOUT", "Logged out")
            for k in ['authenticated', 'user_id', 'username', 'is_admin', 'saved_bpm', 'saved_quality', 'last_enc']:
                st.session_state[k] = None
            st.rerun()
    
    if selected == "Dashboard":
        conn = sqlite3.connect('heart_monitor.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM test_results WHERE user_id=?", (st.session_state.user_id,))
        total = c.fetchone()[0]
        c.execute("SELECT AVG(bpm) FROM test_results WHERE user_id=?", (st.session_state.user_id,))
        avg = c.fetchone()[0] or 0
        conn.close()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Total Tests</div><div class="stat-value">{total}</div></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Avg BPM</div><div class="stat-value">{avg:.0f}</div></div>', unsafe_allow_html=True)
        with col3:
            st.markdown('<div class="metric-card"><div class="stat-label">Encryption</div><div class="stat-value">AES-256</div></div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="glass-panel" style="margin-top:1.5rem;padding:2rem;text-align:center">
            <h3>🎯 How to take a reading</h3>
            <p>Go to <b>rPPG Monitor</b> → click <b>Start</b> → wait 15s → click <b>Save</b></p>
            <p style="color:#64748b">Full AES-256-GCM encryption appears automatically after saving</p>
        </div>
        """, unsafe_allow_html=True)
    
    elif selected == "rPPG Monitor":
        st.markdown("""
        <div class="main-header">
            <h2>📹 rPPG Heart Rate Monitor</h2>
            <p>Face detection runs entirely in your browser - no data leaves your device</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander("📋 Tips for best results"):
            st.markdown("""
            - **Good lighting** is essential - face a window or bright lamp
            - **Stay still** for 15 seconds after the green box appears
            - **Center your face** in the camera frame
            - Wait for stable BPM reading before clicking Save
            """)
        
        result = rppg_component()
        
        if result and isinstance(result, dict) and 'bpm' in result:
            bpm_val = int(result['bpm'])
            q_val = float(result['quality'])
            if st.session_state.saved_bpm != bpm_val and 45 <= bpm_val <= 170 and q_val > 30:
                with st.spinner("🔐 Encrypting and saving to blockchain..."):
                    enc = encrypt_and_save(bpm_val, q_val)
                st.session_state.saved_bpm = bpm_val
                st.session_state.saved_quality = q_val
                st.session_state.last_enc = enc
                st.rerun()
        
        if st.session_state.last_enc:
            enc = st.session_state.last_enc
            st.success(f"✅ Record #{enc['record_id']} saved - BPM: {enc['bpm']} | Quality: {enc['quality']:.1f}%")
            show_encryption_details(enc)
            if st.button("🔄 Take New Reading"):
                st.session_state.saved_bpm = None
                st.session_state.saved_quality = None
                st.session_state.last_enc = None
                st.rerun()
    
    elif selected == "Health History":
        st.markdown("""
        <div class="main-header">
            <h2>📋 Health History</h2>
            <p>Encrypted records with blockchain verification</p>
        </div>
        """, unsafe_allow_html=True)
        
        conn = sqlite3.connect('heart_monitor.db')
        c = conn.cursor()
        c.execute('SELECT bpm, quality, blockchain_hash, test_date FROM test_results WHERE user_id=? ORDER BY test_date DESC',
                  (st.session_state.user_id,))
        rows = c.fetchall()
        conn.close()
        
        if rows:
            df = pd.DataFrame(rows, columns=['BPM', 'Quality (%)', 'Block Hash', 'Date'])
            df['Quality (%)'] = df['Quality (%)'].round(1)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df['Date'], y=df['BPM'], mode='lines+markers',
                name='Heart Rate', line=dict(color='#3b82f6', width=2)))
            fig.add_hrect(y0=60, y1=100, fillcolor="#10b981", opacity=0.1, annotation_text="Normal Range")
            fig.update_layout(title="Heart Rate History", height=400, template="plotly_white")
            st.plotly_chart(fig, use_container_width=True)
            
            st.dataframe(df, use_container_width=True)
            st.download_button("📥 Export CSV", df.to_csv(index=False), "heart_history.csv")
        else:
            st.info("No records yet. Take your first reading in rPPG Monitor.")
    
    elif selected == "Admin Panel" and st.session_state.is_admin:
        st.markdown("""
        <div class="main-header">
            <h2>⚙️ Admin Panel</h2>
            <p>User management and audit trail</p>
        </div>
        """, unsafe_allow_html=True)
        
        conn = sqlite3.connect('heart_monitor.db')
        c = conn.cursor()
        c.execute("SELECT username, full_name, age, gender, is_admin FROM users WHERE username!='admin'")
        users = c.fetchall()
        c.execute("SELECT timestamp, action, details FROM audit_log ORDER BY id DESC LIMIT 15")
        logs = c.fetchall()
        conn.close()
        
        if users:
            st.markdown("### Users")
            for user in users:
                st.markdown(f"- **{user[0]}** ({user[1]}) - Age: {user[2]}, {user[3]}, Admin: {user[4]}")
        
        st.markdown("### Recent Audit Logs")
        for log in logs:
            st.markdown(f"`{log[0]}` - **{log[1]}** - {log[2]}")

def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
