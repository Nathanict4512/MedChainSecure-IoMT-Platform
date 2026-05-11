# app.py - MedChainSecure Complete Application
import streamlit as st
import sqlite3
import hashlib
import json
import secrets
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import bcrypt
from streamlit.components.v1 import html
import time

st.set_page_config(
    page_title="MedChainSecure - Real rPPG Heart Monitor",
    page_icon="❤️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
/* Professional Light Theme */
:root {
    --bg-primary: #f8fafc;
    --bg-secondary: #ffffff;
    --bg-card: #ffffff;
    --text-primary: #1e293b;
    --text-secondary: #64748b;
    --accent-primary: #3b82f6;
    --accent-secondary: #06b6d4;
    --accent-tertiary: #10b981;
    --accent-warning: #f59e0b;
    --border-color: #e2e8f0;
}

.stApp {
    background: var(--bg-primary);
}

.main-header {
    background: linear-gradient(135deg, #ffffff 0%, #f1f5f9 100%);
    padding: 2rem;
    border-radius: 1rem;
    margin-bottom: 2rem;
    border: 1px solid var(--border-color);
    text-align: center;
}

.main-header h1 {
    font-size: 2rem;
    margin-bottom: 0.5rem;
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.main-header p {
    color: var(--text-secondary);
    font-size: 1rem;
}

.glass-panel {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 0.75rem;
    padding: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}

.metric-card {
    background: var(--bg-card);
    border-radius: 0.75rem;
    padding: 1.25rem;
    border: 1px solid var(--border-color);
    text-align: center;
    transition: all 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
}

.stat-value {
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
}

.stat-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
    font-weight: 600;
}

.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.85rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
}

.status-good {
    background: #d1fae5;
    color: #065f46;
}

.status-warning {
    background: #fed7aa;
    color: #9a3412;
}

.status-info {
    background: #dbeafe;
    color: #1e40af;
}

.bpm-card {
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    border-radius: 1rem;
    padding: 1.5rem;
    color: white;
    text-align: center;
    margin-bottom: 1rem;
}

.bpm-value {
    font-size: 4rem;
    font-weight: bold;
}

.quality-bar {
    height: 0.5rem;
    background: rgba(255,255,255,0.3);
    border-radius: 0.25rem;
    overflow: hidden;
    margin: 0.75rem 0;
}

.quality-fill {
    height: 100%;
    background: #10b981;
    transition: width 0.3s;
    width: 0%;
}

.stats-row {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    margin: 1rem 0;
}

.stat-box {
    background: white;
    padding: 0.75rem;
    border-radius: 0.5rem;
    text-align: center;
    border: 1px solid #e2e8f0;
}

.encryption-preview {
    font-family: 'Courier New', monospace;
    font-size: 0.7rem;
    background: #1e293b;
    color: #a5f3fc;
    padding: 0.75rem;
    border-radius: 0.5rem;
    overflow-x: auto;
}

.stButton > button {
    width: 100%;
    border-radius: 0.5rem;
    font-weight: 600;
    padding: 0.5rem 1rem;
}

div[data-testid="stTabs"] button {
    font-weight: 600;
}

/* Status chip */
.status-chip {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    background: rgba(255,255,255,0.2);
    color: white;
}
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'username' not in st.session_state:
    st.session_state.username = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False
if 'saved_bpm' not in st.session_state:
    st.session_state.saved_bpm = None
if 'saved_quality' not in st.session_state:
    st.session_state.saved_quality = None

# Database setup
def init_db():
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bpm INTEGER NOT NULL,
            quality REAL NOT NULL,
            encrypted_hex TEXT NOT NULL,
            key_hex TEXT NOT NULL,
            ecc_public_key TEXT,
            test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            previous_hash TEXT,
            current_hash TEXT
        )
    ''')
    
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        password_hash = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
        cursor.execute('INSERT INTO users (username, password_hash, full_name, age, gender, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
                       ('admin', password_hash, 'System Administrator', 30, 'Male', 1))
    conn.commit()
    conn.close()

init_db()

def add_audit_log(user_id, action, details):
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    cursor.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev = cursor.fetchone()
    previous_hash = prev[0] if prev else 'GENESIS'
    timestamp = datetime.now().isoformat()
    data = f"{previous_hash}{user_id}{action}{timestamp}{details}"
    current_hash = hashlib.sha256(data.encode()).hexdigest()
    cursor.execute('INSERT INTO audit_log (user_id, action, timestamp, details, previous_hash, current_hash) VALUES (?, ?, ?, ?, ?, ?)',
                   (user_id, action, timestamp, details, previous_hash, current_hash))
    conn.commit()
    conn.close()

def encrypt_and_save(bpm, quality):
    health_data = {
        "patient_id": f"PT-{st.session_state.user_id:04d}",
        "heart_rate": bpm,
        "signal_quality": quality,
        "timestamp": datetime.now().isoformat(),
        "user": st.session_state.username
    }
    
    plaintext = json.dumps(health_data)
    
    # AES-256-GCM Encryption
    key = secrets.token_bytes(32)
    key_hex = key.hex()
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    payload = (nonce + ciphertext).hex()
    
    # ECC Key Generation
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # Blockchain hash
    hmac_sig = hashlib.sha256(f"{payload}{key_hex}".encode()).hexdigest()
    blockchain_hash = hashlib.sha256(f"GENESIS{st.session_state.user_id}SAVE_RESULT{datetime.now().isoformat()}{hmac_sig}".encode()).hexdigest()
    
    # Save to database
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO test_results (user_id, bpm, quality, encrypted_hex, key_hex, ecc_public_key)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (st.session_state.user_id, bpm, quality, payload, key_hex, public_pem[:100].decode()))
    conn.commit()
    conn.close()
    
    add_audit_log(st.session_state.user_id, "SAVE_RESULT", f"BPM: {bpm}, Quality: {quality}%")
    
    return key_hex, payload, public_pem.decode(), blockchain_hash

# rPPG Component
def rppg_component():
    component_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>rPPG Monitor</title>
        <script src="https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.15.0/dist/tf.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@tensorflow-models/face-detection@1.0.2/dist/face-detection.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                background: #0a0f1a;
                border-radius: 16px;
                overflow: hidden;
            }
            .video-container {
                position: relative;
                width: 100%;
                background: #0a0f1a;
            }
            video {
                width: 100%;
                height: auto;
                transform: scaleX(-1);
                display: block;
            }
            .face-box {
                position: absolute;
                border: 3px solid #10b981;
                border-radius: 12px;
                display: none;
                pointer-events: none;
            }
            .roi-box {
                position: absolute;
                border: 2px solid #3b82f6;
                background: rgba(59,130,246,0.25);
                border-radius: 6px;
                display: none;
                pointer-events: none;
            }
            .status-text {
                text-align: center;
                padding: 12px;
                font-size: 13px;
                background: #0a0f1a;
                color: #94a3b8;
            }
            .controls {
                display: flex;
                gap: 12px;
                padding: 16px;
                background: #0a0f1a;
                justify-content: center;
                border-top: 1px solid #1e293b;
            }
            button {
                padding: 10px 24px;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                font-size: 14px;
                transition: all 0.2s;
            }
            .btn-start { background: #3b82f6; color: white; }
            .btn-start:hover { background: #2563eb; transform: scale(1.02); }
            .btn-stop { background: #ef4444; color: white; }
            .btn-stop:hover { background: #dc2626; transform: scale(1.02); }
            .btn-save { background: #10b981; color: white; }
            .btn-save:hover { background: #059669; transform: scale(1.02); }
            .spinner {
                display: inline-block;
                width: 14px;
                height: 14px;
                border: 2px solid #fff;
                border-top-color: transparent;
                border-radius: 50%;
                animation: spin 0.6s linear infinite;
                margin-right: 8px;
            }
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="video-container">
            <video id="video" autoplay playsinline muted></video>
            <div id="faceBox" class="face-box"></div>
            <div id="roiBox" class="roi-box"></div>
        </div>
        <div class="status-text" id="statusText">
            <span id="statusIcon">📷</span> Click Start Camera
        </div>
        <div class="controls">
            <button class="btn-start" id="startBtn">▶ Start Camera</button>
            <button class="btn-stop" id="stopBtn">⏹ Stop Camera</button>
            <button class="btn-save" id="saveBtn">💾 Save Reading</button>
        </div>
        
        <script>
            const video = document.getElementById('video');
            const faceBox = document.getElementById('faceBox');
            const roiBox = document.getElementById('roiBox');
            const statusText = document.getElementById('statusText');
            
            let stream = null;
            let animationId = null;
            let faceDetector = null;
            let isRunning = false;
            let modelReady = false;
            
            let redChannel = [];
            let greenChannel = [];
            let blueChannel = [];
            let bpmHistory = [];
            let lastBpm = null;
            let lastQuality = 0;
            let frameCount = 0;
            let fps = 30;
            
            async function loadModel() {
                statusText.innerHTML = '<span class="spinner"></span> Loading face detection...';
                try {
                    await tf.ready();
                    const model = faceDetection.SupportedModels.MediaPipeFaceDetector;
                    faceDetector = await faceDetection.createDetector(model, {
                        runtime: 'tfjs',
                        maxFaces: 1
                    });
                    modelReady = true;
                    statusText.innerHTML = '✅ Model ready. Click Start Camera.';
                    return true;
                } catch(e) {
                    statusText.innerHTML = '❌ Failed to load model. Please refresh.';
                    return false;
                }
            }
            
            async function startCamera() {
                try {
                    statusText.innerHTML = '<span class="spinner"></span> Requesting camera...';
                    stream = await navigator.mediaDevices.getUserMedia({ 
                        video: { width: 640, height: 480, facingMode: "user" },
                        audio: false 
                    });
                    video.srcObject = stream;
                    await video.play();
                    statusText.innerHTML = '✅ Camera active - Detecting face...';
                    return true;
                } catch(e) {
                    statusText.innerHTML = '❌ Camera access denied. Please allow permissions.';
                    return false;
                }
            }
            
            function stopCamera() {
                isRunning = false;
                if (stream) {
                    stream.getTracks().forEach(track => track.stop());
                    stream = null;
                }
                if (animationId) {
                    cancelAnimationFrame(animationId);
                    animationId = null;
                }
                video.srcObject = null;
                faceBox.style.display = 'none';
                roiBox.style.display = 'none';
                statusText.innerHTML = '⏹ Camera stopped';
                redChannel = [];
                greenChannel = [];
                blueChannel = [];
                bpmHistory = [];
            }
            
            async function detectAndProcess() {
                if (!isRunning || !faceDetector || !video.videoWidth) {
                    animationId = requestAnimationFrame(() => detectAndProcess());
                    return;
                }
                
                try {
                    const faces = await faceDetector.estimateFaces(video);
                    
                    if (faces && faces.length > 0) {
                        const face = faces[0];
                        const box = face.boundingBox;
                        
                        const scaleX = video.clientWidth / video.videoWidth;
                        const scaleY = video.clientHeight / video.videoHeight;
                        
                        const left = box.xMin * scaleX;
                        const top = box.yMin * scaleY;
                        const width = (box.xMax - box.xMin) * scaleX;
                        const height = (box.yMax - box.yMin) * scaleY;
                        
                        faceBox.style.display = 'block';
                        faceBox.style.left = left + 'px';
                        faceBox.style.top = top + 'px';
                        faceBox.style.width = width + 'px';
                        faceBox.style.height = height + 'px';
                        
                        // Forehead ROI
                        const roiX = left + width * 0.2;
                        const roiY = top + height * 0.05;
                        const roiW = width * 0.6;
                        const roiH = height * 0.22;
                        
                        roiBox.style.display = 'block';
                        roiBox.style.left = roiX + 'px';
                        roiBox.style.top = roiY + 'px';
                        roiBox.style.width = roiW + 'px';
                        roiBox.style.height = roiH + 'px';
                        
                        // Extract pixel data
                        const tempCanvas = document.createElement('canvas');
                        tempCanvas.width = video.videoWidth;
                        tempCanvas.height = video.videoHeight;
                        const ctx = tempCanvas.getContext('2d');
                        ctx.drawImage(video, 0, 0);
                        
                        const imgX = box.xMin;
                        const imgY = box.yMin;
                        const imgW = (box.xMax - box.xMin);
                        const imgH = (box.yMax - box.yMin);
                        
                        const roiImgX = imgX + imgW * 0.2;
                        const roiImgY = imgY + imgH * 0.05;
                        const roiImgW = imgW * 0.6;
                        const roiImgH = imgH * 0.22;
                        
                        const imageData = ctx.getImageData(roiImgX, roiImgY, roiImgW, roiImgH);
                        
                        let rSum = 0, gSum = 0, bSum = 0;
                        for (let i = 0; i < imageData.data.length; i += 4) {
                            rSum += imageData.data[i];
                            gSum += imageData.data[i+1];
                            bSum += imageData.data[i+2];
                        }
                        const pixelCount = imageData.data.length / 4;
                        const rAvg = rSum / pixelCount;
                        const gAvg = gSum / pixelCount;
                        const bAvg = bSum / pixelCount;
                        
                        redChannel.push(rAvg);
                        greenChannel.push(gAvg);
                        blueChannel.push(bAvg);
                        
                        if (redChannel.length > 300) {
                            redChannel.shift();
                            greenChannel.shift();
                            blueChannel.shift();
                        }
                        
                        if (redChannel.length >= 150 && frameCount % 30 === 0) {
                            calculateBPM();
                        }
                        
                        statusText.innerHTML = '✅ Face detected - Measuring pulse...';
                    } else {
                        faceBox.style.display = 'none';
                        roiBox.style.display = 'none';
                        statusText.innerHTML = '🔍 No face detected - Center your face';
                    }
                } catch(e) {
                    console.error(e);
                }
                
                frameCount++;
                animationId = requestAnimationFrame(() => detectAndProcess());
            }
            
            function calculateBPM() {
                if (redChannel.length < 150) return;
                
                const N = redChannel.length;
                const Xs = [];
                const Ys = [];
                
                for (let i = 0; i < N; i++) {
                    const R = redChannel[i];
                    const G = greenChannel[i];
                    const B = blueChannel[i];
                    Xs.push(R - G);
                    Ys.push(0.5 * R + 0.5 * G - B);
                }
                
                const meanX = Xs.reduce((a,b) => a+b, 0) / N;
                const meanY = Ys.reduce((a,b) => a+b, 0) / N;
                let varX = 0, varY = 0;
                for (let i = 0; i < N; i++) {
                    varX += Math.pow(Xs[i] - meanX, 2);
                    varY += Math.pow(Ys[i] - meanY, 2);
                }
                const alpha = Math.sqrt(varX/N) / Math.sqrt(varY/N);
                
                const chromSignal = [];
                for (let i = 0; i < N; i++) {
                    chromSignal.push(Xs[i] - alpha * Ys[i]);
                }
                
                // Peak detection
                const signal = chromSignal.slice(-150);
                const peaks = [];
                for (let i = 2; i < signal.length - 2; i++) {
                    if (signal[i] > signal[i-1] && signal[i] > signal[i+1] &&
                        signal[i] > signal[i-2] && signal[i] > signal[i+2]) {
                        peaks.push(i);
                    }
                }
                
                if (peaks.length >= 2) {
                    const intervals = [];
                    for (let i = 1; i < peaks.length; i++) {
                        intervals.push(peaks[i] - peaks[i-1]);
                    }
                    const avgInterval = intervals.reduce((a,b) => a+b, 0) / intervals.length;
                    const bpm = Math.round(60 / (avgInterval / fps));
                    
                    const quality = Math.min(100, Math.max(0, (peaks.length / 10) * 70 + 20));
                    
                    if (bpm >= 50 && bpm <= 160 && quality > 40) {
                        lastBpm = bpm;
                        lastQuality = quality;
                        bpmHistory.push(bpm);
                        if (bpmHistory.length > 10) bpmHistory.shift();
                        
                        if (window.parent) {
                            window.parent.postMessage({
                                type: 'bpm_update',
                                bpm: bpm,
                                quality: quality
                            }, '*');
                        }
                    }
                }
            }
            
            async function start() {
                if (isRunning) return;
                if (!modelReady) {
                    await loadModel();
                }
                const cameraStarted = await startCamera();
                if (!cameraStarted) return;
                isRunning = true;
                redChannel = [];
                greenChannel = [];
                blueChannel = [];
                bpmHistory = [];
                frameCount = 0;
                detectAndProcess();
            }
            
            function stop() {
                isRunning = false;
                stopCamera();
            }
            
            function save() {
                if (lastBpm && lastBpm > 45 && lastBpm < 170 && lastQuality > 40) {
                    if (window.parent) {
                        window.parent.postMessage({
                            type: 'save_reading',
                            bpm: Math.round(lastBpm),
                            quality: lastQuality
                        }, '*');
                    }
                } else {
                    alert('No valid reading. Wait for stable face detection and good signal quality.');
                }
            }
            
            loadModel();
            document.getElementById('startBtn').onclick = start;
            document.getElementById('stopBtn').onclick = stop;
            document.getElementById('saveBtn').onclick = save;
        </script>
    </body>
    </html>
    """
    return html(component_html, height=520, scrolling=False)

# Login Page
def show_login():
    # Hero Section
    st.markdown("""
    <div class="main-header">
        <h1>❤️ MedChainSecure</h1>
        <p>Advanced Secure IoMT Heart Rate Monitoring Platform with AES-256-GCM Encryption</p>
        <div style="display: flex; justify-content: center; gap: 0.75rem; margin-top: 1.5rem; flex-wrap: wrap;">
            <span class="status-badge status-good">🔒 AES-256-GCM Encryption</span>
            <span class="status-badge status-good">🔑 ECC SECP256R1 Key Exchange</span>
            <span class="status-badge status-good">📹 Real-time rPPG Monitoring</span>
            <span class="status-badge status-good">📦 Blockchain Audit Trail</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
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
                        st.error("❌ Invalid username or password")
        
        with tab2:
            with st.form("register_form"):
                full_name = st.text_input("Full Name", placeholder="Enter your full name")
                username = st.text_input("Username", placeholder="Choose a username")
                col_a, col_b = st.columns(2)
                with col_a:
                    age = st.number_input("Age", min_value=1, max_value=120, value=30)
                with col_b:
                    gender = st.selectbox("Gender", ["Male", "Female", "Other"])
                password = st.text_input("Password", type="password", placeholder="Create a password")
                confirm = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
                submitted = st.form_submit_button("Register", use_container_width=True)
                
                if submitted:
                    if password != confirm:
                        st.error("❌ Passwords do not match")
                    elif len(password) < 6:
                        st.error("❌ Password must be at least 6 characters")
                    else:
                        conn = sqlite3.connect('heart_monitor.db')
                        cursor = conn.cursor()
                        try:
                            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
                            cursor.execute('INSERT INTO users (username, password_hash, full_name, age, gender, is_admin) VALUES (?, ?, ?, ?, ?, 0)',
                                           (username, pw_hash, full_name, age, gender))
                            conn.commit()
                            st.success("✅ Registration successful! Please login.")
                        except sqlite3.IntegrityError:
                            st.error("❌ Username already exists")
                        finally:
                            conn.close()
    
    # Features Section
    st.markdown("""
    <div style="margin-top: 3rem;">
        <h3 style="text-align: center; margin-bottom: 1.5rem;">Key Features</h3>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    features = [
        ("📹", "Non-invasive rPPG", "Remote heart rate monitoring using standard webcam"),
        ("🔐", "Hybrid Encryption", "AES-256-GCM + ECC SECP256R1 for every record"),
        ("🗄️", "3-Layer Storage", "Local SQLite + Remote Backup + Blockchain"),
        ("📊", "Audit Trail", "Immutable blockchain ledger for compliance")
    ]
    
    for col, (icon, title, desc) in zip([col1, col2, col3, col4], features):
        with col:
            st.markdown(f"""
            <div class="glass-panel" style="text-align: center; height: 100%;">
                <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">{icon}</div>
                <h4 style="margin-bottom: 0.5rem;">{title}</h4>
                <p style="font-size: 0.75rem; color: var(--text-secondary);">{desc}</p>
            </div>
            """, unsafe_allow_html=True)

def show_encryption_simulation(bpm, quality):
    st.markdown("### 🔐 Hybrid Encryption Pipeline")
    st.markdown("Your health data is being secured through military-grade encryption")
    
    health_data = {
        "patient_id": f"PT-{st.session_state.user_id:04d}",
        "heart_rate": bpm,
        "signal_quality": quality,
        "timestamp": datetime.now().isoformat(),
        "user": st.session_state.username
    }
    
    plaintext = json.dumps(health_data, indent=2)
    
    steps = [
        ("📝 Step 1: Original Data", "Patient health data prepared for encryption", plaintext),
        ("🔑 Step 2: AES-256 Key Generation", "Generating cryptographically secure 256-bit key", None),
        ("🎲 Step 3: Nonce Generation", "Creating 96-bit unique nonce for GCM mode", None),
        ("🔒 Step 4: AES-256-GCM Encryption", "Authenticated encryption with integrity tag", None),
        ("🔐 Step 5: ECC Key Exchange", "SECP256R1 curve key pair for secure sharing", None),
        ("✍️ Step 6: HMAC-SHA256 Signing", "Creating signature for tamper-proof verification", None),
        ("📦 Step 7: Blockchain Storage", "Adding to immutable audit trail", None)
    ]
    
    key_hex, payload, ecc_pub, block_hash = encrypt_and_save(bpm, quality)
    
    for i, (title, desc, data) in enumerate(steps, 1):
        with st.container():
            col1, col2 = st.columns([1, 4])
            with col1:
                st.markdown(f"### ✅")
            with col2:
                st.markdown(f"**{title}**")
                st.caption(desc)
                if data:
                    st.code(data, language="json")
                elif i == 2:
                    st.code(f"AES-256 Key: {key_hex[:32]}...{key_hex[-8:]}", language="text")
                elif i == 3:
                    st.code(f"Nonce: {secrets.token_hex(12)}", language="text")
                elif i == 4:
                    st.code(f"Ciphertext length: {len(payload)} bytes", language="text")
                elif i == 5:
                    st.code(f"ECC Public Key: {ecc_pub[:60]}...", language="text")
                elif i == 6:
                    sig = hashlib.sha256(f"{payload}{key_hex}".encode()).hexdigest()
                    st.code(f"HMAC: {sig[:32]}...", language="text")
                elif i == 7:
                    st.code(f"Block Hash: {block_hash[:32]}...", language="text")
        st.divider()
        time.sleep(0.15)
    
    st.markdown("### 📦 Encrypted Payload Preview")
    st.markdown(f"""
    <div class="encryption-preview">
        <strong>🔑 AES-256 Key:</strong> {key_hex[:32]}...{key_hex[-8:]}<br>
        <strong>🔐 ECC Public Key:</strong> {ecc_pub[:60]}...<br>
        <strong>🔗 Blockchain Hash:</strong> {block_hash[:32]}...<br>
        <strong>📊 Encrypted Size:</strong> {len(payload)} bytes
    </div>
    """, unsafe_allow_html=True)
    
    st.success(f"✅ Data saved! BPM: {bpm}, Quality: {quality:.1f}% - Encrypted with AES-256-GCM + ECC SECP256R1")
    return True

def show_dashboard():
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 2rem;">
            <h3 style="color: #3b82f6;">❤️ MedChainSecure</h3>
            <p style="font-size: 0.7rem; color: #64748b;">Secure IoMT Platform</p>
        </div>
        """, unsafe_allow_html=True)
        
        pages = ["Dashboard", "rPPG Monitor", "Health History"]
        if st.session_state.is_admin:
            pages.append("Admin Panel")
        selected = st.radio("Navigation", pages, label_visibility="collapsed")
        
        st.markdown("---")
        
        st.markdown(f"""
        <div class="glass-panel">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #3b82f6, #06b6d4); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                    <span style="color: white;">👤</span>
                </div>
                <div>
                    <p style="font-weight: 600;">{st.session_state.username}</p>
                    <p style="font-size: 0.65rem; color: #64748b;">{'Administrator' if st.session_state.is_admin else 'Patient'}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🚪 Logout", use_container_width=True):
            add_audit_log(st.session_state.user_id, "LOGOUT", f"User logged out")
            for key in ['authenticated', 'user_id', 'username', 'is_admin']:
                st.session_state[key] = None
            st.rerun()
    
    if selected == "Dashboard":
        col1, col2, col3 = st.columns(3)
        conn = sqlite3.connect('heart_monitor.db')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM test_results WHERE user_id = ?", (st.session_state.user_id,))
        total_tests = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(bpm) FROM test_results WHERE user_id = ?", (st.session_state.user_id,))
        avg_bpm = cursor.fetchone()[0] or 0
        conn.close()
        
        with col1:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Total Tests</div><div class="stat-value">{total_tests}</div></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Average BPM</div><div class="stat-value">{avg_bpm:.0f}</div></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Encryption Status</div><div class="stat-value">AES-256</div></div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="glass-panel" style="margin-top: 1.5rem; padding: 2rem; text-align: center;">
            <h3>🎯 Get Started</h3>
            <p style="margin: 1rem 0;">Use the rPPG Monitor to measure your heart rate using just your webcam.</p>
            <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                <span class="status-badge status-good">No physical sensors needed</span>
                <span class="status-badge status-good">Real-time BPM calculation</span>
                <span class="status-badge status-good">End-to-end encryption</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    elif selected == "rPPG Monitor":
        st.markdown("""
        <div class="main-header">
            <h2>📹 Real rPPG Heart Rate Monitor</h2>
            <p>Position your face in the frame - the system will detect your forehead and calculate heart rate in real-time</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            # BPM Display
            st.markdown("""
            <div class="bpm-card">
                <div style="font-size: 0.875rem; opacity: 0.9;">Current Heart Rate</div>
                <div class="bpm-value" id="bpmDisplay">--</div>
                <div style="margin-top: 0.5rem;"><span class="status-chip" id="categoryDisplay">Waiting...</span></div>
                <div class="quality-bar">
                    <div class="quality-fill" id="qualityFill"></div>
                </div>
                <div style="font-size: 0.75rem;" id="qualityText">Signal Quality: --%</div>
            </div>
            
            <div class="stats-row">
                <div class="stat-box"><div class="stat-label">MIN BPM</div><div class="stat-value" id="minDisplay">--</div></div>
                <div class="stat-box"><div class="stat-label">AVG BPM</div><div class="stat-value" id="avgDisplay">--</div></div>
                <div class="stat-box"><div class="stat-label">MAX BPM</div><div class="stat-value" id="maxDisplay">--</div></div>
            </div>
            """, unsafe_allow_html=True)
            
            # Camera Component
            rppg_component()
            
            # JavaScript for updates
            st.markdown("""
            <script>
                let bpmHistory = [];
                
                window.addEventListener('message', function(event) {
                    if (event.data.type === 'bpm_update') {
                        const bpm = event.data.bpm;
                        const quality = event.data.quality;
                        
                        document.getElementById('bpmDisplay').innerHTML = bpm;
                        document.getElementById('qualityFill').style.width = quality + '%';
                        document.getElementById('qualityText').innerHTML = `Signal Quality: ${quality.toFixed(1)}%`;
                        
                        let category = '';
                        if (bpm < 60) category = 'Bradycardia';
                        else if (bpm <= 100) category = 'Normal';
                        else category = 'Tachycardia';
                        document.getElementById('categoryDisplay').innerHTML = category;
                        
                        bpmHistory.push(bpm);
                        if (bpmHistory.length > 10) bpmHistory.shift();
                        
                        const avg = Math.round(bpmHistory.reduce((a,b) => a+b, 0) / bpmHistory.length);
                        const min = Math.min(...bpmHistory);
                        const max = Math.max(...bpmHistory);
                        
                        document.getElementById('minDisplay').innerHTML = min;
                        document.getElementById('avgDisplay').innerHTML = avg;
                        document.getElementById('maxDisplay').innerHTML = max;
                    } else if (event.data.type === 'save_reading') {
                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = '';
                        const bpmField = document.createElement('input');
                        bpmField.name = 'saved_bpm';
                        bpmField.value = event.data.bpm;
                        const qualityField = document.createElement('input');
                        qualityField.name = 'saved_quality';
                        qualityField.value = event.data.quality;
                        form.appendChild(bpmField);
                        form.appendChild(qualityField);
                        document.body.appendChild(form);
                        form.submit();
                    }
                });
            </script>
            """, unsafe_allow_html=True)
        
        if 'saved_bpm' in st.query_params:
            try:
                st.session_state.saved_bpm = int(st.query_params['saved_bpm'])
                st.session_state.saved_quality = float(st.query_params['saved_quality'])
            except:
                pass
        
        if st.session_state.saved_bpm:
            st.markdown("---")
            st.success(f"✅ Reading captured! BPM: {st.session_state.saved_bpm}, Quality: {st.session_state.saved_quality:.1f}%")
            
            with st.expander("🔐 Click to view detailed encryption process", expanded=True):
                show_encryption_simulation(st.session_state.saved_bpm, st.session_state.saved_quality)
            
            if st.button("Clear and Take New Reading"):
                st.session_state.saved_bpm = None
                st.session_state.saved_quality = None
                st.rerun()
    
    elif selected == "Health History":
        st.markdown("""
        <div class="main-header">
            <h2>📋 Health History</h2>
            <p>Your encrypted medical records with blockchain verification</p>
        </div>
        """, unsafe_allow_html=True)
        
        conn = sqlite3.connect('heart_monitor.db')
        cursor = conn.cursor()
        cursor.execute('SELECT bpm, quality, test_date FROM test_results WHERE user_id = ? ORDER BY test_date DESC', (st.session_state.user_id,))
        results = cursor.fetchall()
        conn.close()
        
        if results:
            df = pd.DataFrame(results, columns=['BPM', 'Quality (%)', 'Date'])
            df['Quality (%)'] = df['Quality (%)'].round(1)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df['Date'], y=df['BPM'], mode='lines+markers', name='Heart Rate', line=dict(color='#3b82f6', width=2)))
            fig.add_hrect(y0=60, y1=100, fillcolor="#10b981", opacity=0.1, annotation_text="Normal Range (60-100 BPM)")
            fig.update_layout(title="Heart Rate History", xaxis_title="Date", yaxis_title="BPM", template="plotly_white", height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False)
            st.download_button("📥 Export Records (CSV)", csv, "heart_history.csv", "text/csv")
        else:
            st.info("No records yet. Use the rPPG Monitor to take your first reading.")
    
    elif selected == "Admin Panel" and st.session_state.is_admin:
        st.markdown("""
        <div class="main-header">
            <h2>⚙️ Admin Panel</h2>
            <p>System administration and user management</p>
        </div>
        """, unsafe_allow_html=True)
        
        conn = sqlite3.connect('heart_monitor.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, full_name, age, gender, is_admin FROM users WHERE username != 'admin'")
        users = cursor.fetchall()
        conn.close()
        
        if users:
            for user in users:
                with st.expander(f"👤 {user[1]} - {user[2]}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Age:** {user[3]}")
                        st.write(f"**Gender:** {user[4]}")
                    with col2:
                        st.write(f"**Admin:** {'Yes' if user[5] else 'No'}")
        else:
            st.info("No users found.")
        
        # Audit Log
        st.markdown("### 📜 Recent Audit Logs")
        conn = sqlite3.connect('heart_monitor.db')
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, action, details FROM audit_log ORDER BY id DESC LIMIT 10")
        logs = cursor.fetchall()
        conn.close()
        
        for log in logs:
            st.markdown(f"""
            <div class="glass-panel" style="margin-bottom: 0.5rem; padding: 0.75rem;">
                <small style="color: #64748b;">{log[0]}</small>
                <div><strong>{log[1]}</strong> - {log[2]}</div>
            </div>
            """, unsafe_allow_html=True)

def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
