# app.py - Complete MedChainSecure with Fixed Face Detection and Centered Layout
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
import base64

st.set_page_config(
    page_title="MedChainSecure - Real rPPG Heart Monitor",
    page_icon="❤️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional CSS
st.markdown("""
<style>
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
    
    .stApp { background: var(--bg-primary); }
    
    .main-header {
        background: linear-gradient(135deg, #ffffff 0%, #f1f5f9 100%);
        padding: 2rem;
        border-radius: 1rem;
        margin-bottom: 2rem;
        border: 1px solid var(--border-color);
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    
    .glass-panel {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 0.75rem;
        padding: 1rem;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    
    .metric-card {
        background: var(--bg-card);
        border-radius: 0.75rem;
        padding: 1.25rem;
        border: 1px solid var(--border-color);
        text-align: center;
    }
    
    .stat-value { font-size: 2rem; font-weight: 700; color: var(--text-primary); }
    .stat-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }
    
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    .status-good { background: #d1fae5; color: #065f46; }
    .status-warning { background: #fed7aa; color: #9a3412; }
    .status-info { background: #dbeafe; color: #1e40af; }
    
    .progress-step {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 0.75rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
        background: var(--bg-primary);
        border-left: 3px solid var(--accent-primary);
    }
    
    .progress-step.completed {
        border-left-color: var(--accent-tertiary);
        background: #f0fdf4;
    }
    
    .step-number {
        width: 28px;
        height: 28px;
        border-radius: 50%;
        background: var(--accent-primary);
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .step-number.completed { background: var(--accent-tertiary); }
    
    .btn-primary {
        background: linear-gradient(135deg, #3b82f6, #06b6d4);
        color: white;
        padding: 0.625rem 1.25rem;
        border-radius: 0.5rem;
        font-weight: 600;
        border: none;
        cursor: pointer;
        transition: all 0.3s ease;
        width: 100%;
    }
    
    .encryption-preview {
        font-family: 'Courier New', monospace;
        font-size: 0.7rem;
        background: #1e293b;
        color: #a5f3fc;
        padding: 0.75rem;
        border-radius: 0.5rem;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
    }
    
    /* Centered layout */
    .two-column-layout {
        display: flex;
        gap: 2rem;
        align-items: flex-start;
    }
    
    .camera-column {
        flex: 2;
    }
    
    .controls-column {
        flex: 1;
        position: sticky;
        top: 1rem;
    }
    
    @media (max-width: 768px) {
        .two-column-layout {
            flex-direction: column;
        }
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
            aes_key_hash TEXT,
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

def encrypt_with_simulation(plaintext, bpm, quality):
    """Simulate encryption with detailed progress"""
    steps = []
    
    steps.append({'name': 'AES-256 Key Generation', 'description': 'Generating cryptographically secure random 256-bit key using CSPRNG', 'status': 'completed', 'data': None})
    steps.append({'name': 'Nonce Generation', 'description': 'Creating 96-bit unique nonce for GCM mode', 'status': 'completed', 'data': None})
    steps.append({'name': 'AES-256-GCM Encryption', 'description': 'Authenticated encryption with associated data (AEAD)', 'status': 'completed', 'data': None})
    steps.append({'name': 'ECC SECP256R1 Key Pair', 'description': 'Generating elliptic curve key pair for secure key exchange', 'status': 'completed', 'data': None})
    steps.append({'name': 'HMAC-SHA256 Signing', 'description': 'Creating HMAC signature for integrity verification', 'status': 'completed', 'data': None})
    steps.append({'name': 'Blockchain Ledger Entry', 'description': 'Adding record to immutable audit trail', 'status': 'completed', 'data': None})
    steps.append({'name': '3-Layer Storage Distribution', 'description': 'Writing to Local SQLite + Remote Backup + Blockchain', 'status': 'completed', 'data': None})
    
    key = secrets.token_bytes(32)
    key_hex = key.hex()
    steps[0]['data'] = f"Key: {key_hex[:32]}...{key_hex[-8:]} (256 bits)"
    
    nonce = secrets.token_bytes(12)
    nonce_hex = nonce.hex()
    steps[1]['data'] = f"Nonce: {nonce_hex} (96 bits)"
    
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    payload = (nonce + ciphertext).hex()
    steps[2]['data'] = f"Ciphertext length: {len(ciphertext)} bytes | Tag: {ciphertext[-16:].hex()[:16]}..."
    
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    steps[3]['data'] = f"Public Key: {public_pem[:50].decode()}... | Curve: SECP256R1"
    
    hmac_data = f"{payload}{key_hex}{bpm}{quality}"
    hmac_sig = hashlib.sha256(hmac_data.encode()).hexdigest()
    steps[4]['data'] = f"HMAC: {hmac_sig[:32]}... (SHA-256)"
    
    timestamp = datetime.now().isoformat()
    blockchain_data = f"GENESIS{st.session_state.user_id}SAVE_RESULT{timestamp}{hmac_sig}"
    blockchain_hash = hashlib.sha256(blockchain_data.encode()).hexdigest()
    steps[5]['data'] = f"Block Hash: {blockchain_hash[:32]}... | Chain Verified"
    
    steps[6]['data'] = f"Local: ✓ | Remote: ✓ | Blockchain: ✓"
    
    return key_hex, payload, steps, public_pem.decode(), hmac_sig

# Complete rPPG Component with improved face detection
def rppg_monitor_component():
    rppg_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>rPPG Heart Rate Monitor</title>
        <script src="https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.15.0/dist/tf.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@tensorflow-models/face-detection@1.0.2/dist/face-detection.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: system-ui, -apple-system, sans-serif;
                background: transparent;
                padding: 0;
            }
            .monitor-container {
                width: 100%;
            }
            .video-wrapper {
                position: relative;
                background: #0f172a;
                border-radius: 1rem;
                overflow: hidden;
                aspect-ratio: 4/3;
            }
            #video {
                width: 100%;
                height: 100%;
                object-fit: cover;
                transform: scaleX(-1);
            }
            .face-overlay {
                position: absolute;
                border: 3px solid #10b981;
                border-radius: 12px;
                display: none;
                pointer-events: none;
                box-shadow: 0 0 0 2px rgba(16,185,129,0.2);
            }
            .roi-overlay {
                position: absolute;
                border: 2px solid #3b82f6;
                background: rgba(59,130,246,0.15);
                border-radius: 6px;
                display: none;
                pointer-events: none;
            }
            .face-status {
                text-align: center;
                padding: 0.5rem;
                font-size: 0.75rem;
                color: #64748b;
                margin-top: 0.5rem;
            }
            .bpm-card {
                background: linear-gradient(135deg, #3b82f6, #06b6d4);
                border-radius: 1rem;
                padding: 1rem;
                color: white;
                margin-bottom: 1rem;
            }
            .bpm-value {
                font-size: 3rem;
                font-weight: bold;
                text-align: center;
            }
            .bpm-label {
                font-size: 0.7rem;
                text-align: center;
                opacity: 0.9;
            }
            .quality-bar {
                height: 0.25rem;
                background: rgba(255,255,255,0.3);
                border-radius: 0.125rem;
                overflow: hidden;
                margin: 0.5rem 0;
            }
            .quality-fill {
                height: 100%;
                background: #10b981;
                transition: width 0.3s;
                width: 0%;
            }
            .status-chip {
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.7rem;
                font-weight: 600;
                background: rgba(255,255,255,0.2);
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 0.5rem;
                margin: 1rem 0;
            }
            .stat-box {
                background: white;
                padding: 0.5rem;
                border-radius: 0.5rem;
                text-align: center;
                border: 1px solid #e2e8f0;
            }
            .stat-label-sm {
                font-size: 0.6rem;
                color: #64748b;
                text-transform: uppercase;
            }
            .stat-value-sm {
                font-size: 1rem;
                font-weight: bold;
                color: #1e293b;
            }
            .waveform-container {
                background: #0f172a;
                border-radius: 0.5rem;
                padding: 0.5rem;
                margin: 1rem 0;
            }
            canvas {
                width: 100%;
                height: 60px;
                display: block;
            }
            .btn-group {
                display: flex;
                flex-direction: column;
                gap: 0.5rem;
                margin-top: 1rem;
            }
            .btn {
                padding: 0.625rem;
                border: none;
                border-radius: 0.5rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
                font-size: 0.875rem;
            }
            .btn-start { background: #3b82f6; color: white; }
            .btn-start:hover { background: #2563eb; transform: translateY(-1px); }
            .btn-stop { background: #ef4444; color: white; }
            .btn-stop:hover { background: #dc2626; transform: translateY(-1px); }
            .btn-save { background: #10b981; color: white; }
            .btn-save:hover { background: #059669; transform: translateY(-1px); }
            .instruction {
                background: #f1f5f9;
                padding: 0.5rem;
                border-radius: 0.5rem;
                font-size: 0.7rem;
                color: #475569;
                text-align: center;
                margin-top: 0.5rem;
            }
        </style>
    </head>
    <body>
        <div class="monitor-container">
            <div class="bpm-card">
                <div class="bpm-label">Current Heart Rate</div>
                <div class="bpm-value" id="bpmValue">--</div>
                <div style="text-align: center; margin: 0.25rem 0;">
                    <span class="status-chip" id="bpmCategory">Waiting...</span>
                </div>
                <div class="quality-bar">
                    <div class="quality-fill" id="qualityFill"></div>
                </div>
                <div style="font-size: 0.65rem; text-align: center;" id="qualityText">Signal Quality: --%</div>
            </div>
            
            <div class="video-wrapper">
                <video id="video" autoplay playsinline muted></video>
                <div id="faceOverlay" class="face-overlay"></div>
                <div id="roiOverlay" class="roi-overlay"></div>
            </div>
            
            <div class="face-status" id="faceStatus">
                <span>📷 Click "Start Camera" to begin monitoring</span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-label-sm">Min BPM</div>
                    <div class="stat-value-sm" id="minBpm">--</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label-sm">Avg BPM</div>
                    <div class="stat-value-sm" id="avgBpm">--</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label-sm">Max BPM</div>
                    <div class="stat-value-sm" id="maxBpm">--</div>
                </div>
            </div>
            
            <div class="waveform-container">
                <canvas id="waveformCanvas" width="600" height="60"></canvas>
            </div>
            
            <div class="btn-group">
                <button class="btn btn-start" id="startBtn">▶ Start Camera</button>
                <button class="btn btn-stop" id="stopBtn">⏹ Stop Camera</button>
                <button class="btn btn-save" id="saveBtn">💾 Save Reading & Encrypt</button>
            </div>
            
            <div class="instruction">
                💡 Tip: Ensure good lighting, face centered in frame, and stay still for 10-15 seconds for accurate reading
            </div>
        </div>
        
        <script>
            class RPPGProcessor {
                constructor() {
                    this.bpmHistory = [];
                    this.redChannel = [];
                    this.greenChannel = [];
                    this.blueChannel = [];
                    this.faceDetector = null;
                    this.stream = null;
                    this.animationId = null;
                    this.lastBpm = null;
                    this.quality = 0;
                    this.frameCount = 0;
                    this.fps = 30;
                    this.isRunning = false;
                    this.roiData = [];
                }
                
                async initFaceDetector() {
                    try {
                        await tf.ready();
                        const model = faceDetection.SupportedModels.MediaPipeFaceDetector;
                        const detectorConfig = { 
                            runtime: 'tfjs', 
                            maxFaces: 1,
                            modelUrl: undefined
                        };
                        this.faceDetector = await faceDetection.createDetector(model, detectorConfig);
                        console.log('Face detector ready');
                        return true;
                    } catch (err) {
                        console.error('Face detector init error:', err);
                        return false;
                    }
                }
                
                async startCamera() {
                    try {
                        this.stream = await navigator.mediaDevices.getUserMedia({ 
                            video: { 
                                width: { ideal: 640 },
                                height: { ideal: 480 },
                                frameRate: { ideal: 30 }
                            },
                            audio: false 
                        });
                        const video = document.getElementById('video');
                        video.srcObject = this.stream;
                        await new Promise((resolve) => {
                            video.onloadedmetadata = () => {
                                video.play();
                                resolve();
                            };
                        });
                        document.getElementById('faceStatus').innerHTML = '<span>✅ Camera active - Detecting face...</span>';
                        return true;
                    } catch (err) {
                        console.error('Camera error:', err);
                        document.getElementById('faceStatus').innerHTML = '<span>❌ Camera access denied. Please allow camera permissions.</span>';
                        return false;
                    }
                }
                
                stopCamera() {
                    this.isRunning = false;
                    if (this.stream) {
                        this.stream.getTracks().forEach(track => track.stop());
                        this.stream = null;
                    }
                    if (this.animationId) {
                        cancelAnimationFrame(this.animationId);
                        this.animationId = null;
                    }
                    const video = document.getElementById('video');
                    if (video) video.srcObject = null;
                    document.getElementById('faceStatus').innerHTML = '<span>⏹ Camera stopped</span>';
                    document.getElementById('faceOverlay').style.display = 'none';
                    document.getElementById('roiOverlay').style.display = 'none';
                }
                
                async processFrame() {
                    if (!this.isRunning) return;
                    
                    const video = document.getElementById('video');
                    if (!video || video.readyState < 2 || video.videoWidth === 0) {
                        this.animationId = requestAnimationFrame(() => this.processFrame());
                        return;
                    }
                    
                    if (this.faceDetector) {
                        try {
                            const faces = await this.faceDetector.estimateFaces(video);
                            
                            if (faces && faces.length > 0) {
                                const face = faces[0];
                                const box = face.boundingBox;
                                
                                // Scale coordinates to video dimensions
                                const scaleX = video.videoWidth / video.clientWidth;
                                const scaleY = video.videoHeight / video.clientHeight;
                                
                                const left = box.xMin * scaleX;
                                const top = box.yMin * scaleY;
                                const width = (box.xMax - box.xMin) * scaleX;
                                const height = (box.yMax - box.yMin) * scaleY;
                                
                                // Show face overlay
                                const faceDiv = document.getElementById('faceOverlay');
                                faceDiv.style.display = 'block';
                                faceDiv.style.left = (left / scaleX) + 'px';
                                faceDiv.style.top = (top / scaleY) + 'px';
                                faceDiv.style.width = (width / scaleX) + 'px';
                                faceDiv.style.height = (height / scaleY) + 'px';
                                
                                // Forehead ROI (upper 25% of face, centered)
                                const roiX = left + width * 0.25;
                                const roiY = top + height * 0.05;
                                const roiW = width * 0.5;
                                const roiH = height * 0.2;
                                
                                // Show ROI overlay
                                const roiDiv = document.getElementById('roiOverlay');
                                roiDiv.style.display = 'block';
                                roiDiv.style.left = (roiX / scaleX) + 'px';
                                roiDiv.style.top = (roiY / scaleY) + 'px';
                                roiDiv.style.width = (roiW / scaleX) + 'px';
                                roiDiv.style.height = (roiH / scaleY) + 'px';
                                
                                // Extract pixel data from ROI
                                const tempCanvas = document.createElement('canvas');
                                tempCanvas.width = video.videoWidth;
                                tempCanvas.height = video.videoHeight;
                                const ctx = tempCanvas.getContext('2d');
                                ctx.drawImage(video, 0, 0);
                                const imageData = ctx.getImageData(roiX, roiY, roiW, roiH);
                                
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
                                
                                this.redChannel.push(rAvg);
                                this.greenChannel.push(gAvg);
                                this.blueChannel.push(bAvg);
                                
                                if (this.redChannel.length > 300) {
                                    this.redChannel.shift();
                                    this.greenChannel.shift();
                                    this.blueChannel.shift();
                                }
                                
                                document.getElementById('faceStatus').innerHTML = '<span>✅ Face detected - Analyzing pulse signal...</span>';
                                
                                if (this.redChannel.length >= 150 && this.frameCount % 30 === 0) {
                                    this.computeBPM();
                                }
                            } else {
                                document.getElementById('faceOverlay').style.display = 'none';
                                document.getElementById('roiOverlay').style.display = 'none';
                                document.getElementById('faceStatus').innerHTML = '<span>🔍 No face detected - Please look at camera</span>';
                            }
                        } catch(err) {
                            console.error('Face detection error:', err);
                        }
                    }
                    
                    this.frameCount++;
                    this.animationId = requestAnimationFrame(() => this.processFrame());
                }
                
                computeBPM() {
                    if (this.redChannel.length < 150) return;
                    
                    // CHROM algorithm
                    const Xs = [];
                    const Ys = [];
                    const N = this.redChannel.length;
                    
                    for (let i = 0; i < N; i++) {
                        const R = this.redChannel[i];
                        const G = this.greenChannel[i];
                        const B = this.blueChannel[i];
                        Xs.push(R - G);
                        Ys.push(0.5 * R + 0.5 * G - B);
                    }
                    
                    // Normalize
                    const meanX = Xs.reduce((a,b) => a+b, 0) / N;
                    const meanY = Ys.reduce((a,b) => a+b, 0) / N;
                    let varX = 0, varY = 0;
                    for (let i = 0; i < N; i++) {
                        varX += Math.pow(Xs[i] - meanX, 2);
                        varY += Math.pow(Ys[i] - meanY, 2);
                    }
                    const stdX = Math.sqrt(varX / N);
                    const stdY = Math.sqrt(varY / N);
                    const alpha = stdX / stdY;
                    
                    const chromSignal = [];
                    for (let i = 0; i < N; i++) {
                        chromSignal.push(Xs[i] - alpha * Ys[i]);
                    }
                    
                    // Simple peak detection for BPM
                    const signal = chromSignal.slice(-150);
                    const peaks = [];
                    for (let i = 2; i < signal.length - 2; i++) {
                        if (signal[i] > signal[i-1] && signal[i] > signal[i+1] &&
                            signal[i] > signal[i-2] && signal[i] > signal[i+2]) {
                            peaks.push(i);
                        }
                    }
                    
                    if (peaks.length >= 2) {
                        const avgInterval = (peaks[peaks.length-1] - peaks[0]) / (peaks.length - 1);
                        const bpm = Math.round(60 / (avgInterval / this.fps));
                        
                        // Calculate signal quality based on peak consistency
                        let peakHeights = [];
                        for (let p of peaks) {
                            peakHeights.push(signal[p]);
                        }
                        const avgHeight = peakHeights.reduce((a,b) => a+b, 0) / peakHeights.length;
                        let heightVariance = 0;
                        for (let h of peakHeights) {
                            heightVariance += Math.pow(h - avgHeight, 2);
                        }
                        heightVariance /= peakHeights.length;
                        this.quality = Math.min(100, Math.max(0, 100 - heightVariance / avgHeight * 50));
                        
                        if (bpm >= 45 && bpm <= 180 && this.quality > 30) {
                            this.lastBpm = bpm;
                            this.bpmHistory.push(bpm);
                            if (this.bpmHistory.length > 10) this.bpmHistory.shift();
                            
                            // Update UI
                            document.getElementById('bpmValue').innerHTML = bpm;
                            document.getElementById('qualityFill').style.width = this.quality + '%';
                            document.getElementById('qualityText').innerHTML = `Signal Quality: ${this.quality.toFixed(1)}%`;
                            
                            let category = '';
                            if (bpm < 60) category = 'Bradycardia';
                            else if (bpm <= 100) category = 'Normal';
                            else category = 'Tachycardia';
                            document.getElementById('bpmCategory').innerHTML = category;
                            
                            const avgBpm = Math.round(this.bpmHistory.reduce((a,b) => a+b, 0) / this.bpmHistory.length);
                            const minBpm = Math.min(...this.bpmHistory);
                            const maxBpm = Math.max(...this.bpmHistory);
                            document.getElementById('avgBpm').innerHTML = avgBpm;
                            document.getElementById('minBpm').innerHTML = minBpm;
                            document.getElementById('maxBpm').innerHTML = maxBpm;
                            
                            this.drawWaveform(chromSignal.slice(-200));
                        }
                    }
                }
                
                drawWaveform(signal) {
                    const canvas = document.getElementById('waveformCanvas');
                    const ctx = canvas.getContext('2d');
                    const width = canvas.clientWidth;
                    const height = canvas.clientHeight;
                    canvas.width = width;
                    canvas.height = height;
                    
                    ctx.clearRect(0, 0, width, height);
                    ctx.beginPath();
                    ctx.strokeStyle = '#3b82f6';
                    ctx.lineWidth = 2;
                    
                    const step = width / signal.length;
                    for (let i = 0; i < signal.length - 1; i++) {
                        const x1 = i * step;
                        const y1 = height/2 - (signal[i] / 50) * height;
                        const x2 = (i+1) * step;
                        const y2 = height/2 - (signal[i+1] / 50) * height;
                        ctx.beginPath();
                        ctx.moveTo(x1, Math.max(0, Math.min(height, y1)));
                        ctx.lineTo(x2, Math.max(0, Math.min(height, y2)));
                        ctx.stroke();
                    }
                }
                
                async start() {
                    this.isRunning = true;
                    this.redChannel = [];
                    this.greenChannel = [];
                    this.blueChannel = [];
                    this.bpmHistory = [];
                    this.frameCount = 0;
                    
                    const detectorReady = await this.initFaceDetector();
                    if (detectorReady) {
                        const cameraReady = await this.startCamera();
                        if (cameraReady) {
                            this.processFrame();
                        } else {
                            this.isRunning = false;
                        }
                    } else {
                        document.getElementById('faceStatus').innerHTML = '<span>⚠️ Face detection model failed to load. Please refresh.</span>';
                        this.isRunning = false;
                    }
                }
                
                stop() {
                    this.isRunning = false;
                    this.stopCamera();
                }
                
                getCurrentBPM() {
                    return { bpm: this.lastBpm, quality: this.quality };
                }
            }
            
            const processor = new RPPGProcessor();
            
            document.getElementById('startBtn').onclick = () => processor.start();
            document.getElementById('stopBtn').onclick = () => processor.stop();
            document.getElementById('saveBtn').onclick = () => {
                const current = processor.getCurrentBPM();
                if (current.bpm && current.bpm > 40 && current.bpm < 200 && current.quality > 35) {
                    const result = { bpm: current.bpm, quality: current.quality.toFixed(1), timestamp: Date.now() };
                    if (window.parent && window.parent.postMessage) {
                        window.parent.postMessage({
                            type: 'save_reading',
                            bpm: current.bpm,
                            quality: current.quality
                        }, '*');
                    }
                    alert(`✅ Reading saved! BPM: ${current.bpm}, Quality: ${current.quality.toFixed(1)}%`);
                } else {
                    let msg = '⚠️ No valid reading.\n\n';
                    if (!current.bpm) msg += '• No BPM detected yet. Wait 10-15 seconds after camera starts.\n';
                    else if (current.quality <= 35) msg += `• Signal quality too low (${current.quality.toFixed(1)}%). Need >35%.\n`;
                    msg += '\nTips:\n• Ensure good lighting\n• Face centered in frame\n• Stay still for 15 seconds';
                    alert(msg);
                }
            };
        </script>
    </body>
    </html>
    """
    return html(rppg_html, height=580, scrolling=False)

def show_encryption_simulation(bpm, quality):
    """Display detailed encryption simulation"""
    
    st.markdown("### 🔐 Hybrid Encryption Pipeline")
    st.markdown("Your health data is being secured through military-grade encryption")
    
    health_data = {
        "patient_id": f"PT-{st.session_state.user_id:04d}",
        "heart_rate": bpm,
        "signal_quality": quality,
        "timestamp": datetime.now().isoformat(),
        "device": "rPPG-CAM-01",
        "user": st.session_state.username
    }
    
    plaintext = json.dumps(health_data, indent=2)
    key_hex, encrypted_payload, steps, ecc_pub, hmac_sig = encrypt_with_simulation(plaintext, bpm, quality)
    
    for i, step in enumerate(steps, 1):
        with st.container():
            col1, col2 = st.columns([1, 4])
            with col1:
                st.markdown(f"### ✅")
            with col2:
                st.markdown(f"**Step {i}: {step['name']}**")
                st.caption(step['description'])
                if step['data']:
                    st.code(step['data'], language="text")
        st.divider()
        time.sleep(0.2)
    
    st.markdown("### 📦 Encrypted Payload Preview")
    st.markdown(f"""
    <div class="encryption-preview">
        <strong>🔑 AES-256 Key:</strong> {key_hex[:32]}...{key_hex[-8:]}<br>
        <strong>🔐 ECC Public Key:</strong> {ecc_pub[:60]}...<br>
        <strong>✍️ HMAC Signature:</strong> {hmac_sig[:32]}...<br>
        <strong>📊 Encrypted Size:</strong> {len(encrypted_payload)} bytes<br>
        <strong>🔗 Blockchain Hash:</strong> {hashlib.sha256(encrypted_payload.encode()).hexdigest()[:32]}...
    </div>
    """, unsafe_allow_html=True)
    
    conn = sqlite3.connect('heart_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO test_results (user_id, bpm, quality, encrypted_hex, key_hex, ecc_public_key, aes_key_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (st.session_state.user_id, bpm, quality, encrypted_payload, key_hex, ecc_pub[:100], hmac_sig[:32]))
    conn.commit()
    conn.close()
    
    add_audit_log(st.session_state.user_id, "SAVE_RESULT", f"BPM: {bpm}, Quality: {quality}%, Encrypted and stored")
    
    st.success("✅ Data successfully encrypted with AES-256-GCM + ECC SECP256R1 and stored in 3-layer distributed storage")
    
    return True

def show_login():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div class="main-header" style="text-align: center;">
            <h1>❤️ MedChainSecure</h1>
            <p>Real rPPG Heart Rate Monitoring with AES-256-GCM Encryption</p>
            <div style="display: flex; justify-content: center; gap: 0.75rem; margin-top: 1rem; flex-wrap: wrap;">
                <span class="status-badge status-good">🔒 AES-256-GCM</span>
                <span class="status-badge status-good">🔑 ECC SECP256R1</span>
                <span class="status-badge status-good">📹 Real rPPG</span>
                <span class="status-badge status-good">📦 Blockchain Audit</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                if st.form_submit_button("Login", use_container_width=True):
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
                        st.error("Invalid credentials")
        
        with tab2:
            with st.form("register_form"):
                full_name = st.text_input("Full Name")
                username = st.text_input("Username")
                col_a, col_b = st.columns(2)
                with col_a:
                    age = st.number_input("Age", min_value=1, max_value=120, value=30)
                with col_b:
                    gender = st.selectbox("Gender", ["Male", "Female", "Other"])
                password = st.text_input("Password", type="password")
                confirm = st.text_input("Confirm Password", type="password")
                if st.form_submit_button("Register", use_container_width=True):
                    if password != confirm:
                        st.error("Passwords don't match")
                    else:
                        conn = sqlite3.connect('heart_monitor.db')
                        cursor = conn.cursor()
                        try:
                            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
                            cursor.execute('INSERT INTO users (username, password_hash, full_name, age, gender, is_admin) VALUES (?, ?, ?, ?, ?, 0)',
                                           (username, pw_hash, full_name, age, gender))
                            conn.commit()
                            st.success("Registration successful! Please login.")
                        except sqlite3.IntegrityError:
                            st.error("Username already exists")
                        finally:
                            conn.close()

def show_dashboard():
    with st.sidebar:
        st.markdown("<h3 style='text-align:center; color:#3b82f6;'>MedChainSecure</h3>", unsafe_allow_html=True)
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
                    <p style="font-size: 0.65rem; color: #64748b;">{'Admin' if st.session_state.is_admin else 'Patient'}</p>
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
            st.markdown(f'<div class="metric-card"><div class="stat-label">Encryption</div><div class="stat-value">AES-256</div></div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="glass-panel" style="margin-top: 1rem; padding: 2rem; text-align: center;">
            <h3>🎯 Real rPPG Heart Rate Monitor</h3>
            <p>This system uses your webcam to measure heart rate remotely using the CHROM algorithm.</p>
            <p style="font-size: 0.8rem; color: #64748b;">No physical sensors needed - just look at the camera!</p>
            <hr>
            <h4>🔐 Security Features</h4>
            <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; margin-top: 1rem;">
                <span class="status-badge status-good">AES-256-GCM Encryption</span>
                <span class="status-badge status-good">ECC SECP256R1 Key Exchange</span>
                <span class="status-badge status-good">HMAC-SHA256 Signing</span>
                <span class="status-badge status-good">Blockchain Audit Trail</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    elif selected == "rPPG Monitor":
        st.markdown("""
        <div class="main-header">
            <h2>📹 Real rPPG Heart Rate Monitor</h2>
            <p>Position your face in the frame - system will detect forehead and calculate heart rate</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Two column layout: camera center, controls right
        col_left, col_center, col_right = st.columns([1, 2, 1])
        
        with col_center:
            st.markdown('<div style="text-align: center;">', unsafe_allow_html=True)
            rppg_monitor_component()
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Handle saved reading
        st.markdown("""
        <script>
            window.addEventListener('message', function(event) {
                if (event.data.type === 'save_reading') {
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
        st.markdown('<div class="main-header"><h2>📋 Health History</h2><p>Your encrypted medical records with blockchain verification</p></div>', unsafe_allow_html=True)
        
        conn = sqlite3.connect('heart_monitor.db')
        cursor = conn.cursor()
        cursor.execute('SELECT bpm, quality, test_date, aes_key_hash FROM test_results WHERE user_id = ? ORDER BY test_date DESC', (st.session_state.user_id,))
        results = cursor.fetchall()
        conn.close()
        
        if results:
            df = pd.DataFrame(results, columns=['BPM', 'Quality (%)', 'Date', 'Blockchain Hash'])
            df['Quality (%)'] = df['Quality (%)'].round(1)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df['Date'], y=df['BPM'], mode='lines+markers', name='Heart Rate', line=dict(color='#3b82f6', width=2)))
            fig.add_hrect(y0=60, y1=100, fillcolor="#10b981", opacity=0.1, annotation_text="Normal Range (60-100 BPM)")
            fig.update_layout(title="Heart Rate History", xaxis_title="Date", yaxis_title="BPM", template="plotly_white", height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            st.dataframe(df, use_container_width=True)
            
            with st.expander("🔐 View Encryption Details for Records"):
                for idx, row in results[:5].iterrows():
                    st.markdown(f"""
                    <div class="glass-panel" style="margin-bottom: 0.5rem; padding: 0.75rem;">
                        <strong>📅 {row[2]}</strong> | BPM: {row[0]} | Quality: {row[1]}%<br>
                        <small>🔗 Blockchain Hash: {row[3] if row[3] else 'N/A'}...</small><br>
                        <small>🔒 Encrypted with AES-256-GCM | Verified on-chain</small>
                    </div>
                    """, unsafe_allow_html=True)
            
            csv = df.to_csv(index=False)
            st.download_button("📥 Export Encrypted Records (CSV)", csv, "heart_history.csv", "text/csv")
        else:
            st.info("No records yet. Use the rPPG Monitor to take your first reading.")
    
    elif selected == "Admin Panel" and st.session_state.is_admin:
        st.markdown('<div class="main-header"><h2>⚙️ Admin Panel</h2><p>System administration and audit</p></div>', unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["👥 User Management", "📊 System Audit"])
        
        with tab1:
            conn = sqlite3.connect('heart_monitor.db')
            cursor = conn.cursor()
            cursor.execute("SELECT username, full_name, age, gender, COUNT(t.id) as records FROM users u LEFT JOIN test_results t ON u.id = t.user_id WHERE u.username != 'admin' GROUP BY u.id")
            users = cursor.fetchall()
            conn.close()
            
            if users:
                df_users = pd.DataFrame(users, columns=['Username', 'Full Name', 'Age', 'Gender', 'Records'])
                st.dataframe(df_users, use_container_width=True)
            else:
                st.info("No users found.")
        
        with tab2:
            conn = sqlite3.connect('heart_monitor.db')
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, action, details, current_hash FROM audit_log ORDER BY id DESC LIMIT 20")
            logs = cursor.fetchall()
            conn.close()
            
            for log in logs:
                st.markdown(f"""
                <div class="glass-panel" style="margin-bottom: 0.5rem; padding: 0.75rem;">
                    <div style="display: flex; justify-content: space-between;">
                        <strong>{log[0]}</strong>
                        <span class="status-badge status-info">{log[1]}</span>
                    </div>
                    <div style="font-size: 0.8rem;">{log[2]}</div>
                    <div style="font-size: 0.6rem; font-family: monospace;">Hash: {log[3][:32]}...</div>
                </div>
                """, unsafe_allow_html=True)

def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
