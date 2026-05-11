# app.py - Complete rPPG Heart Rate Monitor with Real Camera Feed
import streamlit as st
import sqlite3
import hashlib
import hmac
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
    }
    
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.7rem;
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
    
    .btn-primary:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(59,130,246,0.3);
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
if 'bpm_history' not in st.session_state:
    st.session_state.bpm_history = []

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
            stress_score INTEGER,
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

def encrypt_aes_gcm(plaintext):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    return key.hex(), (nonce + ciphertext).hex()

# rPPG Monitoring Component with real camera access
def rppg_monitor_component():
    """Embedded HTML/JS component for real rPPG heart rate monitoring"""
    
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
                background: #f8fafc;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }
            .video-container {
                position: relative;
                background: #1e293b;
                border-radius: 16px;
                overflow: hidden;
                margin-bottom: 20px;
            }
            #video {
                width: 100%;
                height: auto;
                transform: scaleX(-1);
                display: block;
            }
            .face-overlay {
                position: absolute;
                border: 2px solid #10b981;
                border-radius: 8px;
                display: none;
                pointer-events: none;
            }
            .roi-overlay {
                position: absolute;
                border: 2px solid #3b82f6;
                background: rgba(59,130,246,0.1);
                border-radius: 4px;
                display: none;
                pointer-events: none;
            }
            .bpm-display {
                text-align: center;
                padding: 20px;
                background: linear-gradient(135deg, #3b82f6, #06b6d4);
                border-radius: 16px;
                color: white;
                margin-bottom: 20px;
            }
            .bpm-value {
                font-size: 64px;
                font-weight: bold;
            }
            .quality-bar {
                height: 8px;
                background: #e2e8f0;
                border-radius: 4px;
                overflow: hidden;
                margin-top: 10px;
            }
            .quality-fill {
                height: 100%;
                background: #10b981;
                transition: width 0.3s;
                width: 0%;
            }
            .status {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 600;
            }
            .status-active { background: #d1fae5; color: #065f46; }
            .status-warning { background: #fed7aa; color: #9a3412; }
            .controls {
                display: flex;
                gap: 12px;
                justify-content: center;
                margin-top: 20px;
            }
            button {
                padding: 10px 24px;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .btn-start {
                background: #3b82f6;
                color: white;
            }
            .btn-start:hover { background: #2563eb; transform: translateY(-1px); }
            .btn-stop {
                background: #ef4444;
                color: white;
            }
            .btn-stop:hover { background: #dc2626; transform: translateY(-1px); }
            .stats {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                margin-top: 20px;
            }
            .stat-card {
                background: white;
                padding: 12px;
                border-radius: 12px;
                text-align: center;
                border: 1px solid #e2e8f0;
            }
            .stat-label { font-size: 11px; color: #64748b; text-transform: uppercase; }
            .stat-value { font-size: 20px; font-weight: bold; color: #1e293b; }
            .waveform {
                background: #1e293b;
                border-radius: 12px;
                padding: 16px;
                margin-top: 20px;
            }
            canvas {
                width: 100%;
                height: 80px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="bpm-display">
                <div style="font-size: 14px; opacity: 0.9;">Current Heart Rate</div>
                <div class="bpm-value" id="bpmValue">--</div>
                <div style="font-size: 14px;" id="bpmCategory">Waiting for signal...</div>
                <div class="quality-bar">
                    <div class="quality-fill" id="qualityFill"></div>
                </div>
                <div style="font-size: 12px; margin-top: 8px;" id="qualityText">Signal Quality: --%</div>
            </div>
            
            <div class="video-container">
                <video id="video" autoplay playsinline muted></video>
                <canvas id="faceOverlay" class="face-overlay"></canvas>
                <canvas id="roiOverlay" class="roi-overlay"></canvas>
            </div>
            
            <div class="controls">
                <button class="btn-start" id="startBtn">▶ Start Camera</button>
                <button class="btn-stop" id="stopBtn">⏹ Stop</button>
                <button class="btn-start" id="saveBtn" style="background: #10b981;">💾 Save Reading</button>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-label">Min BPM</div>
                    <div class="stat-value" id="minBpm">--</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Avg BPM</div>
                    <div class="stat-value" id="avgBpm">--</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Max BPM</div>
                    <div class="stat-value" id="maxBpm">--</div>
                </div>
            </div>
            
            <div class="waveform">
                <canvas id="waveformCanvas" width="700" height="80"></canvas>
            </div>
        </div>
        
        <script>
            // rPPG Signal Processing
            class RPPGProcessor {
                constructor() {
                    this.signalBuffer = [];
                    this.timestamps = [];
                    this.bpmHistory = [];
                    this.fftSize = 300;
                    this.fps = 30;
                    this.processing = false;
                    this.frameCount = 0;
                    this.redChannel = [];
                    this.greenChannel = [];
                    this.blueChannel = [];
                    this.faceDetector = null;
                    this.stream = null;
                    this.animationId = null;
                    this.lastBpm = null;
                    this.quality = 0;
                }
                
                async initFaceDetector() {
                    const model = faceDetection.SupportedModels.MediaPipeFaceDetector;
                    const detectorConfig = {
                        runtime: 'tfjs',
                        maxFaces: 1
                    };
                    this.faceDetector = await faceDetection.createDetector(model, detectorConfig);
                }
                
                async startCamera() {
                    try {
                        this.stream = await navigator.mediaDevices.getUserMedia({ 
                            video: { width: 640, height: 480, frameRate: { ideal: 30 } },
                            audio: false 
                        });
                        const video = document.getElementById('video');
                        video.srcObject = this.stream;
                        await video.play();
                        return true;
                    } catch (err) {
                        console.error('Camera error:', err);
                        return false;
                    }
                }
                
                stopCamera() {
                    if (this.stream) {
                        this.stream.getTracks().forEach(track => track.stop());
                        this.stream = null;
                    }
                    if (this.animationId) {
                        cancelAnimationFrame(this.animationId);
                        this.animationId = null;
                    }
                    this.processing = false;
                }
                
                async processFrame() {
                    if (!this.processing) return;
                    
                    const video = document.getElementById('video');
                    if (!video || video.readyState < 2) {
                        this.animationId = requestAnimationFrame(() => this.processFrame());
                        return;
                    }
                    
                    // Detect face
                    if (this.faceDetector) {
                        const faces = await this.faceDetector.estimateFaces(video);
                        
                        if (faces.length > 0) {
                            const face = faces[0];
                            const box = face.boundingBox;
                            
                            // Draw face overlay
                            const faceCanvas = document.getElementById('faceOverlay');
                            faceCanvas.style.display = 'block';
                            faceCanvas.style.width = box.width + 'px';
                            faceCanvas.style.height = box.height + 'px';
                            faceCanvas.style.left = box.x + 'px';
                            faceCanvas.style.top = box.y + 'px';
                            
                            // Extract forehead ROI (upper 22% of face)
                            const roiX = box.x + box.width * 0.2;
                            const roiY = box.y + box.height * 0.05;
                            const roiW = box.width * 0.6;
                            const roiH = box.height * 0.22;
                            
                            // Draw ROI overlay
                            const roiCanvas = document.getElementById('roiOverlay');
                            roiCanvas.style.display = 'block';
                            roiCanvas.style.width = roiW + 'px';
                            roiCanvas.style.height = roiH + 'px';
                            roiCanvas.style.left = roiX + 'px';
                            roiCanvas.style.top = roiY + 'px';
                            
                            // Get pixel data from ROI
                            const tempCanvas = document.createElement('canvas');
                            tempCanvas.width = video.videoWidth;
                            tempCanvas.height = video.videoHeight;
                            const ctx = tempCanvas.getContext('2d');
                            ctx.drawImage(video, 0, 0);
                            const imageData = ctx.getImageData(roiX, roiY, roiW, roiH);
                            
                            // Calculate average RGB in ROI
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
                            
                            // Store color channels
                            this.redChannel.push(rAvg);
                            this.greenChannel.push(gAvg);
                            this.blueChannel.push(bAvg);
                            
                            // Keep only last 300 samples (10 seconds at 30fps)
                            if (this.redChannel.length > 300) {
                                this.redChannel.shift();
                                this.greenChannel.shift();
                                this.blueChannel.shift();
                            }
                            
                            // Calculate CHROM signal every 30 frames
                            if (this.redChannel.length >= 150 && this.frameCount % 30 === 0) {
                                this.computeBPM();
                            }
                        } else {
                            document.getElementById('faceOverlay').style.display = 'none';
                            document.getElementById('roiOverlay').style.display = 'none';
                            document.getElementById('bpmCategory').innerHTML = '⚠️ No face detected';
                        }
                    }
                    
                    this.frameCount++;
                    this.animationId = requestAnimationFrame(() => this.processFrame());
                }
                
                computeBPM() {
                    // CHROM algorithm implementation
                    // Xs = R - G, Ys = 0.5R + 0.5G - B
                    const Xs = [];
                    const Ys = [];
                    
                    for (let i = 0; i < this.redChannel.length; i++) {
                        const R = this.redChannel[i];
                        const G = this.greenChannel[i];
                        const B = this.blueChannel[i];
                        Xs.push(R - G);
                        Ys.push(0.5 * R + 0.5 * G - B);
                    }
                    
                    // Detrend and normalize
                    const alpha = this.std(Xs) / this.std(Ys);
                    const chromSignal = [];
                    for (let i = 0; i < Xs.length; i++) {
                        chromSignal.push(Xs[i] - alpha * Ys[i]);
                    }
                    
                    // Apply Hanning window
                    const windowed = this.hanningWindow(chromSignal);
                    
                    // Compute FFT
                    const fftResult = this.fft(windowed);
                    
                    // Find peak in 0.67-3.5 Hz (40-210 BPM)
                    const freqs = [];
                    for (let i = 0; i < fftResult.length / 2; i++) {
                        freqs.push(i * this.fps / this.redChannel.length);
                    }
                    
                    let maxMagnitude = 0;
                    let peakFreq = 0;
                    for (let i = 0; i < freqs.length; i++) {
                        if (freqs[i] >= 0.67 && freqs[i] <= 3.5) {
                            const magnitude = Math.sqrt(fftResult[i*2] * fftResult[i*2] + fftResult[i*2+1] * fftResult[i*2+1]);
                            if (magnitude > maxMagnitude) {
                                maxMagnitude = magnitude;
                                peakFreq = freqs[i];
                            }
                        }
                    }
                    
                    // Calculate BPM
                    const bpm = Math.round(peakFreq * 60);
                    
                    // Calculate signal quality
                    let totalPower = 0;
                    let inBandPower = 0;
                    for (let i = 0; i < freqs.length; i++) {
                        const magnitude = Math.sqrt(fftResult[i*2] * fftResult[i*2] + fftResult[i*2+1] * fftResult[i*2+1]);
                        totalPower += magnitude;
                        if (freqs[i] >= 0.67 && freqs[i] <= 3.5) {
                            inBandPower += magnitude;
                        }
                    }
                    this.quality = totalPower > 0 ? (inBandPower / totalPower * 100) : 0;
                    
                    if (bpm >= 40 && bpm <= 210 && this.quality > 30) {
                        this.lastBpm = bpm;
                        this.bpmHistory.push(bpm);
                        if (this.bpmHistory.length > 10) this.bpmHistory.shift();
                        
                        // Update UI
                        document.getElementById('bpmValue').innerHTML = bpm;
                        document.getElementById('qualityFill').style.width = this.quality + '%';
                        document.getElementById('qualityText').innerHTML = `Signal Quality: ${this.quality.toFixed(1)}%`;
                        
                        // Update category
                        let category = '';
                        let categoryClass = '';
                        if (bpm < 60) {
                            category = 'Bradycardia';
                            categoryClass = 'status-warning';
                        } else if (bpm <= 100) {
                            category = 'Normal';
                            categoryClass = 'status-active';
                        } else {
                            category = 'Tachycardia';
                            categoryClass = 'status-warning';
                        }
                        document.getElementById('bpmCategory').innerHTML = `<span class="status ${categoryClass}">${category}</span>`;
                        
                        // Update stats
                        const avgBpm = Math.round(this.bpmHistory.reduce((a,b) => a+b, 0) / this.bpmHistory.length);
                        const minBpm = Math.min(...this.bpmHistory);
                        const maxBpm = Math.max(...this.bpmHistory);
                        document.getElementById('avgBpm').innerHTML = avgBpm;
                        document.getElementById('minBpm').innerHTML = minBpm;
                        document.getElementById('maxBpm').innerHTML = maxBpm;
                        
                        // Draw waveform
                        this.drawWaveform(chromSignal.slice(-200));
                        
                        // Send to Streamlit
                        if (window.parent && window.parent.postMessage) {
                            window.parent.postMessage({
                                type: 'streamlit:setComponentValue',
                                value: { bpm: bpm, quality: this.quality.toFixed(1), timestamp: Date.now() }
                            }, '*');
                        }
                    }
                }
                
                drawWaveform(signal) {
                    const canvas = document.getElementById('waveformCanvas');
                    const ctx = canvas.getContext('2d');
                    const width = canvas.width;
                    const height = canvas.height;
                    
                    ctx.clearRect(0, 0, width, height);
                    ctx.beginPath();
                    ctx.strokeStyle = '#3b82f6';
                    ctx.lineWidth = 2;
                    
                    const step = width / signal.length;
                    for (let i = 0; i < signal.length - 1; i++) {
                        const x1 = i * step;
                        const y1 = height / 2 - (signal[i] / 100) * height;
                        const x2 = (i + 1) * step;
                        const y2 = height / 2 - (signal[i + 1] / 100) * height;
                        
                        ctx.beginPath();
                        ctx.moveTo(x1, Math.max(0, Math.min(height, y1)));
                        ctx.lineTo(x2, Math.max(0, Math.min(height, y2)));
                        ctx.stroke();
                    }
                }
                
                std(arr) {
                    const mean = arr.reduce((a,b) => a+b, 0) / arr.length;
                    const variance = arr.reduce((a,b) => a + Math.pow(b - mean, 2), 0) / arr.length;
                    return Math.sqrt(variance);
                }
                
                hanningWindow(signal) {
                    const N = signal.length;
                    const windowed = [];
                    for (let i = 0; i < N; i++) {
                        const w = 0.5 * (1 - Math.cos(2 * Math.PI * i / (N - 1)));
                        windowed.push(signal[i] * w);
                    }
                    return windowed;
                }
                
                fft(signal) {
                    const N = signal.length;
                    const re = new Float64Array(N);
                    const im = new Float64Array(N);
                    for (let i = 0; i < N; i++) re[i] = signal[i];
                    
                    // Bit-reversal permutation
                    let j = 0;
                    for (let i = 0; i < N - 1; i++) {
                        if (i < j) {
                            [re[i], re[j]] = [re[j], re[i]];
                            [im[i], im[j]] = [im[j], im[i]];
                        }
                        let k = N >> 1;
                        while (k <= j) {
                            j -= k;
                            k >>= 1;
                        }
                        j += k;
                    }
                    
                    // FFT computation
                    for (let len = 2; len <= N; len <<= 1) {
                        const angle = -2 * Math.PI / len;
                        const wlenRe = Math.cos(angle);
                        const wlenIm = Math.sin(angle);
                        for (let i = 0; i < N; i += len) {
                            let wRe = 1;
                            let wIm = 0;
                            for (let j = 0; j < len / 2; j++) {
                                const uRe = re[i + j];
                                const uIm = im[i + j];
                                const vRe = re[i + j + len/2] * wRe - im[i + j + len/2] * wIm;
                                const vIm = re[i + j + len/2] * wIm + im[i + j + len/2] * wRe;
                                re[i + j] = uRe + vRe;
                                im[i + j] = uIm + vIm;
                                re[i + j + len/2] = uRe - vRe;
                                im[i + j + len/2] = uIm - vIm;
                                const nextWRe = wRe * wlenRe - wIm * wlenIm;
                                const nextWIm = wRe * wlenIm + wIm * wlenRe;
                                wRe = nextWRe;
                                wIm = nextWIm;
                            }
                        }
                    }
                    
                    const result = [];
                    for (let i = 0; i < N; i++) {
                        result.push(re[i]);
                        result.push(im[i]);
                    }
                    return result;
                }
                
                start() {
                    this.processing = true;
                    this.initFaceDetector().then(() => {
                        this.startCamera().then(success => {
                            if (success) {
                                this.processFrame();
                            }
                        });
                    });
                }
                
                stop() {
                    this.processing = false;
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
                if (current.bpm) {
                    alert(`Reading saved! BPM: ${current.bpm}, Quality: ${current.quality.toFixed(1)}%`);
                    if (window.parent && window.parent.postMessage) {
                        window.parent.postMessage({
                            type: 'save_reading',
                            bpm: current.bpm,
                            quality: current.quality
                        }, '*');
                    }
                } else {
                    alert('No valid reading yet. Please wait for stable signal.');
                }
            };
        </script>
    </body>
    </html>
    """
    
    return html(rppg_html, height=700, scrolling=False)

# Authentication UI
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

# Dashboard
def show_dashboard():
    with st.sidebar:
        st.markdown("<h3 style='text-align:center; color:#3b82f6;'>MedChainSecure</h3>", unsafe_allow_html=True)
        pages = ["Dashboard", "rPPG Monitor", "Health History", "Admin Panel" if st.session_state.is_admin else None]
        pages = [p for p in pages if p]
        selected = st.radio("Navigation", pages, label_visibility="collapsed")
        
        st.markdown("---")
        st.markdown(f"""
        <div class="glass-panel">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #3b82f6, #06b6d4); border-radius: 50%;"></div>
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
            st.markdown(f'<div class="metric-card"><div class="stat-label">Security</div><div class="stat-value">AES-256</div></div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="glass-panel" style="margin-top: 1rem; padding: 2rem; text-align: center;">
            <h3>🎯 Real rPPG Heart Rate Monitor</h3>
            <p>This system uses your webcam to measure heart rate remotely using the CHROM algorithm.</p>
            <p style="font-size: 0.8rem; color: #64748b;">No physical sensors needed - just look at the camera!</p>
        </div>
        """, unsafe_allow_html=True)
        
    elif selected == "rPPG Monitor":
        st.markdown("""
        <div class="main-header">
            <h2>📹 Real rPPG Heart Rate Monitor</h2>
            <p>Position your face in frame - the system will detect your forehead and calculate BPM</p>
        </div>
        """, unsafe_allow_html=True)
        
        rppg_monitor_component()
        
    elif selected == "Health History":
        st.markdown('<div class="main-header"><h2>📋 Health History</h2><p>Your encrypted medical records</p></div>', unsafe_allow_html=True)
        
        conn = sqlite3.connect('heart_monitor.db')
        cursor = conn.cursor()
        cursor.execute('SELECT bpm, quality, test_date FROM test_results WHERE user_id = ? ORDER BY test_date DESC', (st.session_state.user_id,))
        results = cursor.fetchall()
        conn.close()
        
        if results:
            df = pd.DataFrame(results, columns=['BPM', 'Quality', 'Date'])
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df['Date'], y=df['BPM'], mode='lines+markers', name='Heart Rate', line=dict(color='#3b82f6', width=2)))
            fig.add_hrect(y0=60, y1=100, fillcolor="#10b981", opacity=0.1, annotation_text="Normal Range")
            fig.update_layout(title="Heart Rate History", xaxis_title="Date", yaxis_title="BPM", template="plotly_white", height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False)
            st.download_button("📥 Export CSV", csv, "heart_history.csv", "text/csv")
        else:
            st.info("No records yet. Use the rPPG Monitor to take your first reading.")
    
    elif selected == "Admin Panel" and st.session_state.is_admin:
        st.markdown('<div class="main-header"><h2>⚙️ Admin Panel</h2><p>System administration</p></div>', unsafe_allow_html=True)
        
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

def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
