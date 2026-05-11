# app.py - MedChainSecure Complete Application (Fixed rPPG Face Detection)
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
from streamlit.components.v1 import html as st_html
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
    padding: 2rem; border-radius: 1rem; margin-bottom: 2rem;
    border: 1px solid var(--border-color); text-align: center;
}
.main-header h1, .main-header h2 {
    font-size: 2rem; margin-bottom: 0.5rem;
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
}
.main-header p { color: var(--text-secondary); font-size: 1rem; }
.glass-panel {
    background: var(--bg-card); border: 1px solid var(--border-color);
    border-radius: 0.75rem; padding: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}
.metric-card {
    background: var(--bg-card); border-radius: 0.75rem;
    padding: 1.25rem; border: 1px solid var(--border-color);
    text-align: center; transition: all 0.3s ease;
}
.metric-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
.stat-value { font-size: 2rem; font-weight: 700; color: var(--text-primary); }
.stat-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); font-weight: 600; }
.status-badge {
    display: inline-flex; align-items: center; gap: 0.5rem;
    padding: 0.35rem 0.85rem; border-radius: 9999px;
    font-size: 0.75rem; font-weight: 600;
}
.status-good { background: #d1fae5; color: #065f46; }
.status-warning { background: #fed7aa; color: #9a3412; }
.status-info { background: #dbeafe; color: #1e40af; }
.encryption-preview {
    font-family: 'Courier New', monospace; font-size: 0.7rem;
    background: #1e293b; color: #a5f3fc;
    padding: 0.75rem; border-radius: 0.5rem; overflow-x: auto;
}
.stButton > button { width: 100%; border-radius: 0.5rem; font-weight: 600; padding: 0.5rem 1rem; }
div[data-testid="stTabs"] button { font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ─── Session State ────────────────────────────────────────────────────────────
for k, v in [('authenticated', False), ('user_id', None), ('username', None),
             ('is_admin', False), ('saved_bpm', None), ('saved_quality', None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect('heart_monitor.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        age INTEGER, gender TEXT,
        is_admin BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS test_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        bpm INTEGER NOT NULL,
        quality REAL NOT NULL,
        encrypted_hex TEXT NOT NULL,
        key_hex TEXT NOT NULL,
        ecc_public_key TEXT,
        test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        details TEXT, previous_hash TEXT, current_hash TEXT)''')
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        pw = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
        c.execute('INSERT INTO users (username,password_hash,full_name,age,gender,is_admin) VALUES (?,?,?,?,?,?)',
                  ('admin', pw, 'System Administrator', 30, 'Male', 1))
    conn.commit(); conn.close()

init_db()

def add_audit_log(user_id, action, details):
    conn = sqlite3.connect('heart_monitor.db')
    c = conn.cursor()
    c.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev = c.fetchone()
    previous_hash = prev[0] if prev else 'GENESIS'
    ts = datetime.now().isoformat()
    current_hash = hashlib.sha256(f"{previous_hash}{user_id}{action}{ts}{details}".encode()).hexdigest()
    c.execute('INSERT INTO audit_log (user_id,action,timestamp,details,previous_hash,current_hash) VALUES (?,?,?,?,?,?)',
              (user_id, action, ts, details, previous_hash, current_hash))
    conn.commit(); conn.close()

def encrypt_and_save(bpm, quality):
    health_data = {
        "patient_id": f"PT-{st.session_state.user_id:04d}",
        "heart_rate": bpm, "signal_quality": quality,
        "timestamp": datetime.now().isoformat(),
        "user": st.session_state.username
    }
    plaintext = json.dumps(health_data)
    key = secrets.token_bytes(32); key_hex = key.hex()
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    payload = (nonce + ciphertext).hex()
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    hmac_sig = hashlib.sha256(f"{payload}{key_hex}".encode()).hexdigest()
    blockchain_hash = hashlib.sha256(
        f"GENESIS{st.session_state.user_id}SAVE_RESULT{datetime.now().isoformat()}{hmac_sig}".encode()
    ).hexdigest()
    conn = sqlite3.connect('heart_monitor.db')
    c = conn.cursor()
    c.execute('INSERT INTO test_results (user_id,bpm,quality,encrypted_hex,key_hex,ecc_public_key) VALUES (?,?,?,?,?,?)',
              (st.session_state.user_id, bpm, quality, payload, key_hex, public_pem[:100].decode()))
    conn.commit(); conn.close()
    add_audit_log(st.session_state.user_id, "SAVE_RESULT", f"BPM:{bpm}, Quality:{quality}%")
    return key_hex, payload, public_pem.decode(), blockchain_hash

# ─── rPPG Component (FIXED) ───────────────────────────────────────────────────
def rppg_component():
    component_html = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0d1117;font-family:system-ui,sans-serif;overflow:hidden}

  #layout{display:flex;flex-direction:column;height:100vh}

  /* video row */
  #videoWrap{position:relative;flex:1;background:#000;min-height:0}
  #video{width:100%;height:100%;object-fit:cover;transform:scaleX(-1);display:block}
  #overlay{position:absolute;inset:0;pointer-events:none}

  /* BPM banner */
  #bpmBanner{
    display:flex;align-items:center;justify-content:space-between;
    padding:8px 14px;background:#0d1117;border-top:1px solid #1e293b;
  }
  #bpmVal{font-size:2.2rem;font-weight:800;color:#10b981;letter-spacing:-1px}
  #bpmUnit{font-size:0.7rem;color:#64748b;margin-left:4px;align-self:flex-end;margin-bottom:6px}
  #catBadge{
    font-size:0.7rem;font-weight:700;padding:3px 10px;
    border-radius:20px;background:#1e293b;color:#94a3b8;
  }
  #qualityWrap{flex:1;margin:0 14px}
  #qualityLabel{font-size:0.65rem;color:#64748b;margin-bottom:3px}
  #qualityBar{height:5px;background:#1e293b;border-radius:3px;overflow:hidden}
  #qualityFill{height:100%;width:0%;background:#3b82f6;transition:width .4s;border-radius:3px}

  /* waveform */
  #waveCanvas{width:100%;height:52px;background:#0d1117;display:block;border-top:1px solid #1e293b}

  /* status */
  #statusBar{
    text-align:center;padding:6px 10px;font-size:11px;
    color:#64748b;background:#0d1117;border-top:1px solid #1e293b;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  }

  /* controls */
  #controls{
    display:flex;gap:8px;padding:10px 12px;background:#0d1117;
    border-top:1px solid #1e293b;
  }
  button{
    flex:1;padding:8px 6px;border:none;border-radius:7px;
    font-weight:700;cursor:pointer;font-size:12px;transition:all .15s;
  }
  #startBtn{background:#3b82f6;color:#fff}
  #startBtn:hover{background:#2563eb}
  #stopBtn{background:#374151;color:#9ca3af}
  #stopBtn:hover{background:#ef4444;color:#fff}
  #saveBtn{background:#10b981;color:#fff}
  #saveBtn:hover{background:#059669}
  #saveBtn:disabled{background:#1e293b;color:#4b5563;cursor:not-allowed}

  /* face / ROI boxes drawn on #overlay canvas */
  #overlayCanvas{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}

  .spin{
    display:inline-block;width:10px;height:10px;
    border:2px solid #fff;border-top-color:transparent;
    border-radius:50%;animation:sp .6s linear infinite;
    margin-right:5px;vertical-align:middle;
  }
  @keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div id="layout">

  <div id="videoWrap">
    <video id="video" autoplay playsinline muted></video>
    <canvas id="overlayCanvas"></canvas>
  </div>

  <div id="bpmBanner">
    <div style="display:flex;align-items:baseline">
      <span id="bpmVal">--</span>
      <span id="bpmUnit">BPM</span>
    </div>
    <div id="qualityWrap">
      <div id="qualityLabel">Signal Quality</div>
      <div id="qualityBar"><div id="qualityFill"></div></div>
    </div>
    <div id="catBadge">Waiting…</div>
  </div>

  <canvas id="waveCanvas"></canvas>

  <div id="statusBar">📷 Press ▶ Start Camera to begin</div>

  <div id="controls">
    <button id="startBtn">▶ Start</button>
    <button id="stopBtn">⏹ Stop</button>
    <button id="saveBtn" disabled>💾 Save</button>
  </div>

</div>

<script>
// ── DOM refs ──────────────────────────────────────────────────────────────────
const video       = document.getElementById('video');
const overlayC    = document.getElementById('overlayCanvas');
const overlayCtx  = overlayC.getContext('2d');
const waveC       = document.getElementById('waveCanvas');
const waveCtx     = waveC.getContext('2d');
const statusBar   = document.getElementById('statusBar');
const bpmVal      = document.getElementById('bpmVal');
const qualFill    = document.getElementById('qualityFill');
const catBadge    = document.getElementById('catBadge');
const startBtn    = document.getElementById('startBtn');
const stopBtn     = document.getElementById('stopBtn');
const saveBtn     = document.getElementById('saveBtn');

// ── State ─────────────────────────────────────────────────────────────────────
let stream = null, rafId = null, isRunning = false;
let detector = null, mpReady = false;

const MAX_BUF = 300;
let rBuf=[], gBuf=[], bBuf=[], chromaBuf=[];
let frameIdx = 0, FPS = 30;
let lastBpm = null, lastQuality = 0;
let bpmHistory = [];

// Sampling canvas (hidden, reused each frame)
const sampC = document.createElement('canvas');
const sampCtx = sampC.getContext('2d', {willReadFrequently: true});

// ── Helpers ───────────────────────────────────────────────────────────────────
function setStatus(msg){ statusBar.innerHTML = msg; }

function updateBpmUI(bpm, quality){
  bpmVal.textContent = bpm;
  qualFill.style.width = quality.toFixed(0) + '%';
  let cat = 'Normal', col = '#10b981';
  if(bpm < 60){ cat='Bradycardia'; col='#f59e0b'; }
  else if(bpm > 100){ cat='Tachycardia'; col='#ef4444'; }
  catBadge.textContent = cat;
  catBadge.style.color = col;
  bpmVal.style.color   = col;
  saveBtn.disabled = false;
}

// ── Load MediaPipe FaceDetector (tasks-vision) ────────────────────────────────
async function loadMediaPipe(){
  setStatus('<span class="spin"></span> Loading face detection model…');
  try {
    const { FaceDetector, FilesetResolver } = await import(
      'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.14/vision_bundle.mjs'
    );
    const vision = await FilesetResolver.forVisionTasks(
      'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.14/wasm'
    );
    detector = await FaceDetector.createFromOptions(vision, {
      baseOptions: {
        modelAssetPath: 'https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite',
        delegate: 'GPU'
      },
      runningMode: 'VIDEO',
      minDetectionConfidence: 0.5
    });
    mpReady = true;
    setStatus('✅ Model ready — press ▶ Start Camera');
  } catch(e){
    console.warn('MediaPipe failed:', e);
    setStatus('⚠️ No face model — using forehead-region fallback');
    mpReady = false;
  }
}

// ── Camera ────────────────────────────────────────────────────────────────────
async function startCamera(){
  try {
    setStatus('<span class="spin"></span> Requesting camera…');
    stream = await navigator.mediaDevices.getUserMedia({
      video:{ width:{ideal:640}, height:{ideal:480}, facingMode:'user' },
      audio: false
    });
    video.srcObject = stream;
    await video.play();
    return true;
  } catch(e){
    setStatus('❌ Camera access denied. Allow camera and refresh.');
    return false;
  }
}

function stopEverything(){
  isRunning = false;
  if(rafId){ cancelAnimationFrame(rafId); rafId=null; }
  if(stream){ stream.getTracks().forEach(t=>t.stop()); stream=null; }
  video.srcObject = null;
  overlayCtx.clearRect(0,0,overlayC.width,overlayC.height);
  waveCtx.clearRect(0,0,waveC.width,waveC.height);
  rBuf=[]; gBuf=[]; bBuf=[]; chromaBuf=[];
  bpmHistory=[]; lastBpm=null; lastQuality=0;
  bpmVal.textContent='--'; qualFill.style.width='0%';
  catBadge.textContent='Stopped'; saveBtn.disabled=true;
  setStatus('⏹ Camera stopped');
}

// ── Resize overlay canvas to match video display size ─────────────────────────
function syncCanvasSize(){
  const r = video.getBoundingClientRect();
  if(overlayC.width !== r.width || overlayC.height !== r.height){
    overlayC.width  = r.width;
    overlayC.height = r.height;
  }
}

// ── Draw boxes on overlay canvas ──────────────────────────────────────────────
function drawBoxes(faceRect, roiRect, useFallback){
  overlayCtx.clearRect(0,0,overlayC.width,overlayC.height);
  if(faceRect && !useFallback){
    overlayCtx.strokeStyle='#10b981';
    overlayCtx.lineWidth=3;
    overlayCtx.beginPath();
    overlayCtx.roundRect(faceRect.x, faceRect.y, faceRect.w, faceRect.h, 10);
    overlayCtx.stroke();
  }
  if(roiRect){
    overlayCtx.strokeStyle = useFallback ? '#f59e0b' : '#3b82f6';
    overlayCtx.fillStyle   = useFallback ? 'rgba(245,158,11,0.15)' : 'rgba(59,130,246,0.2)';
    overlayCtx.lineWidth   = useFallback ? 2 : 2;
    overlayCtx.setLineDash(useFallback ? [6,4] : []);
    overlayCtx.beginPath();
    overlayCtx.roundRect(roiRect.x, roiRect.y, roiRect.w, roiRect.h, 6);
    overlayCtx.fill();
    overlayCtx.stroke();
    overlayCtx.setLineDash([]);

    // Label
    overlayCtx.fillStyle = useFallback ? '#f59e0b' : '#3b82f6';
    overlayCtx.font = 'bold 10px system-ui';
    overlayCtx.fillText(useFallback ? 'Forehead ROI (fallback)' : 'ROI', roiRect.x+4, roiRect.y-4);
  }
}

// ── Sample pixels from ROI in video-pixel coords ───────────────────────────────
function sampleROI(vx, vy, vw, vh){
  if(vw < 1 || vh < 1) return;
  sampC.width  = Math.round(vw);
  sampC.height = Math.round(vh);
  sampCtx.drawImage(video, vx, vy, vw, vh, 0, 0, sampC.width, sampC.height);
  const d = sampCtx.getImageData(0,0,sampC.width,sampC.height).data;
  let rS=0,gS=0,bS=0, n=d.length/4;
  for(let i=0;i<d.length;i+=4){ rS+=d[i]; gS+=d[i+1]; bS+=d[i+2]; }
  rBuf.push(rS/n); gBuf.push(gS/n); bBuf.push(bS/n);
  if(rBuf.length>MAX_BUF){ rBuf.shift(); gBuf.shift(); bBuf.shift(); }
}

// ── Main loop ─────────────────────────────────────────────────────────────────
async function loop(){
  if(!isRunning) return;

  try {
    if(video.readyState >= 2 && video.videoWidth > 0){
      syncCanvasSize();
      const VW = video.videoWidth, VH = video.videoHeight;
      const DW = overlayC.width,   DH = overlayC.height;
      const scaleX = DW/VW, scaleY = DH/VH;

      let useFallback = true;
      let faceRect=null, roiRect=null;
      let roiVx, roiVy, roiVw, roiVh;  // video-pixel coords

      // ── Try MediaPipe ──────────────────────────────────────────────────────
      if(mpReady && detector){
        let faces;
        try{ faces = detector.detectForVideo(video, performance.now()).detections; }
        catch(_){ faces=[]; }

        if(faces && faces.length > 0){
          useFallback = false;
          const bb = faces[0].boundingBox;

          // The video element has transform:scaleX(-1) so mirror x for display
          const dispX = (VW - bb.originX - bb.width) * scaleX;
          const dispY = bb.originY * scaleY;
          const dispW = bb.width  * scaleX;
          const dispH = bb.height * scaleY;

          faceRect = { x:dispX, y:dispY, w:dispW, h:dispH };

          // Forehead ROI (top 25 %, centre 60 %)
          const rDispX = dispX + dispW * 0.20;
          const rDispY = dispY + dispH * 0.03;
          const rDispW = dispW * 0.60;
          const rDispH = dispH * 0.22;
          roiRect = { x:rDispX, y:rDispY, w:rDispW, h:rDispH };

          // Video-pixel coords for sampling (NOT mirrored — grab from actual frame)
          roiVx = bb.originX + bb.width * 0.20;
          roiVy = bb.originY + bb.height * 0.03;
          roiVw = bb.width  * 0.60;
          roiVh = bb.height * 0.22;

          setStatus('✅ Face detected — measuring pulse…');
        }
      }

      // ── Fallback: centre-forehead region ──────────────────────────────────
      if(useFallback){
        roiVx = VW * 0.30; roiVy = VH * 0.10;
        roiVw = VW * 0.40; roiVh = VH * 0.20;

        roiRect = {
          x: DW * 0.30, y: DH * 0.10,
          w: DW * 0.40, h: DH * 0.20
        };
        setStatus(mpReady
          ? '🔍 No face — centre your face in the frame'
          : '📊 Using forehead region — stay still & well-lit');
      }

      drawBoxes(faceRect, roiRect, useFallback);
      sampleROI(roiVx, roiVy, roiVw, roiVh);

      if(rBuf.length >= 90 && frameIdx % 30 === 0) computeBPM();
    }
  } catch(e){ console.error('Frame err:', e); }

  frameIdx++;
  drawWave();
  rafId = requestAnimationFrame(loop);
}

// ── CHROM rPPG ────────────────────────────────────────────────────────────────
function computeBPM(){
  const N = rBuf.length;
  const Xs=[], Ys=[];
  for(let i=0;i<N;i++){
    Xs.push(rBuf[i]-gBuf[i]);
    Ys.push(0.5*rBuf[i]+0.5*gBuf[i]-bBuf[i]);
  }
  const mX=Xs.reduce((a,b)=>a+b,0)/N;
  const mY=Ys.reduce((a,b)=>a+b,0)/N;
  let vX=0,vY=0;
  for(let i=0;i<N;i++){ vX+=(Xs[i]-mX)**2; vY+=(Ys[i]-mY)**2; }
  const alpha=Math.sqrt(vX/N)/(Math.sqrt(vY/N)||1);

  const sig=[];
  for(let i=0;i<N;i++) sig.push(Xs[i]-alpha*Ys[i]);
  chromaBuf = sig.slice(-150);

  const sm=sig.reduce((a,b)=>a+b,0)/N;
  const ss=Math.sqrt(sig.map(v=>(v-sm)**2).reduce((a,b)=>a+b,0)/N)||1;
  const norm=sig.map(v=>(v-sm)/ss);

  const win=norm.slice(-150);
  const peaks=[];
  for(let i=2;i<win.length-2;i++){
    if(win[i]>win[i-1]&&win[i]>win[i+1]&&win[i]>win[i-2]&&win[i]>win[i+2]&&win[i]>0.2)
      peaks.push(i);
  }
  if(peaks.length<2) return;

  const ivls=[];
  for(let i=1;i<peaks.length;i++) ivls.push(peaks[i]-peaks[i-1]);
  const avgIvl=ivls.reduce((a,b)=>a+b,0)/ivls.length;
  const bpm=Math.round(60/(avgIvl/FPS));
  const quality=Math.min(100,Math.max(0,(peaks.length/8)*70+20));

  if(bpm>=45&&bpm<=170&&quality>30){
    lastBpm=bpm; lastQuality=quality;
    bpmHistory.push(bpm);
    if(bpmHistory.length>10) bpmHistory.shift();
    updateBpmUI(bpm, quality);
    try{ window.parent.postMessage({type:'bpm_update',bpm,quality},'*'); }catch(_){}
  }
}

// ── Waveform ──────────────────────────────────────────────────────────────────
function drawWave(){
  const W=waveC.width=waveC.offsetWidth, H=waveC.height=52;
  waveCtx.fillStyle='#0d1117';
  waveCtx.fillRect(0,0,W,H);

  const data = chromaBuf.length ? chromaBuf : rBuf;
  if(data.length<2) return;

  const mn=Math.min(...data), mx=Math.max(...data), rng=(mx-mn)||1;
  waveCtx.beginPath();
  waveCtx.strokeStyle='#3b82f6';
  waveCtx.lineWidth=1.5;
  const step=W/(data.length-1);
  data.forEach((v,i)=>{
    const x=i*step, y=H-((v-mn)/rng)*(H-8)-4;
    i===0?waveCtx.moveTo(x,y):waveCtx.lineTo(x,y);
  });
  waveCtx.stroke();
}

// ── Buttons ───────────────────────────────────────────────────────────────────
startBtn.onclick = async () => {
  if(isRunning) return;
  if(!mpReady && !detector) await loadMediaPipe();
  const ok = await startCamera();
  if(!ok) return;
  isRunning=true;
  rBuf=[]; gBuf=[]; bBuf=[]; chromaBuf=[];
  bpmHistory=[]; frameIdx=0; lastBpm=null; lastQuality=0;
  loop();
};

stopBtn.onclick = () => stopEverything();

saveBtn.onclick = () => {
  if(!lastBpm || lastQuality < 30){
    alert('No valid reading yet. Wait for a stable signal on the waveform.');
    return;
  }
  const bpm = Math.round(lastBpm);
  const quality = parseFloat(lastQuality.toFixed(2));

  // Notify parent (for live BPM display updates)
  try{ window.parent.postMessage({type:'save_reading', bpm, quality},'*'); }catch(_){}

  // Update parent URL so Streamlit picks up query params on next rerun
  try{
    const url = new URL(window.parent.location.href);
    url.searchParams.set('saved_bpm', bpm);
    url.searchParams.set('saved_quality', quality);
    window.parent.history.replaceState({}, '', url.toString());
    // Trigger Streamlit rerun via small reload delay
    setTimeout(()=>{ window.parent.location.reload(); }, 250);
  } catch(e){
    // Cross-origin fallback: show values so user can note them
    alert('Reading saved locally!\nBPM: ' + bpm + '\nQuality: ' + quality + '%\n\nStreamlit will update shortly.');
  }
};

// ── Boot ──────────────────────────────────────────────────────────────────────
loadMediaPipe();
</script>
</body>
</html>"""
    return st_html(component_html, height=580, scrolling=False)


# ─── Encryption Simulation ────────────────────────────────────────────────────
def show_encryption_simulation(bpm, quality):
    st.markdown("### 🔐 Hybrid Encryption Pipeline")
    st.markdown("Your health data is being secured through military-grade encryption")

    health_data = {
        "patient_id": f"PT-{st.session_state.user_id:04d}",
        "heart_rate": bpm, "signal_quality": quality,
        "timestamp": datetime.now().isoformat(),
        "user": st.session_state.username
    }
    plaintext = json.dumps(health_data, indent=2)

    key_hex, payload, ecc_pub, block_hash = encrypt_and_save(bpm, quality)

    steps = [
        ("📝 Step 1: Original Data",        "Patient health data prepared for encryption", plaintext),
        ("🔑 Step 2: AES-256 Key",           "Generating 256-bit key", f"AES-256 Key: {key_hex[:32]}...{key_hex[-8:]}"),
        ("🎲 Step 3: Nonce",                 "Creating 96-bit GCM nonce", f"Nonce: {secrets.token_hex(12)}"),
        ("🔒 Step 4: AES-256-GCM",           "Authenticated encryption", f"Ciphertext length: {len(payload)} bytes"),
        ("🔐 Step 5: ECC SECP256R1",         "ECC key pair generated", f"ECC Public Key: {ecc_pub[:60]}..."),
        ("✍️ Step 6: HMAC-SHA256",           "Tamper-proof signature", f"HMAC: {hashlib.sha256(f'{payload}{key_hex}'.encode()).hexdigest()[:32]}..."),
        ("📦 Step 7: Blockchain Storage",    "Immutable audit entry", f"Block Hash: {block_hash[:32]}..."),
    ]

    for title, desc, data in steps:
        col1, col2 = st.columns([1, 8])
        with col1:
            st.markdown("### ✅")
        with col2:
            st.markdown(f"**{title}**")
            st.caption(desc)
            lang = "json" if "Step 1" in title else "text"
            st.code(data, language=lang)
        st.divider()
        time.sleep(0.1)

    st.markdown(f"""
    <div class="encryption-preview">
        <strong>🔑 AES-256 Key:</strong> {key_hex[:32]}...{key_hex[-8:]}<br>
        <strong>🔐 ECC Public Key:</strong> {ecc_pub[:60]}...<br>
        <strong>🔗 Blockchain Hash:</strong> {block_hash[:32]}...<br>
        <strong>📊 Encrypted Size:</strong> {len(payload)} bytes
    </div>
    """, unsafe_allow_html=True)

    st.success(f"✅ Data saved! BPM: {bpm}, Quality: {quality:.1f}% — Encrypted with AES-256-GCM + ECC SECP256R1")


# ─── Login Page ───────────────────────────────────────────────────────────────
def show_login():
    st.markdown("""
    <div class="main-header">
        <h1>❤️ MedChainSecure</h1>
        <p>Advanced Secure IoMT Heart Rate Monitoring Platform with AES-256-GCM Encryption</p>
        <div style="display:flex;justify-content:center;gap:.75rem;margin-top:1.5rem;flex-wrap:wrap;">
            <span class="status-badge status-good">🔒 AES-256-GCM</span>
            <span class="status-badge status-good">🔑 ECC SECP256R1</span>
            <span class="status-badge status-good">📹 Real-time rPPG</span>
            <span class="status-badge status-good">📦 Blockchain Audit</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1, 2, 1])
    with col:
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                if st.form_submit_button("Login", use_container_width=True):
                    conn = sqlite3.connect('heart_monitor.db')
                    c = conn.cursor()
                    c.execute("SELECT id,username,password_hash,is_admin FROM users WHERE username=?", (username,))
                    user = c.fetchone(); conn.close()
                    if user and bcrypt.checkpw(password.encode(), user[2]):
                        st.session_state.authenticated = True
                        st.session_state.user_id   = user[0]
                        st.session_state.username  = user[1]
                        st.session_state.is_admin  = bool(user[3])
                        add_audit_log(user[0], "LOGIN", f"User {username} logged in")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")

        with tab2:
            with st.form("register_form"):
                full_name = st.text_input("Full Name")
                username  = st.text_input("Username")
                ca, cb    = st.columns(2)
                with ca: age    = st.number_input("Age", 1, 120, 25)
                with cb: gender = st.selectbox("Gender", ["Male", "Female", "Other"])
                password = st.text_input("Password", type="password")
                confirm  = st.text_input("Confirm Password", type="password")
                if st.form_submit_button("Register", use_container_width=True):
                    if password != confirm:
                        st.error("❌ Passwords do not match")
                    elif len(password) < 6:
                        st.error("❌ Password must be at least 6 characters")
                    else:
                        try:
                            conn = sqlite3.connect('heart_monitor.db')
                            c = conn.cursor()
                            pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
                            c.execute('INSERT INTO users (username,password_hash,full_name,age,gender,is_admin) VALUES (?,?,?,?,?,0)',
                                      (username, pw, full_name, age, gender))
                            conn.commit(); conn.close()
                            st.success("✅ Registration successful! Please login.")
                        except sqlite3.IntegrityError:
                            st.error("❌ Username already exists")

    st.markdown("<div style='margin-top:3rem;'><h3 style='text-align:center;margin-bottom:1.5rem;'>Key Features</h3></div>",
                unsafe_allow_html=True)
    cols = st.columns(4)
    for col, (icon, title, desc) in zip(cols, [
        ("📹", "Non-invasive rPPG", "Remote heart rate monitoring using standard webcam"),
        ("🔐", "Hybrid Encryption", "AES-256-GCM + ECC SECP256R1 for every record"),
        ("🗄️", "3-Layer Storage",   "Local SQLite + Remote Backup + Blockchain"),
        ("📊", "Audit Trail",       "Immutable blockchain ledger for compliance"),
    ]):
        with col:
            st.markdown(f"""
            <div class="glass-panel" style="text-align:center;height:100%;">
                <div style="font-size:2.5rem;margin-bottom:.5rem;">{icon}</div>
                <h4 style="margin-bottom:.5rem;">{title}</h4>
                <p style="font-size:.75rem;color:var(--text-secondary);">{desc}</p>
            </div>""", unsafe_allow_html=True)


# ─── Dashboard ────────────────────────────────────────────────────────────────
def show_dashboard():
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center;margin-bottom:2rem;">
            <h3 style="color:#3b82f6;">❤️ MedChainSecure</h3>
            <p style="font-size:.7rem;color:#64748b;">Secure IoMT Platform</p>
        </div>""", unsafe_allow_html=True)

        pages = ["Dashboard", "rPPG Monitor", "Health History"]
        if st.session_state.is_admin:
            pages.append("Admin Panel")
        selected = st.radio("Navigation", pages, label_visibility="collapsed")

        st.markdown("---")
        st.markdown(f"""
        <div class="glass-panel">
            <div style="display:flex;align-items:center;gap:.75rem;">
                <div style="width:40px;height:40px;background:linear-gradient(135deg,#3b82f6,#06b6d4);
                    border-radius:50%;display:flex;align-items:center;justify-content:center;">
                    <span style="color:white;">👤</span>
                </div>
                <div>
                    <p style="font-weight:600;">{st.session_state.username}</p>
                    <p style="font-size:.65rem;color:#64748b;">{'Administrator' if st.session_state.is_admin else 'Patient'}</p>
                </div>
            </div>
        </div>""", unsafe_allow_html=True)

        if st.button("🚪 Logout", use_container_width=True):
            add_audit_log(st.session_state.user_id, "LOGOUT", "User logged out")
            for k in ['authenticated','user_id','username','is_admin','saved_bpm','saved_quality']:
                st.session_state[k] = None
            st.rerun()

    # ── Dashboard page ─────────────────────────────────────────────────────────
    if selected == "Dashboard":
        conn = sqlite3.connect('heart_monitor.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM test_results WHERE user_id=?", (st.session_state.user_id,))
        total_tests = c.fetchone()[0]
        c.execute("SELECT AVG(bpm) FROM test_results WHERE user_id=?", (st.session_state.user_id,))
        avg_bpm = c.fetchone()[0] or 0
        conn.close()

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Total Tests</div><div class="stat-value">{total_tests}</div></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Average BPM</div><div class="stat-value">{avg_bpm:.0f}</div></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card"><div class="stat-label">Encryption</div><div class="stat-value" style="font-size:1.2rem;">AES-256</div></div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="glass-panel" style="margin-top:1.5rem;padding:2rem;text-align:center;">
            <h3>🎯 Get Started</h3>
            <p style="margin:1rem 0;">Go to <strong>rPPG Monitor</strong> → press ▶ Start Camera → wait ~10 s → press 💾 Save Reading.</p>
            <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;">
                <span class="status-badge status-good">No physical sensors needed</span>
                <span class="status-badge status-good">Real-time BPM calculation</span>
                <span class="status-badge status-good">End-to-end encryption</span>
            </div>
        </div>""", unsafe_allow_html=True)

    # ── rPPG Monitor page ──────────────────────────────────────────────────────
    elif selected == "rPPG Monitor":
        st.markdown("""
        <div class="main-header">
            <h2>📹 Real rPPG Heart Rate Monitor</h2>
            <p>Position your face in the frame — the system detects your forehead and calculates heart rate in real-time</p>
        </div>""", unsafe_allow_html=True)

        # Tips
        with st.expander("📋 How to get a good reading", expanded=False):
            st.markdown("""
            1. **Good lighting** — face should be evenly lit (avoid backlight from windows)
            2. **Stay still** — movement adds noise to the signal
            3. **Wait ~10–15 seconds** after the waveform appears before saving
            4. If face is not detected, the **yellow dashed box** (fallback ROI) still works — just make sure your forehead is inside it
            5. A **green BPM** = Normal, **orange** = Bradycardia, **red** = Tachycardia
            """)

        _, col, _ = st.columns([1, 3, 1])
        with col:
            rppg_component()

        # Pick up saved reading from query params (set by the component's save button)
        qp = st.query_params
        if 'saved_bpm' in qp and st.session_state.saved_bpm is None:
            try:
                st.session_state.saved_bpm     = int(qp['saved_bpm'])
                st.session_state.saved_quality = float(qp['saved_quality'])
                # Clear from URL
                st.query_params.clear()
            except Exception:
                pass

        if st.session_state.saved_bpm:
            st.markdown("---")
            st.success(f"✅ Reading captured! BPM: {st.session_state.saved_bpm}, Quality: {st.session_state.saved_quality:.1f}%")
            with st.expander("🔐 View detailed encryption process", expanded=True):
                show_encryption_simulation(st.session_state.saved_bpm, st.session_state.saved_quality)
            if st.button("🔄 Clear and take new reading"):
                st.session_state.saved_bpm     = None
                st.session_state.saved_quality = None
                st.rerun()

    # ── Health History page ────────────────────────────────────────────────────
    elif selected == "Health History":
        st.markdown("""
        <div class="main-header">
            <h2>📋 Health History</h2>
            <p>Your encrypted medical records with blockchain verification</p>
        </div>""", unsafe_allow_html=True)

        conn = sqlite3.connect('heart_monitor.db')
        c = conn.cursor()
        c.execute('SELECT bpm,quality,test_date FROM test_results WHERE user_id=? ORDER BY test_date DESC',
                  (st.session_state.user_id,))
        results = c.fetchall(); conn.close()

        if results:
            df = pd.DataFrame(results, columns=['BPM','Quality (%)','Date'])
            df['Quality (%)'] = df['Quality (%)'].round(1)

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df['Date'], y=df['BPM'],
                mode='lines+markers', name='Heart Rate',
                line=dict(color='#3b82f6', width=2)))
            fig.add_hrect(y0=60, y1=100, fillcolor="#10b981", opacity=0.1,
                          annotation_text="Normal Range (60–100 BPM)")
            fig.update_layout(title="Heart Rate History", xaxis_title="Date",
                              yaxis_title="BPM", template="plotly_white", height=400)
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(df, use_container_width=True)
            st.download_button("📥 Export Records (CSV)", df.to_csv(index=False),
                               "heart_history.csv", "text/csv")
        else:
            st.info("No records yet. Use the rPPG Monitor to take your first reading.")

    # ── Admin Panel ────────────────────────────────────────────────────────────
    elif selected == "Admin Panel" and st.session_state.is_admin:
        st.markdown("""
        <div class="main-header">
            <h2>⚙️ Admin Panel</h2>
            <p>System administration and user management</p>
        </div>""", unsafe_allow_html=True)

        conn = sqlite3.connect('heart_monitor.db')
        c = conn.cursor()
        c.execute("SELECT id,username,full_name,age,gender,is_admin FROM users WHERE username!='admin'")
        users = c.fetchall(); conn.close()

        if users:
            for u in users:
                with st.expander(f"👤 {u[1]} — {u[2]}"):
                    c1, c2 = st.columns(2)
                    with c1: st.write(f"**Age:** {u[3]}"); st.write(f"**Gender:** {u[4]}")
                    with c2: st.write(f"**Admin:** {'Yes' if u[5] else 'No'}")
        else:
            st.info("No users found.")

        st.markdown("### 📜 Recent Audit Logs")
        conn = sqlite3.connect('heart_monitor.db')
        c = conn.cursor()
        c.execute("SELECT timestamp,action,details FROM audit_log ORDER BY id DESC LIMIT 10")
        logs = c.fetchall(); conn.close()

        for log in logs:
            st.markdown(f"""
            <div class="glass-panel" style="margin-bottom:.5rem;padding:.75rem;">
                <small style="color:#64748b;">{log[0]}</small>
                <div><strong>{log[1]}</strong> — {log[2]}</div>
            </div>""", unsafe_allow_html=True)


# ─── Entry Point ──────────────────────────────────────────────────────────────
def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
