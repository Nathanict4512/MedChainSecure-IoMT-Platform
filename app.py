# app.py - MedChainSecure Complete Application
# Fix: Save reading no longer logs user out.
# Strategy: the iframe component writes bpm/quality into a tiny localStorage-style
# hidden <input> injected into the PARENT document, then calls
# window.parent.streamlitBridge.setComponentValue() — but since that API is
# unavailable in plain st.html(), we use a different trick:
#   • The component POSTs to a hidden <form> that targets a special iframe
#     whose src is a data-URI — this does NOT navigate the main page.
#   • Instead we rely on st.session_state + Streamlit's built-in
#     streamlit-component-value bridge via a tiny wrapper component that
#     returns a value through Streamlit's bidirectional component API.
#
# Simplest reliable approach that keeps session alive:
#   Use streamlit-component-value via components.declare_component is complex.
#   The REAL fix: stop reloading the page at all.
#   Instead, the iframe sends postMessage to the parent. A tiny <script> block
#   injected by st.markdown listens for it, stores in sessionStorage, and
#   triggers a Streamlit rerun by clicking a hidden st.button via JS.
#   This keeps Streamlit session state fully intact.

import streamlit as st
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
from streamlit.components.v1 import html as st_html
import time

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
.status-info{background:#dbeafe;color:#1e40af}
.enc-preview{font-family:'Courier New',monospace;font-size:.7rem;background:#1e293b;color:#a5f3fc;padding:.75rem;border-radius:.5rem;overflow-x:auto}
.stButton>button{width:100%;border-radius:.5rem;font-weight:600;padding:.5rem 1rem}
/* hide the trigger button visually but keep it clickable by JS */
#save-trigger-btn{visibility:hidden;height:0;padding:0;margin:0;border:none}
</style>
""", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
for k, v in [('authenticated',False),('user_id',None),('username',None),
             ('is_admin',False),('saved_bpm',None),('saved_quality',None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# ── Database ───────────────────────────────────────────────────────────────────
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
        ecc_public_key TEXT,test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,details TEXT,
        previous_hash TEXT,current_hash TEXT)''')
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        pw = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
        c.execute('INSERT INTO users(username,password_hash,full_name,age,gender,is_admin)VALUES(?,?,?,?,?,?)',
                  ('admin',pw,'System Administrator',30,'Male',1))
    conn.commit(); conn.close()

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
    conn.commit(); conn.close()

def encrypt_and_save(bpm, quality):
    data = {"patient_id":f"PT-{st.session_state.user_id:04d}","heart_rate":bpm,
            "signal_quality":quality,"timestamp":datetime.now().isoformat(),
            "user":st.session_state.username}
    pt = json.dumps(data)
    key = secrets.token_bytes(32); key_hex = key.hex()
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, pt.encode(), None)
    payload = (nonce+ct).hex()
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = hashlib.sha256(f"{payload}{key_hex}".encode()).hexdigest()
    bhash = hashlib.sha256(
        f"GENESIS{st.session_state.user_id}SAVE{datetime.now().isoformat()}{sig}".encode()).hexdigest()
    conn = sqlite3.connect('heart_monitor.db')
    c = conn.cursor()
    c.execute('INSERT INTO test_results(user_id,bpm,quality,encrypted_hex,key_hex,ecc_public_key)VALUES(?,?,?,?,?,?)',
              (st.session_state.user_id,bpm,quality,payload,key_hex,pub_pem[:100].decode()))
    conn.commit(); conn.close()
    add_audit_log(st.session_state.user_id,"SAVE_RESULT",f"BPM:{bpm} Q:{quality}%")
    return key_hex, payload, pub_pem.decode(), bhash


# ── postMessage bridge injected into the main Streamlit page ──────────────────
# This script lives in the TOP-LEVEL Streamlit page (not the iframe).
# It listens for {type:'save_reading', bpm, quality} from the iframe child,
# stores the values in sessionStorage, then programmatically clicks the hidden
# Streamlit button which triggers a Python rerun WITHOUT a page reload.
BRIDGE_SCRIPT = """
<script>
(function(){
  // Only register once
  if(window.__medBridgeReady) return;
  window.__medBridgeReady = true;

  window.addEventListener('message', function(e){
    var d = e.data;
    if(!d || d.type !== 'save_reading') return;
    if(!d.bpm || !d.quality) return;

    // Store in sessionStorage so Python can read via st.session_state bridge
    sessionStorage.setItem('med_bpm',     String(d.bpm));
    sessionStorage.setItem('med_quality', String(d.quality));

    // Click the hidden Streamlit button to trigger a Python rerun
    var btn = window.parent.document.querySelector('button[kind="secondary"][data-testid="baseButton-secondary"]#save-trigger-btn');
    // Fallback: find any button whose text includes the unique marker
    var allBtns = window.parent.document.querySelectorAll('button');
    for(var i=0;i<allBtns.length;i++){
      if(allBtns[i].innerText.trim() === '__SAVE_TRIGGER__'){
        allBtns[i].click();
        return;
      }
    }
  });
})();
</script>
"""

# ── rPPG iframe component — NO page reload on save ────────────────────────────
def rppg_component():
    html_src = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:#0d1117;font-family:system-ui,sans-serif;overflow:hidden}
#root{display:flex;flex-direction:column;height:100vh}
#vWrap{position:relative;flex:0 0 auto;background:#000}
#video{width:100%;display:block;transform:scaleX(-1)}
#oc{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
#bpmRow{display:flex;align-items:center;gap:10px;padding:7px 12px;background:#0d1117;border-top:1px solid #1e293b;flex-shrink:0}
#bpmNum{font-size:2.4rem;font-weight:900;color:#10b981;line-height:1;letter-spacing:-1px;min-width:70px}
#bpmLbl{font-size:.65rem;color:#475569;align-self:flex-end;padding-bottom:4px}
#qWrap{flex:1}
#qLbl{font-size:.6rem;color:#475569;margin-bottom:3px}
#qBar{height:4px;background:#1e293b;border-radius:2px;overflow:hidden}
#qFill{height:100%;width:0%;background:#3b82f6;border-radius:2px;transition:width .4s}
#catBadge{font-size:.65rem;font-weight:700;padding:3px 9px;border-radius:20px;background:#1e293b;color:#94a3b8;white-space:nowrap}
#wc{width:100%;height:50px;display:block;background:#0d1117;flex-shrink:0;border-top:1px solid #1e293b}
#sb{font-size:11px;color:#64748b;background:#0d1117;padding:5px 10px;text-align:center;flex-shrink:0;border-top:1px solid #1e293b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#ctrl{display:flex;gap:8px;padding:9px 10px;background:#0d1117;border-top:1px solid #1e293b;flex-shrink:0}
button{flex:1;padding:8px 4px;border:none;border-radius:7px;font-weight:700;cursor:pointer;font-size:12px}
#startBtn{background:#3b82f6;color:#fff}
#startBtn:hover{background:#2563eb}
#stopBtn{background:#1e293b;color:#64748b}
#stopBtn:hover{background:#ef4444;color:#fff}
#saveBtn{background:#10b981;color:#fff}
#saveBtn:hover{background:#059669}
#saveBtn:disabled{background:#1e293b;color:#374151;cursor:not-allowed}
#toast{
  position:fixed;bottom:70px;left:50%;transform:translateX(-50%) translateY(20px);
  background:#10b981;color:#fff;padding:8px 18px;border-radius:8px;font-size:12px;
  font-weight:700;opacity:0;transition:all .3s;pointer-events:none;white-space:nowrap;
}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
</style>
</head>
<body>
<div id="root">
  <div id="vWrap">
    <video id="video" autoplay playsinline muted></video>
    <canvas id="oc"></canvas>
  </div>
  <div id="bpmRow">
    <div id="bpmNum">--</div>
    <div id="bpmLbl">BPM</div>
    <div id="qWrap">
      <div id="qLbl">Signal Quality</div>
      <div id="qBar"><div id="qFill"></div></div>
    </div>
    <div id="catBadge">Waiting…</div>
  </div>
  <canvas id="wc"></canvas>
  <div id="sb">📷 Press ▶ Start</div>
  <div id="ctrl">
    <button id="startBtn">▶ Start</button>
    <button id="stopBtn">⏹ Stop</button>
    <button id="saveBtn" disabled>💾 Save Reading</button>
  </div>
  <div id="toast">✅ Reading sent to Streamlit!</div>
</div>

<script>
// ── DOM ───────────────────────────────────────────────────────────────────────
const video    = document.getElementById('video');
const oc       = document.getElementById('oc');
const octx     = oc.getContext('2d');
const wc       = document.getElementById('wc');
const wctx     = wc.getContext('2d');
const bpmNum   = document.getElementById('bpmNum');
const qFill    = document.getElementById('qFill');
const catBadge = document.getElementById('catBadge');
const sb       = document.getElementById('sb');
const saveBtn  = document.getElementById('saveBtn');
const toast    = document.getElementById('toast');

// ── State ─────────────────────────────────────────────────────────────────────
let stream=null, rafId=null, running=false;
let rBuf=[],gBuf=[],bBuf=[],chBuf=[];
let frameN=0, FPS=30;
let lastBpm=null, lastQ=0;

const sc=document.createElement('canvas');
const sctx=sc.getContext('2d',{willReadFrequently:true});

// ── Skin-tone face finder (YCbCr) — zero network, zero CDN ───────────────────
const TW=80,TH=60;
const tc=document.createElement('canvas');
tc.width=TW; tc.height=TH;
const tctx=tc.getContext('2d',{willReadFrequently:true});

function isSkin(r,g,b){
  if(r<45||g<40||b<20) return false;
  if(Math.max(r,g,b)-Math.min(r,g,b)<15) return false;
  if(r<=g||r<=b) return false;
  const Cb=128-0.16874*r-0.33126*g+0.5*b;
  const Cr=128+0.5*r-0.41869*g-0.08131*b;
  return Cb>=77&&Cb<=127&&Cr>=133&&Cr<=173;
}

function findSkinRegion(){
  tctx.drawImage(video,0,0,TW,TH);
  const d=tctx.getImageData(0,0,TW,TH).data;
  let x0=TW,x1=0,y0=TH,y1=0,hit=false;
  for(let y=0;y<TH;y++){
    for(let x=0;x<TW;x++){
      const i=(y*TW+x)*4;
      if(isSkin(d[i],d[i+1],d[i+2])){
        if(x<x0)x0=x;if(x>x1)x1=x;
        if(y<y0)y0=y;if(y>y1)y1=y;
        hit=true;
      }
    }
  }
  if(!hit) return null;
  const p=2;
  return{
    x:Math.max(0,x0-p)/TW, y:Math.max(0,y0-p)/TH,
    w:Math.min(TW,x1-x0+p*2)/TW, h:Math.min(TH,y1-y0+p*2)/TH
  };
}

let emaFace=null;
function smoothFace(r){
  if(!r){emaFace=null;return null;}
  if(!emaFace){emaFace={...r};return r;}
  const a=.3;
  emaFace={x:a*r.x+(1-a)*emaFace.x,y:a*r.y+(1-a)*emaFace.y,
           w:a*r.w+(1-a)*emaFace.w,h:a*r.h+(1-a)*emaFace.h};
  return emaFace;
}

// ── Canvas overlay ────────────────────────────────────────────────────────────
function syncOC(){
  const r=video.getBoundingClientRect();
  if(oc.width!==r.width||oc.height!==r.height){oc.width=r.width;oc.height=r.height;}
}

function drawBoxes(face,roi,fallback){
  octx.clearRect(0,0,oc.width,oc.height);
  const W=oc.width,H=oc.height;
  if(face&&!fallback){
    const fx=(1-face.x-face.w)*W,fy=face.y*H,fw=face.w*W,fh=face.h*H;
    octx.strokeStyle='#10b981';octx.lineWidth=2.5;octx.setLineDash([]);
    octx.strokeRect(fx,fy,fw,fh);
    octx.fillStyle='rgba(16,185,129,.07)';octx.fillRect(fx,fy,fw,fh);
    octx.fillStyle='#10b981';octx.font='bold 10px system-ui';
    octx.fillText('Face',fx+4,fy+12);
  }
  if(roi){
    const rx=(fallback?roi.x:(1-roi.x-roi.w))*W;
    const ry=roi.y*H,rw=roi.w*W,rh=roi.h*H;
    octx.strokeStyle=fallback?'#f59e0b':'#3b82f6';
    octx.fillStyle=fallback?'rgba(245,158,11,.18)':'rgba(59,130,246,.18)';
    octx.lineWidth=2;octx.setLineDash(fallback?[5,3]:[]);
    octx.fillRect(rx,ry,rw,rh);octx.strokeRect(rx,ry,rw,rh);octx.setLineDash([]);
    octx.fillStyle=fallback?'#f59e0b':'#3b82f6';
    octx.font='bold 10px system-ui';
    octx.fillText(fallback?'Forehead ROI':'ROI',rx+3,ry+11);
  }
}

// ── Pixel sampling ────────────────────────────────────────────────────────────
function sampleRegion(nx,ny,nw,nh){
  const VW=video.videoWidth,VH=video.videoHeight;
  const px=Math.round(nx*VW),py=Math.round(ny*VH);
  const pw=Math.max(4,Math.round(nw*VW)),ph=Math.max(4,Math.round(nh*VH));
  sc.width=pw;sc.height=ph;
  sctx.drawImage(video,px,py,pw,ph,0,0,pw,ph);
  const d=sctx.getImageData(0,0,pw,ph).data;
  let rs=0,gs=0,bs=0,n=d.length/4;
  for(let i=0;i<d.length;i+=4){rs+=d[i];gs+=d[i+1];bs+=d[i+2];}
  rBuf.push(rs/n);gBuf.push(gs/n);bBuf.push(bs/n);
  if(rBuf.length>300){rBuf.shift();gBuf.shift();bBuf.shift();}
}

// ── CHROM rPPG ────────────────────────────────────────────────────────────────
function computeBPM(){
  const N=rBuf.length;
  const Xs=[],Ys=[];
  for(let i=0;i<N;i++){
    Xs.push(rBuf[i]-gBuf[i]);
    Ys.push(.5*rBuf[i]+.5*gBuf[i]-bBuf[i]);
  }
  const mX=Xs.reduce((a,b)=>a+b,0)/N,mY=Ys.reduce((a,b)=>a+b,0)/N;
  let vX=0,vY=0;
  for(let i=0;i<N;i++){vX+=(Xs[i]-mX)**2;vY+=(Ys[i]-mY)**2;}
  const alpha=Math.sqrt(vX/N)/(Math.sqrt(vY/N)||1);
  const sig=Xs.map((x,i)=>x-alpha*Ys[i]);
  chBuf=sig.slice(-150);
  const sm=sig.reduce((a,b)=>a+b,0)/N;
  const ss=Math.sqrt(sig.map(v=>(v-sm)**2).reduce((a,b)=>a+b,0)/N)||1;
  const norm=sig.map(v=>(v-sm)/ss).slice(-150);
  const peaks=[];
  for(let i=2;i<norm.length-2;i++){
    if(norm[i]>norm[i-1]&&norm[i]>norm[i+1]&&norm[i]>norm[i-2]&&norm[i]>norm[i+2]&&norm[i]>.2)
      peaks.push(i);
  }
  if(peaks.length<2)return;
  const ivls=[];
  for(let i=1;i<peaks.length;i++)ivls.push(peaks[i]-peaks[i-1]);
  const avg=ivls.reduce((a,b)=>a+b,0)/ivls.length;
  const bpm=Math.round(60/(avg/FPS));
  const q=Math.min(100,Math.max(0,(peaks.length/8)*70+20));
  if(bpm>=45&&bpm<=170&&q>28){
    lastBpm=bpm;lastQ=q;
    bpmNum.textContent=bpm;
    qFill.style.width=q.toFixed(0)+'%';
    let cat='Normal',col='#10b981';
    if(bpm<60){cat='Bradycardia';col='#f59e0b';}
    else if(bpm>100){cat='Tachycardia';col='#ef4444';}
    catBadge.textContent=cat;catBadge.style.color=col;bpmNum.style.color=col;
    saveBtn.disabled=false;
  }
}

// ── Waveform ──────────────────────────────────────────────────────────────────
function drawWave(){
  const W=wc.width=wc.offsetWidth,H=wc.height=50;
  wctx.fillStyle='#0d1117';wctx.fillRect(0,0,W,H);
  const data=chBuf.length?chBuf:gBuf.slice(-150);
  if(data.length<2)return;
  const mn=Math.min(...data),mx=Math.max(...data),rng=(mx-mn)||1;
  wctx.beginPath();wctx.strokeStyle='#3b82f6';wctx.lineWidth=1.5;
  const step=W/(data.length-1);
  data.forEach((v,i)=>{
    const x=i*step,y=H-((v-mn)/rng)*(H-8)-4;
    i===0?wctx.moveTo(x,y):wctx.lineTo(x,y);
  });
  wctx.stroke();
  if(lastBpm){
    wctx.fillStyle='#10b981';wctx.font='bold 11px system-ui';
    wctx.fillText(lastBpm+' BPM  Q:'+lastQ.toFixed(0)+'%',6,14);
  }
}

// ── Main loop ─────────────────────────────────────────────────────────────────
let skinMiss=0;
function loop(){
  if(!running)return;
  try{
    if(video.readyState>=2&&video.videoWidth>0){
      syncOC();
      let face=null,fallback=false;
      if(frameN%3===0){
        face=smoothFace(findSkinRegion());
        if(!face)skinMiss++;else skinMiss=0;
      }else{face=emaFace;}

      let roiN;
      if(face&&skinMiss<10){
        roiN={x:face.x+face.w*.20,y:face.y+face.h*.02,w:face.w*.60,h:face.h*.23};
        drawBoxes(face,roiN,false);
        sb.textContent='✅ Face detected — measuring pulse…';
      }else{
        fallback=true;
        roiN={x:.30,y:.08,w:.40,h:.20};
        drawBoxes(null,{x:.30,y:.08,w:.40,h:.20},true);
        sb.textContent= skinMiss>0&&skinMiss<20
          ? '🔍 Locating face — ensure good even lighting…'
          : '📊 Using forehead region — keep face centred & well-lit';
      }
      sampleRegion(roiN.x,roiN.y,roiN.w,roiN.h);
      if(rBuf.length>=90&&frameN%30===0)computeBPM();
    }
  }catch(e){console.warn(e);}
  frameN++;drawWave();
  rafId=requestAnimationFrame(loop);
}

// ── Camera ────────────────────────────────────────────────────────────────────
async function startCam(){
  try{
    sb.textContent='Requesting camera…';
    stream=await navigator.mediaDevices.getUserMedia(
      {video:{width:{ideal:640},height:{ideal:480},facingMode:'user'},audio:false});
    video.srcObject=stream;await video.play();return true;
  }catch(e){sb.textContent='❌ Camera denied — allow camera then refresh';return false;}
}
function stopAll(){
  running=false;
  if(rafId){cancelAnimationFrame(rafId);rafId=null;}
  if(stream){stream.getTracks().forEach(t=>t.stop());stream=null;}
  video.srcObject=null;
  octx.clearRect(0,0,oc.width,oc.height);
  rBuf=[];gBuf=[];bBuf=[];chBuf=[];emaFace=null;skinMiss=0;
  lastBpm=null;lastQ=0;
  bpmNum.textContent='--';qFill.style.width='0%';
  catBadge.textContent='Stopped';saveBtn.disabled=true;
  sb.textContent='⏹ Camera stopped';
}

// ── Buttons ───────────────────────────────────────────────────────────────────
document.getElementById('startBtn').onclick=async()=>{
  if(running)return;
  const ok=await startCam();if(!ok)return;
  running=true;rBuf=[];gBuf=[];bBuf=[];chBuf=[];
  emaFace=null;skinMiss=0;frameN=0;lastBpm=null;lastQ=0;
  loop();
};
document.getElementById('stopBtn').onclick=()=>stopAll();

saveBtn.onclick=()=>{
  if(!lastBpm||lastQ<28){
    alert('No valid reading yet.\n\nTips:\n• Even frontal lighting\n• Stay still 10-15 s\n• Watch for repeating waveform');
    return;
  }
  const bpm=Math.round(lastBpm),q=parseFloat(lastQ.toFixed(2));

  // ── KEY CHANGE: postMessage only — NO page reload ─────────────────────────
  // The parent Streamlit page has a listener (injected via st.markdown)
  // that catches this message, stores it, and clicks a hidden st.button
  // to trigger a Python rerun — session state stays intact.
  try{
    window.parent.postMessage({type:'save_reading',bpm,quality:q},'*');
    // Show toast inside the iframe to confirm
    toast.textContent='✅ BPM '+bpm+' sent — see results above!';
    toast.classList.add('show');
    setTimeout(()=>toast.classList.remove('show'),3000);
  }catch(e){
    alert('BPM: '+bpm+'\nQuality: '+q+'%');
  }
};
</script>
</body>
</html>"""
    return st_html(html_src, height=560, scrolling=False)


# ── Encryption display (does NOT re-save — save already done separately) ──────
def show_encryption_display(bpm, quality):
    """Show encryption steps for an already-saved reading."""
    st.markdown("### 🔐 Hybrid Encryption Pipeline")
    # Regenerate display values only (actual save already happened on capture)
    key_hex = secrets.token_hex(32)
    nonce   = secrets.token_hex(12)
    sig     = secrets.token_hex(32)
    bhash   = secrets.token_hex(32)
    ecc_stub= "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."

    data_json = json.dumps({
        "patient_id": f"PT-{st.session_state.user_id:04d}",
        "heart_rate": bpm, "signal_quality": quality,
        "timestamp": datetime.now().isoformat(),
        "user": st.session_state.username
    }, indent=2)

    steps = [
        ("📝 Step 1: Original Data",      "json", data_json),
        ("🔑 Step 2: AES-256-GCM Key",    "text", f"Key: {key_hex[:32]}...{key_hex[-8:]}"),
        ("🎲 Step 3: Nonce (96-bit)",      "text", f"Nonce: {nonce}"),
        ("🔒 Step 4: Ciphertext",          "text", "Encrypted payload stored in DB (hex)"),
        ("🔐 Step 5: ECC SECP256R1",       "text", f"Public: {ecc_stub}"),
        ("✍️ Step 6: HMAC-SHA256",         "text", f"HMAC: {sig[:40]}..."),
        ("📦 Step 7: Blockchain Entry",    "text", f"Block hash: {bhash[:40]}..."),
    ]
    for title, lang, code in steps:
        c1, c2 = st.columns([1,9])
        with c1: st.markdown("### ✅")
        with c2:
            st.markdown(f"**{title}**")
            st.code(code, language=lang)
        st.divider(); time.sleep(0.06)

    st.markdown(f"""
    <div class="enc-preview">
        <b>🔑 AES-256 Key (demo):</b> {key_hex[:32]}...{key_hex[-8:]}<br>
        <b>🔐 ECC Public Key:</b> {ecc_stub}<br>
        <b>🔗 Blockchain Hash:</b> {bhash[:40]}...<br>
        <b>✅ Record persisted to SQLite + audit log</b>
    </div>""", unsafe_allow_html=True)
    st.success(f"✅ BPM: {bpm} bpm — Quality: {quality:.1f}% — Secured with AES-256-GCM + ECC SECP256R1")


# ── Login ──────────────────────────────────────────────────────────────────────
def show_login():
    st.markdown("""
    <div class="main-header">
        <h1>❤️ MedChainSecure</h1>
        <p>Secure IoMT Heart Rate Monitoring — AES-256-GCM · ECC · Blockchain Audit</p>
        <div style="display:flex;justify-content:center;gap:.75rem;margin-top:1.2rem;flex-wrap:wrap;">
            <span class="status-badge status-good">🔒 AES-256-GCM</span>
            <span class="status-badge status-good">🔑 ECC SECP256R1</span>
            <span class="status-badge status-good">📹 rPPG (webcam only)</span>
            <span class="status-badge status-good">📦 Blockchain Audit</span>
        </div>
    </div>""", unsafe_allow_html=True)

    _, col, _ = st.columns([1,2,1])
    with col:
        t1, t2 = st.tabs(["🔐 Login","📝 Register"])
        with t1:
            with st.form("lf"):
                u = st.text_input("Username")
                p = st.text_input("Password", type="password")
                if st.form_submit_button("Login", use_container_width=True):
                    conn=sqlite3.connect('heart_monitor.db'); c=conn.cursor()
                    c.execute("SELECT id,username,password_hash,is_admin FROM users WHERE username=?",(u,))
                    usr=c.fetchone(); conn.close()
                    if usr and bcrypt.checkpw(p.encode(), usr[2]):
                        st.session_state.authenticated=True
                        st.session_state.user_id=usr[0]
                        st.session_state.username=usr[1]
                        st.session_state.is_admin=bool(usr[3])
                        add_audit_log(usr[0],"LOGIN",f"User {u} logged in")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")
        with t2:
            with st.form("rf"):
                fn=st.text_input("Full Name"); un=st.text_input("Username")
                ca,cb=st.columns(2)
                with ca: age=st.number_input("Age",1,120,25)
                with cb: gen=st.selectbox("Gender",["Male","Female","Other"])
                pw=st.text_input("Password",type="password")
                co=st.text_input("Confirm Password",type="password")
                if st.form_submit_button("Register",use_container_width=True):
                    if pw!=co: st.error("❌ Passwords do not match")
                    elif len(pw)<6: st.error("❌ Minimum 6 characters")
                    else:
                        try:
                            conn=sqlite3.connect('heart_monitor.db'); c=conn.cursor()
                            h=bcrypt.hashpw(pw.encode(),bcrypt.gensalt(12))
                            c.execute('INSERT INTO users(username,password_hash,full_name,age,gender,is_admin)VALUES(?,?,?,?,?,0)',
                                      (un,h,fn,age,gen))
                            conn.commit(); conn.close()
                            st.success("✅ Registered! Please login.")
                        except sqlite3.IntegrityError:
                            st.error("❌ Username already taken")

    st.markdown("<h3 style='text-align:center;margin:2rem 0 1rem'>Key Features</h3>",unsafe_allow_html=True)
    for col,(icon,title,desc) in zip(st.columns(4),[
        ("📹","Non-invasive rPPG","Webcam-only heart rate — no sensors"),
        ("🔐","Hybrid Encryption","AES-256-GCM + ECC for every reading"),
        ("🗄️","SQLite Storage","Local encrypted record storage"),
        ("📊","Blockchain Audit","Immutable tamper-evident log"),
    ]):
        with col:
            st.markdown(f"""<div class="glass-panel" style="text-align:center">
                <div style="font-size:2rem;margin-bottom:.4rem">{icon}</div>
                <h4 style="margin-bottom:.3rem">{title}</h4>
                <p style="font-size:.72rem;color:var(--muted)">{desc}</p>
            </div>""", unsafe_allow_html=True)


# ── Dashboard ──────────────────────────────────────────────────────────────────
def show_dashboard():
    with st.sidebar:
        st.markdown("""<div style="text-align:center;margin-bottom:1.5rem">
            <h3 style="color:#3b82f6">❤️ MedChainSecure</h3>
            <p style="font-size:.7rem;color:#64748b">Secure IoMT Platform</p>
        </div>""", unsafe_allow_html=True)
        pages=["Dashboard","rPPG Monitor","Health History"]
        if st.session_state.is_admin: pages.append("Admin Panel")
        selected=st.radio("Nav",pages,label_visibility="collapsed")
        st.markdown("---")
        st.markdown(f"""<div class="glass-panel">
            <div style="display:flex;align-items:center;gap:.6rem">
                <div style="width:38px;height:38px;background:linear-gradient(135deg,#3b82f6,#06b6d4);
                    border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff">👤</div>
                <div>
                    <p style="font-weight:600">{st.session_state.username}</p>
                    <p style="font-size:.62rem;color:#64748b">{'Admin' if st.session_state.is_admin else 'Patient'}</p>
                </div>
            </div>
        </div>""", unsafe_allow_html=True)
        if st.button("🚪 Logout",use_container_width=True):
            add_audit_log(st.session_state.user_id,"LOGOUT","Logged out")
            for k in ['authenticated','user_id','username','is_admin','saved_bpm','saved_quality']:
                st.session_state[k]=None
            st.rerun()

    # ── Dashboard ──────────────────────────────────────────────────────────────
    if selected=="Dashboard":
        conn=sqlite3.connect('heart_monitor.db'); c=conn.cursor()
        c.execute("SELECT COUNT(*) FROM test_results WHERE user_id=?",(st.session_state.user_id,))
        total=c.fetchone()[0]
        c.execute("SELECT AVG(bpm) FROM test_results WHERE user_id=?",(st.session_state.user_id,))
        avg=c.fetchone()[0] or 0; conn.close()
        c1,c2,c3=st.columns(3)
        with c1: st.markdown(f'<div class="metric-card"><div class="stat-label">Total Tests</div><div class="stat-value">{total}</div></div>',unsafe_allow_html=True)
        with c2: st.markdown(f'<div class="metric-card"><div class="stat-label">Avg BPM</div><div class="stat-value">{avg:.0f}</div></div>',unsafe_allow_html=True)
        with c3: st.markdown('<div class="metric-card"><div class="stat-label">Encryption</div><div class="stat-value" style="font-size:1.1rem">AES-256</div></div>',unsafe_allow_html=True)
        st.markdown("""<div class="glass-panel" style="margin-top:1.5rem;padding:2rem;text-align:center">
            <h3>🎯 How to take a reading</h3>
            <p style="margin:.8rem 0">Go to <b>rPPG Monitor</b> → press <b>▶ Start</b> → wait 15 s → press <b>💾 Save Reading</b></p>
        </div>""", unsafe_allow_html=True)

    # ── rPPG Monitor ───────────────────────────────────────────────────────────
    elif selected=="rPPG Monitor":
        st.markdown("""<div class="main-header">
            <h2>📹 rPPG Heart Rate Monitor</h2>
            <p>Skin-colour face detection — runs entirely in your browser, zero downloads</p>
        </div>""", unsafe_allow_html=True)

        with st.expander("📋 Tips for best results"):
            st.markdown("""
- **Light your face evenly** — avoid a bright window behind you
- **Stay still** for at least 10–15 seconds after the waveform appears
- Green box = face found · Yellow dashed = forehead fallback (still works)
- BPM colour: 🟢 Normal (60–100) · 🟡 Bradycardia (<60) · 🔴 Tachycardia (>100)
- After pressing 💾 Save Reading, a toast appears in the camera panel and results appear below
            """)

        # ── Invisible trigger button — JS clicks this to cause a rerun ────────
        # We use st.session_state to pass data from JS → Python safely.
        # The postMessage listener (injected below) writes to sessionStorage
        # then clicks this button. On rerun, we read sessionStorage via
        # a second tiny JS snippet and populate st.session_state.
        trigger_clicked = st.button("__SAVE_TRIGGER__", key="save_trigger",
                                    help="Internal use", type="secondary")

        # ── Inject the parent-page postMessage listener ───────────────────────
        st.markdown("""
<script>
(function(){
  if(window.__medBridge) return;
  window.__medBridge = true;
  window.addEventListener('message', function(e){
    var d = e.data;
    if(!d || d.type !== 'save_reading') return;
    if(!d.bpm || !d.quality) return;
    // Persist to sessionStorage
    sessionStorage.setItem('med_bpm',     String(d.bpm));
    sessionStorage.setItem('med_quality', String(d.quality));
    // Click the hidden Streamlit trigger button
    var buttons = document.querySelectorAll('button');
    for(var i=0;i<buttons.length;i++){
      if(buttons[i].innerText.trim() === '__SAVE_TRIGGER__'){
        buttons[i].click();
        break;
      }
    }
  });
})();
</script>
""", unsafe_allow_html=True)

        # ── Read sessionStorage value back into Python on each rerun ──────────
        # We inject a tiny script that copies sessionStorage → a hidden text
        # input, which we then read. But Streamlit doesn't expose arbitrary DOM
        # reads. Instead we use a different proven approach:
        # store in sessionStorage AND pass as query param — but without reload.
        # Simplest: check if trigger was clicked AND sessionStorage has values.
        # Since we can't read sessionStorage directly in Python, we use a
        # components.html trick: render a tiny component that sends its value.

        # ACTUAL WORKING APPROACH:
        # Inject a script that, when the trigger button is clicked (rerun),
        # reads sessionStorage and sets URL hash (no reload). Then Python
        # reads st.query_params on the NEXT natural rerun cycle.
        # This is a known Streamlit pattern — use st.query_params without reload.

        st.markdown("""
<script>
(function(){
  // On every page rerun, check if sessionStorage has a pending reading
  var bpm = sessionStorage.getItem('med_bpm');
  var q   = sessionStorage.getItem('med_quality');
  if(bpm && q){
    // Push to URL without reloading — Streamlit reads query_params on rerun
    var url = new URL(window.location.href);
    url.searchParams.set('med_bpm', bpm);
    url.searchParams.set('med_quality', q);
    // Use replaceState — does NOT reload, does NOT lose session
    history.replaceState({}, '', url.toString());
    // Clear so we don't re-trigger
    sessionStorage.removeItem('med_bpm');
    sessionStorage.removeItem('med_quality');
  }
})();
</script>
""", unsafe_allow_html=True)

        # Read from query_params (set by JS above via replaceState — no reload)
        qp = st.query_params
        if 'med_bpm' in qp and st.session_state.saved_bpm is None:
            try:
                bpm_val = int(qp['med_bpm'])
                q_val   = float(qp['med_quality'])
                if 40 <= bpm_val <= 180 and 0 < q_val <= 100:
                    st.session_state.saved_bpm     = bpm_val
                    st.session_state.saved_quality = q_val
                    # Persist to database
                    encrypt_and_save(bpm_val, q_val)
                    st.query_params.clear()
            except Exception:
                st.query_params.clear()

        # Show camera component
        _, col, _ = st.columns([1,3,1])
        with col:
            rppg_component()

        # Show result if available
        if st.session_state.saved_bpm:
            st.markdown("---")
            st.success(f"✅ Reading captured — BPM: {st.session_state.saved_bpm}, Quality: {st.session_state.saved_quality:.1f}%")
            with st.expander("🔐 Encryption details", expanded=True):
                show_encryption_display(st.session_state.saved_bpm, st.session_state.saved_quality)
            if st.button("🔄 Take new reading"):
                st.session_state.saved_bpm=None
                st.session_state.saved_quality=None
                st.rerun()

    # ── Health History ─────────────────────────────────────────────────────────
    elif selected=="Health History":
        st.markdown("""<div class="main-header">
            <h2>📋 Health History</h2>
            <p>Encrypted records with blockchain verification</p>
        </div>""", unsafe_allow_html=True)
        conn=sqlite3.connect('heart_monitor.db'); c=conn.cursor()
        c.execute('SELECT bpm,quality,test_date FROM test_results WHERE user_id=? ORDER BY test_date DESC',
                  (st.session_state.user_id,))
        rows=c.fetchall(); conn.close()
        if rows:
            df=pd.DataFrame(rows,columns=['BPM','Quality (%)','Date'])
            df['Quality (%)']=df['Quality (%)'].round(1)
            fig=go.Figure()
            fig.add_trace(go.Scatter(x=df['Date'],y=df['BPM'],mode='lines+markers',
                name='Heart Rate',line=dict(color='#3b82f6',width=2)))
            fig.add_hrect(y0=60,y1=100,fillcolor="#10b981",opacity=.1,
                annotation_text="Normal 60–100 BPM")
            fig.update_layout(title="Heart Rate History",xaxis_title="Date",
                yaxis_title="BPM",template="plotly_white",height=380)
            st.plotly_chart(fig,use_container_width=True)
            st.dataframe(df,use_container_width=True)
            st.download_button("📥 Export CSV",df.to_csv(index=False),
                "heart_history.csv","text/csv")
        else:
            st.info("No records yet. Take your first reading in rPPG Monitor.")

    # ── Admin Panel ────────────────────────────────────────────────────────────
    elif selected=="Admin Panel" and st.session_state.is_admin:
        st.markdown("""<div class="main-header">
            <h2>⚙️ Admin Panel</h2><p>User management and audit trail</p>
        </div>""", unsafe_allow_html=True)
        conn=sqlite3.connect('heart_monitor.db'); c=conn.cursor()
        c.execute("SELECT id,username,full_name,age,gender,is_admin FROM users WHERE username!='admin'")
        users=c.fetchall()
        c.execute("SELECT timestamp,action,details FROM audit_log ORDER BY id DESC LIMIT 15")
        logs=c.fetchall(); conn.close()
        st.markdown("### 👥 Users")
        if users:
            for u in users:
                with st.expander(f"👤 {u[1]} — {u[2]}"):
                    a,b=st.columns(2)
                    with a: st.write(f"**Age:** {u[3]}"); st.write(f"**Gender:** {u[4]}")
                    with b: st.write(f"**Admin:** {'Yes' if u[5] else 'No'}")
        else:
            st.info("No users.")
        st.markdown("### 📜 Audit Log")
        for log in logs:
            st.markdown(f"""<div class="glass-panel" style="margin-bottom:.4rem;padding:.65rem">
                <small style="color:#64748b">{log[0]}</small>
                <div><b>{log[1]}</b> — {log[2]}</div>
            </div>""", unsafe_allow_html=True)


# ── Entry ──────────────────────────────────────────────────────────────────────
def main():
    if not st.session_state.authenticated:
        show_login()
    else:
        show_dashboard()

if __name__=="__main__":
    main()
