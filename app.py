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

st.set_page_config(page_title="MedChainSecure", page_icon="❤️", layout="wide")

st.markdown("""<style>
:root{--bg:#f8fafc;--card:#fff;--txt:#1e293b;--muted:#64748b;--border:#e2e8f0}
.stApp{background:var(--bg)}
.main-header{background:linear-gradient(135deg,#fff,#f1f5f9);padding:2rem;border-radius:1rem;margin-bottom:2rem;border:1px solid var(--border);text-align:center;}
.main-header h1,.main-header h2{font-size:2rem;background:linear-gradient(135deg,#3b82f6,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.glass-panel{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1rem;}
.metric-card{background:var(--card);border-radius:.75rem;padding:1.25rem;border:1px solid var(--border);text-align:center;}
.stat-value{font-size:2rem;font-weight:700;color:var(--txt)}
.chain-block{background:linear-gradient(135deg,#1e293b,#0f172a);border-radius:.75rem;padding:1rem;margin-bottom:.5rem;color:#e2e8f0;font-family:'Courier New',monospace;font-size:.72rem;border:1px solid #334155}
</style>""", unsafe_allow_html=True)

# Database Setup
DB_PATH = Path("/tmp/heart_monitor.db").resolve()

def get_db_connection():
    return sqlite3.connect(str(DB_PATH))

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,full_name TEXT,age INTEGER,gender TEXT,is_admin BOOLEAN DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS test_results(id INTEGER PRIMARY KEY,user_id INTEGER,bpm INTEGER,quality REAL,encrypted_hex TEXT,key_hex TEXT,ecc_public_key TEXT,blockchain_hash TEXT,test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,user_id INTEGER,action TEXT,timestamp TIMESTAMP,details TEXT,previous_hash TEXT,current_hash TEXT)''')
    
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        pw_hash = bcrypt.hashpw(b'Admin@123', bcrypt.gensalt(12))
        c.execute("INSERT INTO users(username,password_hash,full_name,age,gender,is_admin) VALUES(?,?,?,?,?,1)", 
                  ('admin', pw_hash, 'System Administrator', 30, 'Male'))
    conn.commit()
    conn.close()

init_db()

# Session State
for k in ['authenticated', 'user_id', 'username', 'is_admin', 'saved_bpm', 'saved_quality', 'last_enc']:
    if k not in st.session_state:
        st.session_state[k] = False if k == 'authenticated' else None

# RPPG_HTML and RELAY_SCRIPT (same as your original)
RPPG_HTML = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:#0d1117;font-family:system-ui,sans-serif;overflow:hidden}
#root{display:flex;flex-direction:column;height:100vh}
#vWrap{position:relative;background:#000;flex-shrink:0}
#video{width:100%;display:block;transform:scaleX(-1);max-height:240px;object-fit:cover}
#oc{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
#bpmRow{display:flex;align-items:center;gap:10px;padding:6px 12px;background:#0d1117;border-top:1px solid #1e293b;flex-shrink:0}
#bpmNum{font-size:2.2rem;font-weight:900;color:#10b981;line-height:1;letter-spacing:-1px;min-width:65px}
#bpmLbl{font-size:.6rem;color:#475569;align-self:flex-end;padding-bottom:3px}
#qWrap{flex:1}
#qLbl{font-size:.58rem;color:#475569;margin-bottom:2px}
#qBar{height:4px;background:#1e293b;border-radius:2px;overflow:hidden}
#qFill{height:100%;width:0%;background:#3b82f6;border-radius:2px;transition:width .4s}
#catBadge{font-size:.62rem;font-weight:700;padding:2px 8px;border-radius:20px;background:#1e293b;color:#94a3b8;white-space:nowrap}
#wc{width:100%;height:46px;display:block;background:#0d1117;flex-shrink:0;border-top:1px solid #1e293b}
#sb{font-size:10px;color:#64748b;background:#0d1117;padding:4px 10px;text-align:center;flex-shrink:0;border-top:1px solid #1e293b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#ctrl{display:flex;gap:7px;padding:8px 10px;background:#0d1117;border-top:1px solid #1e293b;flex-shrink:0}
button{flex:1;padding:7px 4px;border:none;border-radius:7px;font-weight:700;cursor:pointer;font-size:11px}
#startBtn{background:#3b82f6;color:#fff}#startBtn:hover{background:#2563eb}
#stopBtn{background:#1e293b;color:#64748b}#stopBtn:hover{background:#ef4444;color:#fff}
#saveBtn{background:#10b981;color:#fff}#saveBtn:hover{background:#059669}
#saveBtn:disabled{background:#1e293b;color:#374151;cursor:not-allowed}
#toast{position:fixed;bottom:60px;left:50%;transform:translateX(-50%) translateY(10px);
  background:#10b981;color:#fff;padding:6px 16px;border-radius:7px;font-size:11px;
  font-weight:700;opacity:0;transition:all .3s;pointer-events:none;white-space:nowrap;z-index:99}
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
    <div id="bpmNum">--</div><div id="bpmLbl">BPM</div>
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
  <div id="toast">✅ Reading saved!</div>
</div>
<script>
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
 
let stream=null,rafId=null,running=false;
let rBuf=[],gBuf=[],bBuf=[],chBuf=[];
let frameN=0,FPS=30,lastBpm=null,lastQ=0,savedOnce=false;
const sc=document.createElement('canvas');
const sctx=sc.getContext('2d',{willReadFrequently:true});
 
const TW=80,TH=60;
const tc=document.createElement('canvas');
tc.width=TW;tc.height=TH;
const tctx=tc.getContext('2d',{willReadFrequently:true});
function isSkin(r,g,b){
  if(r<45||g<40||b<20)return false;
  if(Math.max(r,g,b)-Math.min(r,g,b)<15)return false;
  if(r<=g||r<=b)return false;
  const Cb=128-0.16874*r-0.33126*g+0.5*b;
  const Cr=128+0.5*r-0.41869*g-0.08131*b;
  return Cb>=77&&Cb<=127&&Cr>=133&&Cr<=173;
}
function findSkinRegion(){
  tctx.drawImage(video,0,0,TW,TH);
  const d=tctx.getImageData(0,0,TW,TH).data;
  let x0=TW,x1=0,y0=TH,y1=0,hit=false;
  for(let y=0;y<TH;y++)for(let x=0;x<TW;x++){
    const i=(y*TW+x)*4;
    if(isSkin(d[i],d[i+1],d[i+2])){
      if(x<x0)x0=x;if(x>x1)x1=x;if(y<y0)y0=y;if(y>y1)y1=y;hit=true;
    }
  }
  if(!hit)return null;
  const p=2;
  return{x:Math.max(0,x0-p)/TW,y:Math.max(0,y0-p)/TH,
         w:Math.min(TW,x1-x0+p*2)/TW,h:Math.min(TH,y1-y0+p*2)/TH};
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
    octx.fillText('Face detected',fx+4,fy+12);
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
    octx.fillText(fallback?'Forehead ROI (auto)':'Forehead ROI',rx+3,ry+11);
  }
}
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
  if(bpm>=45&&bpm<=170&&q>25){
    lastBpm=bpm;lastQ=q;savedOnce=false;
    bpmNum.textContent=bpm;
    qFill.style.width=q.toFixed(0)+'%';
    let cat='Normal',col='#10b981';
    if(bpm<60){cat='Bradycardia';col='#f59e0b';}
    else if(bpm>100){cat='Tachycardia';col='#ef4444';}
    catBadge.textContent=cat;catBadge.style.color=col;bpmNum.style.color=col;
    saveBtn.disabled=false;
  }
}
function drawWave(){
  const W=wc.width=wc.offsetWidth,H=wc.height=46;
  wctx.fillStyle='#0d1117';wctx.fillRect(0,0,W,H);
  const data=chBuf.length?chBuf:gBuf.slice(-150);
  if(data.length<2)return;
  const mn=Math.min(...data),mx=Math.max(...data),rng=(mx-mn)||1;
  wctx.beginPath();wctx.strokeStyle='#3b82f6';wctx.lineWidth=1.5;
  const step=W/(data.length-1);
  data.forEach((v,i)=>{
    const x=i*step,y=H-((v-mn)/rng)*(H-6)-3;
    i===0?wctx.moveTo(x,y):wctx.lineTo(x,y);
  });
  wctx.stroke();
  if(lastBpm){
    wctx.fillStyle='#10b981';wctx.font='bold 10px system-ui';
    wctx.fillText(lastBpm+' BPM  Q:'+lastQ.toFixed(0)+'%',5,13);
  }
}
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
      }else face=emaFace;
      let roiN;
      if(face&&skinMiss<10){
        roiN={x:face.x+face.w*.20,y:face.y+face.h*.02,w:face.w*.60,h:face.h*.23};
        drawBoxes(face,roiN,false);
        sb.textContent='✅ Face detected — measuring pulse…';
      }else{
        fallback=true;
        roiN={x:.30,y:.08,w:.40,h:.20};
        drawBoxes(null,{x:.30,y:.08,w:.40,h:.20},true);
        sb.textContent=skinMiss>0&&skinMiss<20
          ?'🔍 Locating face — ensure good even lighting…'
          :'📊 Using forehead region — keep face centred & well-lit';
      }
      sampleRegion(roiN.x,roiN.y,roiN.w,roiN.h);
      if(rBuf.length>=90&&frameN%30===0)computeBPM();
    }
  }catch(e){console.warn(e);}
  frameN++;drawWave();
  rafId=requestAnimationFrame(loop);
}
async function startCam(){
  try{
    sb.textContent='Requesting camera access…';
    stream=await navigator.mediaDevices.getUserMedia(
      {video:{width:{ideal:640},height:{ideal:480},facingMode:'user'},audio:false});
    video.srcObject=stream;
    await video.play();
    return true;
  }catch(e){sb.textContent='❌ Camera denied — allow camera then refresh';return false;}
}
function stopAll(){
  running=false;
  if(rafId){cancelAnimationFrame(rafId);rafId=null;}
  if(stream){stream.getTracks().forEach(t=>t.stop());stream=null;}
  video.srcObject=null;
  octx.clearRect(0,0,oc.width,oc.height);
  rBuf=[];gBuf=[];bBuf=[];chBuf=[];emaFace=null;skinMiss=0;
  lastBpm=null;lastQ=0;savedOnce=false;
  bpmNum.textContent='--';qFill.style.width='0%';
  catBadge.textContent='Stopped';saveBtn.disabled=true;
  sb.textContent='⏹ Camera stopped';
}
document.getElementById('startBtn').onclick=async()=>{
  if(running)return;
  const ok=await startCam();if(!ok)return;
  running=true;rBuf=[];gBuf=[];bBuf=[];chBuf=[];
  emaFace=null;skinMiss=0;frameN=0;lastBpm=null;lastQ=0;savedOnce=false;
  loop();
};
document.getElementById('stopBtn').onclick=()=>stopAll();
 
// ── Save: post message to parent Streamlit window ─────────────────────────────
saveBtn.onclick=()=>{
  if(savedOnce){sb.textContent='✅ Saved — press Stop then Start for a new reading';return;}
  if(!lastBpm||lastQ<25){
    alert('No valid reading yet.\n\nTips:\n• Even frontal lighting\n• Stay still 10–15 s\n• Watch for a repeating wave');
    return;
  }
  savedOnce=true;
  saveBtn.disabled=true;
  saveBtn.textContent='✅ Saved!';
  // Send to Streamlit parent via postMessage — relay script (outside iframe) catches this
  window.parent.postMessage(
    {type:'rppg:save', bpm:Math.round(lastBpm), quality:parseFloat(lastQ.toFixed(2))},
    '*'
  );
  toast.textContent='✅ BPM '+Math.round(lastBpm)+' — scroll up!';
  toast.classList.add('show');
  setTimeout(()=>toast.classList.remove('show'),3000);
  sb.textContent='✅ Reading sent — scroll up to see encryption results';
};
</script>
</body>
</html>"""

RELAY_SCRIPT = """<script>(function(){window.addEventListener('message', function(e){if(e.data&&e.data.type==='rppg:save'){const url=new URL(window.location.href);url.searchParams.set('rppg_bpm',e.data.bpm);url.searchParams.set('rppg_q',e.data.quality);window.location.href=url.toString();}});})();</script>"""

# Helper Functions (add_audit_log, do_encrypt_and_save) - same as before
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
    # ... (your original do_encrypt_and_save function)
    # I'll keep it short here - use your original version
    ts = datetime.now().isoformat()
    # [Paste your full do_encrypt_and_save function here]
    # Return the enc dictionary
    pass  # Replace with your full function

# ================== FULL SHOW_DASHBOARD ==================
def show_dashboard():
    with st.sidebar:
        st.title("❤️ MedChainSecure")
        pages = ["Dashboard", "rPPG Monitor", "Health History"]
        if st.session_state.is_admin:
            pages.append("Admin Panel")
        selected = st.radio("Navigation", pages, label_visibility="collapsed")

        st.divider()
        st.write(f"**{st.session_state.username}**")
        st.caption("Admin" if st.session_state.is_admin else "Patient")

        if st.button("Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

    if selected == "Dashboard":
        st.markdown('<div class="main-header"><h1>Welcome back, ' + st.session_state.username + '</h1></div>', unsafe_allow_html=True)
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM test_results WHERE user_id=?", (st.session_state.user_id,))
        total = c.fetchone()[0]
        c.execute("SELECT AVG(bpm) FROM test_results WHERE user_id=?", (st.session_state.user_id,))
        avg = c.fetchone()[0] or 0
        conn.close()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Readings", total)
        col2.metric("Average BPM", f"{avg:.1f}")
        col3.metric("Security", "AES-256 + Blockchain")

        st.info("Go to **rPPG Monitor** to take a new heart rate reading.")

    elif selected == "rPPG Monitor":
        st.markdown('<div class="main-header"><h2>📹 rPPG Heart Rate Monitor</h2></div>', unsafe_allow_html=True)
        
        with st.expander("📋 Tips for Accurate Reading"):
            st.markdown("- Good lighting on your face\n- Stay still for 15 seconds\n- Look directly at camera")

        col1, col2, col1 = st.columns([1,3,1])
        with col2:
            components.html(RPPG_HTML, height=520, scrolling=False)
            components.html(RELAY_SCRIPT, height=0)

        # Handle reading from query params
        params = st.query_params
        if "rppg_bpm" in params and "rppg_q" in params:
            try:
                bpm = int(params["rppg_bpm"])
                quality = float(params["rppg_q"])
                if st.session_state.saved_bpm != bpm:
                    with st.spinner("Encrypting & Saving to Blockchain..."):
                        enc = do_encrypt_and_save(bpm, quality)
                        st.session_state.last_enc = enc
                        st.session_state.saved_bpm = bpm
                        st.session_state.saved_quality = quality
                    st.success(f"✅ Reading saved! BPM: {bpm}")
                    st.query_params.clear()
                    st.rerun()
            except:
                pass

        if st.session_state.last_enc:
            st.success("Record Saved Successfully!")
            # Call show_encryption_and_chain(st.session_state.last_enc)

    elif selected == "Health History":
        st.markdown('<div class="main-header"><h2>📋 Health History</h2></div>', unsafe_allow_html=True)
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT bpm, quality, blockchain_hash, test_date FROM test_results WHERE user_id=? ORDER BY test_date DESC", 
                  (st.session_state.user_id,))
        rows = c.fetchall()
        conn.close()

        if rows:
            df = pd.DataFrame(rows, columns=['BPM', 'Quality (%)', 'Block Hash', 'Date'])
            df['Quality (%)'] = df['Quality (%)'].round(1)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df['Date'], y=df['BPM'], mode='lines+markers', name='Heart Rate'))
            fig.update_layout(title="Heart Rate Trend", height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No readings yet. Take your first reading in **rPPG Monitor**.")

    elif selected == "Admin Panel":
        st.header("Admin Panel")
        # Add your admin code here if needed

def main():
    if not st.session_state.authenticated:
        # Paste your show_login() function here
        st.title("MedChainSecure Login")
        # ... your login code
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
