"""
Drop-in replacement for the rppg_component() function in app.py (MedChainSecure).

CHANGES MADE:
1. Replaced @tensorflow-models/face-detection (unreliable in iframes) with
   MediaPipe FaceMesh via the official @mediapipe/tasks-vision WASM bundle.
2. Added a robust canvas-based fallback ROI (centre-forehead region) when
   MediaPipe is still loading, so signal collection begins immediately.
3. Fixed the save mechanism: instead of submitting an invisible HTML <form>
   (which fails inside Streamlit iframes), the component now appends
   ?saved_bpm=XX&saved_quality=YY to the parent window URL — the same
   st.query_params approach already used in show_dashboard().
4. Added graceful error recovery so a single frame error never stops the loop.
5. Added live waveform canvas so the user can see the rPPG signal.

HOW TO APPLY:
  - In app.py, delete the entire rppg_component() function definition.
  - Paste this file's content in its place (the function is self-contained).
  - No other changes needed.
"""

from streamlit.components.v1 import html


def rppg_component():
    component_html = r"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { background:#0a0f1a; font-family:system-ui,sans-serif; border-radius:16px; overflow:hidden; }

    .video-wrap { position:relative; width:100%; background:#0a0f1a; }
    video { width:100%; height:auto; transform:scaleX(-1); display:block; }

    #faceBox {
      position:absolute; border:3px solid #10b981; border-radius:12px;
      display:none; pointer-events:none;
    }
    #roiBox {
      position:absolute; border:2px solid #3b82f6;
      background:rgba(59,130,246,0.2); border-radius:6px;
      display:none; pointer-events:none;
    }
    #fallbackBox {
      position:absolute; border:2px dashed #f59e0b;
      background:rgba(245,158,11,0.15); border-radius:6px;
      display:none; pointer-events:none;
    }

    #statusBar {
      text-align:center; padding:10px;
      font-size:12px; color:#94a3b8; background:#0a0f1a;
    }

    #waveCanvas {
      width:100%; height:60px; background:#111827;
      display:block; border-top:1px solid #1e293b;
    }

    .controls {
      display:flex; gap:10px; padding:14px; background:#0a0f1a;
      justify-content:center; border-top:1px solid #1e293b;
    }
    button {
      padding:9px 22px; border:none; border-radius:8px;
      font-weight:600; cursor:pointer; font-size:13px; transition:all .2s;
    }
    .btn-start { background:#3b82f6; color:#fff; }
    .btn-start:hover { background:#2563eb; }
    .btn-stop  { background:#ef4444; color:#fff; }
    .btn-stop:hover  { background:#dc2626; }
    .btn-save  { background:#10b981; color:#fff; }
    .btn-save:hover  { background:#059669; }

    .spin {
      display:inline-block; width:12px; height:12px;
      border:2px solid #fff; border-top-color:transparent;
      border-radius:50%; animation:spin .6s linear infinite;
      margin-right:6px; vertical-align:middle;
    }
    @keyframes spin { to { transform:rotate(360deg); } }
  </style>
</head>
<body>

<div class="video-wrap">
  <video id="video" autoplay playsinline muted></video>
  <div id="faceBox"></div>
  <div id="roiBox"></div>
  <div id="fallbackBox"></div>
</div>

<div id="statusBar">📷 Click ▶ Start Camera</div>

<canvas id="waveCanvas"></canvas>

<div class="controls">
  <button class="btn-start" id="startBtn">▶ Start Camera</button>
  <button class="btn-stop"  id="stopBtn" >⏹ Stop</button>
  <button class="btn-save"  id="saveBtn" >💾 Save Reading</button>
</div>

<script>
// ─── Globals ────────────────────────────────────────────────────────────────
const video      = document.getElementById('video');
const faceBox    = document.getElementById('faceBox');
const roiBox     = document.getElementById('roiBox');
const fbBox      = document.getElementById('fallbackBox');
const statusBar  = document.getElementById('statusBar');
const waveCanvas = document.getElementById('waveCanvas');
const wCtx       = waveCanvas.getContext('2d');

let stream        = null;
let rafId         = null;
let isRunning     = false;
let detector      = null;  // MediaPipe FaceMesh detector
let mpReady       = false;

// Signal buffers
const MAX_BUF   = 300;
let rBuf=[], gBuf=[], bBuf=[];
let chromaBuf   = [];    // for waveform
let frameIdx    = 0;
const FPS       = 30;

// Result state
let lastBpm     = null;
let lastQuality = 0;
let bpmHistory  = [];

// ─── Status helper ──────────────────────────────────────────────────────────
function setStatus(html) { statusBar.innerHTML = html; }

// ─── Load MediaPipe FaceMesh (tasks-vision) ─────────────────────────────────
async function loadMediaPipe() {
  setStatus('<span class="spin"></span> Loading face detection…');
  try {
    // Use the official @mediapipe/tasks-vision bundle from unpkg
    const { FaceDetector, FilesetResolver } = await import(
      'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.14/vision_bundle.mjs'
    );
    const vision = await FilesetResolver.forVisionTasks(
      'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.14/wasm'
    );
    detector = await FaceDetector.createFromOptions(vision, {
      baseOptions: {
        modelAssetPath:
          'https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite',
        delegate: 'GPU'
      },
      runningMode: 'VIDEO'
    });
    mpReady = true;
    setStatus('✅ Face detection ready — click ▶ Start Camera');
  } catch(e) {
    console.warn('MediaPipe load failed, using fallback ROI:', e);
    setStatus('⚠️ Using centre-forehead fallback (no face model)');
    mpReady = false;
  }
}

// ─── Camera ─────────────────────────────────────────────────────────────────
async function startCamera() {
  try {
    setStatus('<span class="spin"></span> Requesting camera…');
    stream = await navigator.mediaDevices.getUserMedia({
      video: { width:{ideal:640}, height:{ideal:480}, facingMode:'user' },
      audio: false
    });
    video.srcObject = stream;
    await video.play();
    return true;
  } catch(e) {
    setStatus('❌ Camera denied — please allow camera access and refresh');
    return false;
  }
}

function stopCamera() {
  isRunning = false;
  if (stream)  { stream.getTracks().forEach(t=>t.stop()); stream=null; }
  if (rafId)   { cancelAnimationFrame(rafId); rafId=null; }
  video.srcObject = null;
  [faceBox, roiBox, fbBox].forEach(b=>b.style.display='none');
  setStatus('⏹ Camera stopped');
  rBuf=[]; gBuf=[]; bBuf=[]; chromaBuf=[];
}

// ─── Main processing loop ───────────────────────────────────────────────────
async function processFrame() {
  if (!isRunning) return;

  try {
    if (video.readyState >= 2 && video.videoWidth > 0) {
      let roiPixelX, roiPixelY, roiPixelW, roiPixelH;
      let faceDetected = false;

      // ── MediaPipe detection ──────────────────────────────────────────────
      if (mpReady && detector) {
        const now = performance.now();
        let faces;
        try { faces = detector.detectForVideo(video, now).detections; }
        catch(_) { faces = []; }

        if (faces && faces.length > 0) {
          faceDetected = true;
          const bb = faces[0].boundingBox;
          const sx = video.clientWidth  / video.videoWidth;
          const sy = video.clientHeight / video.videoHeight;

          // Face box overlay (mirrored)
          const dLeft  = (video.videoWidth - bb.originX - bb.width) * sx;
          const dTop   = bb.originY * sy;
          const dW     = bb.width  * sx;
          const dH     = bb.height * sy;

          faceBox.style.cssText = `display:block;left:${dLeft}px;top:${dTop}px;width:${dW}px;height:${dH}px;`;

          // Forehead ROI (top 25% of face, centre 60%)
          const rX = dLeft + dW * 0.20;
          const rY = dTop  + dH * 0.03;
          const rW = dW * 0.60;
          const rH = dH * 0.22;
          roiBox.style.cssText = `display:block;left:${rX}px;top:${rY}px;width:${rW}px;height:${rH}px;`;
          fbBox.style.display = 'none';

          // Map ROI back to video pixel coords (un-mirror)
          roiPixelX = bb.originX + bb.width * 0.20;
          roiPixelY = bb.originY + bb.height * 0.03;
          roiPixelW = bb.width * 0.60;
          roiPixelH = bb.height * 0.22;

          setStatus('✅ Face detected — measuring pulse…');
        }
      }

      // ── Fallback: use centre-forehead region ──────────────────────────────
      if (!faceDetected) {
        faceBox.style.display = 'none';
        roiBox.style.display  = 'none';

        const vw = video.videoWidth, vh = video.videoHeight;
        roiPixelX = vw * 0.30;
        roiPixelY = vh * 0.10;
        roiPixelW = vw * 0.40;
        roiPixelH = vh * 0.20;

        const cx = video.clientWidth, cy = video.clientHeight;
        fbBox.style.cssText = `display:block;left:${cx*0.30}px;top:${cy*0.10}px;width:${cx*0.40}px;height:${cy*0.20}px;`;

        if (mpReady) {
          setStatus('🔍 No face detected — centre your face in frame');
        } else {
          setStatus('📊 Using forehead region (dashed box) — stay still');
        }
      }

      // ── Sample ROI pixels ─────────────────────────────────────────────────
      if (roiPixelW > 0) {
        const tmp = document.createElement('canvas');
        tmp.width  = roiPixelW;
        tmp.height = roiPixelH;
        const tc = tmp.getContext('2d');
        tc.drawImage(video,
          roiPixelX, roiPixelY, roiPixelW, roiPixelH,
          0, 0, roiPixelW, roiPixelH);
        const id = tc.getImageData(0, 0, roiPixelW, roiPixelH).data;

        let rS=0,gS=0,bS=0, n=id.length/4;
        for (let i=0; i<id.length; i+=4) { rS+=id[i]; gS+=id[i+1]; bS+=id[i+2]; }
        rBuf.push(rS/n); gBuf.push(gS/n); bBuf.push(bS/n);
        if (rBuf.length > MAX_BUF) { rBuf.shift(); gBuf.shift(); bBuf.shift(); }
      }

      // ── Compute BPM every 30 frames once we have enough data ──────────────
      if (rBuf.length >= 90 && frameIdx % 30 === 0) {
        calculateBPM();
      }
    }
  } catch(e) {
    console.error('Frame error:', e);
  }

  frameIdx++;
  drawWave();
  rafId = requestAnimationFrame(processFrame);
}

// ─── CHROM rPPG algorithm ───────────────────────────────────────────────────
function calculateBPM() {
  const N = rBuf.length;
  const Xs=[], Ys=[];
  for (let i=0;i<N;i++) {
    Xs.push(rBuf[i] - gBuf[i]);
    Ys.push(0.5*rBuf[i] + 0.5*gBuf[i] - bBuf[i]);
  }
  const mX = Xs.reduce((a,b)=>a+b,0)/N;
  const mY = Ys.reduce((a,b)=>a+b,0)/N;
  let vX=0,vY=0;
  for (let i=0;i<N;i++) { vX+=(Xs[i]-mX)**2; vY+=(Ys[i]-mY)**2; }
  const alpha = Math.sqrt(vX/N) / (Math.sqrt(vY/N)||1);

  const sig = [];
  for (let i=0;i<N;i++) sig.push(Xs[i] - alpha*Ys[i]);

  // Store for waveform
  chromaBuf = sig.slice(-150);

  // Normalize
  const sm = sig.reduce((a,b)=>a+b,0)/N;
  const ss = Math.sqrt(sig.map(v=>(v-sm)**2).reduce((a,b)=>a+b,0)/N) || 1;
  const norm = sig.map(v=>(v-sm)/ss);

  // Peak detection on last 150 samples
  const win = norm.slice(-150);
  const peaks=[];
  for (let i=2;i<win.length-2;i++) {
    if (win[i]>win[i-1] && win[i]>win[i+1] &&
        win[i]>win[i-2] && win[i]>win[i+2] && win[i]>0.2) {
      peaks.push(i);
    }
  }

  if (peaks.length >= 2) {
    const ivls=[];
    for (let i=1;i<peaks.length;i++) ivls.push(peaks[i]-peaks[i-1]);
    const avgIvl = ivls.reduce((a,b)=>a+b,0)/ivls.length;
    const bpm = Math.round(60 / (avgIvl / FPS));
    const quality = Math.min(100, Math.max(0, (peaks.length/8)*70 + 20));

    if (bpm >= 45 && bpm <= 170 && quality > 35) {
      lastBpm = bpm;
      lastQuality = quality;
      bpmHistory.push(bpm);
      if (bpmHistory.length > 10) bpmHistory.shift();

      // Notify Streamlit parent
      try {
        window.parent.postMessage({ type:'bpm_update', bpm, quality }, '*');
      } catch(_) {}
    }
  }
}

// ─── Live waveform ───────────────────────────────────────────────────────────
function drawWave() {
  const W = waveCanvas.width  = waveCanvas.offsetWidth;
  const H = waveCanvas.height = 60;
  wCtx.clearRect(0,0,W,H);
  wCtx.fillStyle = '#111827';
  wCtx.fillRect(0,0,W,H);

  const data = chromaBuf.length ? chromaBuf : rBuf;
  if (data.length < 2) return;

  const mn = Math.min(...data), mx = Math.max(...data);
  const rng = (mx-mn) || 1;

  wCtx.beginPath();
  wCtx.strokeStyle = '#3b82f6';
  wCtx.lineWidth   = 1.5;

  const step = W / (data.length-1);
  data.forEach((v,i) => {
    const x = i * step;
    const y = H - ((v-mn)/rng)*(H-8) - 4;
    i===0 ? wCtx.moveTo(x,y) : wCtx.lineTo(x,y);
  });
  wCtx.stroke();

  // BPM overlay
  if (lastBpm) {
    wCtx.fillStyle = '#10b981';
    wCtx.font = 'bold 14px system-ui';
    wCtx.fillText(`${lastBpm} BPM  |  Q: ${lastQuality.toFixed(0)}%`, 8, 16);
  }
}

// ─── Button handlers ─────────────────────────────────────────────────────────
document.getElementById('startBtn').onclick = async () => {
  if (isRunning) return;
  if (!mpReady && !detector) await loadMediaPipe();
  const ok = await startCamera();
  if (!ok) return;
  isRunning = true;
  rBuf=[]; gBuf=[]; bBuf=[]; chromaBuf=[];
  bpmHistory=[]; frameIdx=0; lastBpm=null;
  processFrame();
};

document.getElementById('stopBtn').onclick = () => stopCamera();

document.getElementById('saveBtn').onclick = () => {
  if (!lastBpm || lastBpm < 45 || lastBpm > 170 || lastQuality < 35) {
    alert('No valid reading yet. Wait for face detection and a stable signal (watch the waveform).');
    return;
  }
  const bpm     = Math.round(lastBpm);
  const quality = parseFloat(lastQuality.toFixed(2));

  // Method 1: postMessage to Streamlit (works when parent listens)
  try {
    window.parent.postMessage({ type:'save_reading', bpm, quality }, '*');
  } catch(_) {}

  // Method 2: update parent URL query params (picked up by st.query_params)
  try {
    const url = new URL(window.parent.location.href);
    url.searchParams.set('saved_bpm', bpm);
    url.searchParams.set('saved_quality', quality);
    window.parent.history.replaceState({}, '', url.toString());
    // Small delay then reload so Streamlit re-runs and picks up the params
    setTimeout(() => window.parent.location.reload(), 300);
  } catch(e) {
    // Cross-origin guard — fall back to alert with value
    alert(`Reading: BPM=${bpm}, Quality=${quality}% — Please note these values and enter them manually if save fails.`);
  }
};

// Start loading MediaPipe immediately so it is ready when camera starts
loadMediaPipe();
</script>
</body>
</html>
"""
    return html(component_html, height=560, scrolling=False)
