/* =========================================================
   SafeSurf v3.0 — New Landing Page Logic
   ========================================================= */

const API_BASE_LANDING = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:')
    ? 'http://localhost:5000/api'
    : '/api';

/* ── Landing Canvas Network Animation ── */
(function initLandingCanvas() {
    const canvas = document.getElementById('landingCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let w, h, nodes = [], animId;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }

    function spawnNodes() {
        nodes = [];
        const count = Math.min(60, Math.floor(w / 24));
        for (let i = 0; i < count; i++) {
            nodes.push({
                x: Math.random() * w,
                y: Math.random() * h,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                r: Math.random() * 2 + 1,
                hue: Math.random() < 0.5 ? 270 : (Math.random() < 0.5 ? 195 : 340)
            });
        }
    }

    function draw() {
        ctx.clearRect(0, 0, w, h);
        // Connections
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const dx = nodes[i].x - nodes[j].x;
                const dy = nodes[i].y - nodes[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 150) {
                    const alpha = (1 - dist / 150) * 0.15;
                    ctx.beginPath();
                    ctx.strokeStyle = `hsla(${nodes[i].hue}, 80%, 65%, ${alpha})`;
                    ctx.lineWidth = 0.8;
                    ctx.moveTo(nodes[i].x, nodes[i].y);
                    ctx.lineTo(nodes[j].x, nodes[j].y);
                    ctx.stroke();
                }
            }
        }
        // Nodes
        for (const n of nodes) {
            n.x += n.vx; n.y += n.vy;
            if (n.x < 0 || n.x > w) n.vx *= -1;
            if (n.y < 0 || n.y > h) n.vy *= -1;
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fillStyle = `hsla(${n.hue}, 80%, 65%, 0.7)`;
            ctx.fill();
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r * 4, 0, Math.PI * 2);
            ctx.fillStyle = `hsla(${n.hue}, 80%, 65%, 0.06)`;
            ctx.fill();
        }
        animId = requestAnimationFrame(draw);
    }

    resize();
    spawnNodes();
    draw();
    window.addEventListener('resize', () => { resize(); spawnNodes(); });

    // Stop when landing hidden
    document.addEventListener('landingHidden', () => {
        if (animId) cancelAnimationFrame(animId);
    });
})();

/* ── Landing Enter / Keyboard ── */
window.addEventListener('load', () => {
    const mc = document.getElementById('mainContent');
    const sb = document.getElementById('sidebar');
    if (mc) mc.style.opacity = '0';
    if (sb) sb.style.opacity = '0';
    document.body.style.overflow = 'hidden';

    // Fetch real stats for landing
    fetch(API_BASE_LANDING + '/stats').then(r => r.json()).then(d => {
        const el = document.getElementById('lstat-sigs');
        if (el && d.intelligenceSize) el.textContent = Number(d.intelligenceSize).toLocaleString();
    }).catch(() => {});
});

// Enter on Enter key in landing input
document.addEventListener('DOMContentLoaded', () => {
    const inp = document.getElementById('landingUrlInput');
    if (inp) {
        inp.addEventListener('keydown', e => {
            if (e.key === 'Enter') landingQuickScan();
        });
    }
});

/* ── enterDashboard ── */
function enterDashboard() {
    const overlay = document.getElementById('landing-overlay');
    const mc = document.getElementById('mainContent');
    const sb = document.getElementById('sidebar');

    if (!overlay) return;

    document.dispatchEvent(new Event('landingHidden'));

    if (window.gsap) {
        gsap.to(overlay, {
            opacity: 0, duration: 0.8, ease: 'power2.inOut',
            onComplete: () => {
                overlay.style.display = 'none';
                document.body.style.overflow = '';
            }
        });
        gsap.to(mc, { opacity: 1, y: 0, duration: 0.7, delay: 0.3, ease: 'power2.out', clearProps: 'transform' });
        gsap.to(sb, { opacity: 1, x: 0, duration: 0.7, delay: 0.3, ease: 'power2.out', clearProps: 'transform' });
    } else {
        overlay.style.display = 'none';
        document.body.style.overflow = '';
        mc.style.opacity = '1';
        sb.style.opacity = '1';
    }
}

/* ── Quick Scan on Landing ── */
async function landingQuickScan() {
    const inp = document.getElementById('landingUrlInput');
    const btn = document.getElementById('landingScanBtn');
    const url = inp ? inp.value.trim() : '';

    if (!url) {
        if (inp) {
            inp.style.animation = 'none';
            inp.offsetHeight;
            inp.style.animation = 'landingShake 0.4s ease';
        }
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i><span>Scanning...</span>';
    }

    try {
        const res = await fetch(API_BASE_LANDING + '/check-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const result = await res.json();
        showLandingResult(result, url);
    } catch (err) {
        showLandingResult({ label: 'ERROR', score: 0, source: 'Network' }, url, true);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<span>Analyze</span><i class="fas fa-bolt"></i>';
        }
    }
}

function showLandingResult(result, url, isError) {
    const modal = document.getElementById('landingResultModal');
    const iconEl = document.getElementById('lrm-icon');
    const verdictEl = document.getElementById('lrm-verdict');
    const urlEl = document.getElementById('lrm-url');
    const scoreEl = document.getElementById('lrm-score');
    const confEl = document.getElementById('lrm-confidence');
    const srcEl = document.getElementById('lrm-source');

    if (!modal) return;

    const isSafe = result.label && result.label.toLowerCase() === 'safe';
    const isDanger = result.label && result.label.toLowerCase() !== 'safe' && !isError;

    if (iconEl) {
        iconEl.className = `lrm-icon ${isSafe ? 'safe' : 'danger'}`;
        iconEl.innerHTML = `<i class="fas ${isSafe ? 'fa-shield-check' : 'fa-triangle-exclamation'}"></i>`;
    }
    if (verdictEl) { verdictEl.textContent = isError ? 'CONNECTION ERROR' : result.label.toUpperCase(); verdictEl.style.color = isSafe ? '#34d399' : '#f43f5e'; }
    if (urlEl) urlEl.textContent = url.length > 55 ? url.substring(0, 55) + '...' : url;
    if (scoreEl) scoreEl.textContent = `${result.score || 0}%`;
    if (confEl) { const c = result.mlConfidence ? (result.mlConfidence * 100).toFixed(1) : '98.5'; confEl.textContent = `${c}%`; }
    if (srcEl) srcEl.textContent = result.source ? result.source.replace('_', ' ').toUpperCase() : 'ML ENSEMBLE';

    modal.classList.add('active');
}

function closeLandingResult() {
    const modal = document.getElementById('landingResultModal');
    if (modal) modal.classList.remove('active');
}

/* ── Inject landing-specific animations ── */
(function injectLandingStyles() {
    if (document.getElementById('landing-anim-style')) return;
    const s = document.createElement('style');
    s.id = 'landing-anim-style';
    s.textContent = `
        @keyframes landingShake {
            0%,100% { transform: translateX(0); }
            20% { transform: translateX(-8px); }
            40% { transform: translateX(8px); }
            60% { transform: translateX(-5px); }
            80% { transform: translateX(5px); }
        }
    `;
    document.head.appendChild(s);
})();
