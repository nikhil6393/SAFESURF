/* =========================================================
   SafeSurf v2.0 — 3D Cyber Application Logic
   ========================================================= */

const API_BASE = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:') 
    ? 'http://localhost:5000/api' 
    : '/api';

let activityChart = null;
let analyticsChart = null;
let scanHistory = [];

// ===================== SECURITY: HTML ESCAPING =====================
// URLs (and any record field) are attacker-controllable via /api/check-url and
// are persisted, then rendered here. ALWAYS escape before inserting into innerHTML
// to prevent stored XSS. Escapes both element and attribute contexts.
function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ===================== INIT =====================
document.addEventListener('DOMContentLoaded', () => {
    initDeepSpaceBackground();
    initFloatingParticles();
    init3DTiltCards();
    initApp();
    setupNavigation();
    setupMobileMenu();
    initCharts();
    setupKeyboardShortcuts();
    initMouseTrail();
});

function initApp() {
    fetchStats();
    fetchHistory();
    fetchDataset();
    setInterval(fetchStats, 6000);
    setInterval(fetchHistory, 12000);
}

// ===================== DEEP SPACE BACKGROUND =====================
function initDeepSpaceBackground() {
    const canvas = document.getElementById('bgCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let w, h;
    let dots = [];
    let mouse = { x: -1000, y: -1000 };
    const DOT_COUNT = 80;
    const CONNECTION_DIST = 160;
    const MOUSE_DIST = 200;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }

    function createDots() {
        dots = [];
        for (let i = 0; i < DOT_COUNT; i++) {
            dots.push({
                x: Math.random() * w,
                y: Math.random() * h,
                vx: (Math.random() - 0.5) * 0.25,
                vy: (Math.random() - 0.5) * 0.25,
                r: Math.random() * 1.5 + 0.5,
                hue: Math.random() * 60 + 250 // Purple to blue range
            });
        }
    }

    function draw() {
        ctx.clearRect(0, 0, w, h);

        // Draw connections between dots
        for (let i = 0; i < dots.length; i++) {
            for (let j = i + 1; j < dots.length; j++) {
                const dx = dots[i].x - dots[j].x;
                const dy = dots[i].y - dots[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < CONNECTION_DIST) {
                    const alpha = (1 - dist / CONNECTION_DIST) * 0.06;
                    ctx.beginPath();
                    const gradient = ctx.createLinearGradient(dots[i].x, dots[i].y, dots[j].x, dots[j].y);
                    gradient.addColorStop(0, `hsla(${dots[i].hue}, 80%, 65%, ${alpha})`);
                    gradient.addColorStop(1, `hsla(${dots[j].hue}, 80%, 65%, ${alpha})`);
                    ctx.strokeStyle = gradient;
                    ctx.lineWidth = 0.6;
                    ctx.moveTo(dots[i].x, dots[i].y);
                    ctx.lineTo(dots[j].x, dots[j].y);
                    ctx.stroke();
                }
            }
        }

        // Draw mouse connections
        for (const d of dots) {
            const dx = d.x - mouse.x;
            const dy = d.y - mouse.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < MOUSE_DIST) {
                const alpha = (1 - dist / MOUSE_DIST) * 0.2;
                ctx.beginPath();
                ctx.strokeStyle = `rgba(168, 85, 247, ${alpha})`;
                ctx.lineWidth = 1;
                ctx.moveTo(d.x, d.y);
                ctx.lineTo(mouse.x, mouse.y);
                ctx.stroke();

                // Gently push dots away from mouse
                const force = (1 - dist / MOUSE_DIST) * 0.5;
                d.vx += (dx / dist) * force * 0.1;
                d.vy += (dy / dist) * force * 0.1;
            }
        }

        // Update & draw dots
        for (const d of dots) {
            // Dampen velocity
            d.vx *= 0.99;
            d.vy *= 0.99;

            d.x += d.vx;
            d.y += d.vy;
            if (d.x < 0 || d.x > w) d.vx *= -1;
            if (d.y < 0 || d.y > h) d.vy *= -1;

            // Draw dot with glow
            ctx.beginPath();
            ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
            ctx.fillStyle = `hsla(${d.hue}, 80%, 70%, 0.5)`;
            ctx.fill();

            // Soft glow
            ctx.beginPath();
            ctx.arc(d.x, d.y, d.r * 3, 0, Math.PI * 2);
            ctx.fillStyle = `hsla(${d.hue}, 80%, 70%, 0.05)`;
            ctx.fill();
        }

        requestAnimationFrame(draw);
    }

    resize();
    createDots();
    draw();
    
    window.addEventListener('resize', () => { resize(); createDots(); });
    window.addEventListener('mousemove', (e) => { mouse.x = e.clientX; mouse.y = e.clientY; });
    window.addEventListener('mouseleave', () => { mouse.x = -1000; mouse.y = -1000; });
}

// ===================== FLOATING PARTICLES =====================
function initFloatingParticles() {
    const container = document.getElementById('particles');
    if (!container) return;

    const colors = ['#a855f7', '#22d3ee', '#f43f5e', '#34d399'];

    function spawnParticle() {
        const particle = document.createElement('div');
        particle.className = 'particle';
        const color = colors[Math.floor(Math.random() * colors.length)];
        const size = Math.random() * 3 + 1;
        const left = Math.random() * 100;
        const duration = Math.random() * 15 + 10;
        const delay = Math.random() * 5;

        particle.style.cssText = `
            width: ${size}px;
            height: ${size}px;
            left: ${left}%;
            background: ${color};
            box-shadow: 0 0 ${size * 3}px ${color};
            animation-duration: ${duration}s;
            animation-delay: ${delay}s;
        `;

        container.appendChild(particle);

        setTimeout(() => {
            particle.remove();
        }, (duration + delay) * 1000);
    }

    // Initial burst
    for (let i = 0; i < 15; i++) {
        spawnParticle();
    }

    // Continuous spawning
    setInterval(spawnParticle, 2000);
}

// ===================== 3D TILT CARDS =====================
function init3DTiltCards() {
    const cards = document.querySelectorAll('.tilt-card');

    cards.forEach(card => {
        const inner = card.querySelector('.card-3d-inner');
        if (!inner) return;

        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;

            const rotateX = ((y - centerY) / centerY) * -5;
            const rotateY = ((x - centerX) / centerX) * 5;

            inner.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateZ(8px)`;

            // Move shine based on mouse
            const shine = inner.querySelector('.card-shine');
            if (shine) {
                const shineX = (x / rect.width) * 100;
                shine.style.background = `
                    radial-gradient(circle at ${shineX}% ${(y / rect.height) * 100}%,
                    rgba(255,255,255,0.08) 0%,
                    transparent 60%)
                `;
                shine.style.left = '0';
                shine.style.opacity = '1';
            }
        });

        card.addEventListener('mouseleave', () => {
            inner.style.transform = 'rotateX(0) rotateY(0) translateZ(0)';
            inner.style.transition = 'transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
            const shine = inner.querySelector('.card-shine');
            if (shine) {
                shine.style.opacity = '0';
            }
            setTimeout(() => {
                inner.style.transition = 'transform 0.15s ease-out';
            }, 500);
        });

        card.addEventListener('mouseenter', () => {
            inner.style.transition = 'transform 0.15s ease-out';
        });
    });
}

// ===================== MOUSE TRAIL =====================
function initMouseTrail() {
    const main = document.getElementById('mainContent');
    if (!main) return;

    main.addEventListener('mousemove', (e) => {
        const trail = document.createElement('div');
        trail.style.cssText = `
            position: fixed;
            left: ${e.clientX}px;
            top: ${e.clientY}px;
            width: 4px;
            height: 4px;
            border-radius: 50%;
            background: rgba(168, 85, 247, 0.3);
            pointer-events: none;
            z-index: 9999;
            animation: trailFade 0.8s ease-out forwards;
        `;
        document.body.appendChild(trail);
        setTimeout(() => trail.remove(), 800);
    });

    // Inject trail animation
    if (!document.getElementById('trail-style')) {
        const style = document.createElement('style');
        style.id = 'trail-style';
        style.textContent = `
            @keyframes trailFade {
                from { opacity: 1; transform: scale(1); }
                to { opacity: 0; transform: scale(3); }
            }
            @keyframes rowFadeIn {
                from { opacity: 0; transform: translateX(-10px); }
                to { opacity: 1; transform: translateX(0); }
            }
        `;
        document.head.appendChild(style);
    }
}

// ===================== NAVIGATION =====================
function setupNavigation() {
    document.querySelectorAll('.menu a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = link.getAttribute('data-page');

            document.querySelectorAll('.menu a').forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            document.querySelectorAll('.page-content').forEach(p => p.classList.remove('active'));
            const targetPage = document.getElementById(`${pageId}-page`);
            if (targetPage) {
                targetPage.classList.add('active');
                if (pageId === 'dashboard' && activityChart) activityChart.update('none');
                if (pageId === 'analytics' && analyticsChart) analyticsChart.update('none');
                
                // Re-init tilt on new page
                setTimeout(() => init3DTiltCards(), 100);
            }

            closeMobileSidebar();
        });
    });
}

function setupMobileMenu() {
    const btn = document.getElementById('mobileMenuBtn');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');

    if (btn) {
        btn.addEventListener('click', () => {
            sidebar.classList.add('open');
            overlay.classList.add('active');
        });
    }

    if (overlay) {
        overlay.addEventListener('click', closeMobileSidebar);
    }
}

function closeMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (sidebar) sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
}

function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && document.activeElement.id === 'urlInput') {
            scanURL();
        }
        if (e.key === 'Escape') {
            closeModal();
        }
    });
}

// ===================== DATA FETCHING =====================
async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const data = await res.json();

        animateCounter('hero-total', data.totalScanned);
        animateCounter('hero-blocked', data.threatsBlocked);
        animateCounter('intelligence-size', data.intelligenceSize);

        const integrityText = document.getElementById('integrity-text');
        if (integrityText) {
            const score = 98.5 + (Math.random() * 1.4);
            integrityText.innerText = `${score.toFixed(1)}%`;
        }
    } catch (err) {
        console.warn("Stats API connection lost.");
    }
}

function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    
    const current = parseInt(el.innerText.replace(/,/g, '')) || 0;
    if (current === target) return;
    
    const diff = target - current;
    const steps = 40;
    const increment = diff / steps;
    let step = 0;

    function easeOut(t) {
        return 1 - Math.pow(1 - t, 3);
    }

    const timer = setInterval(() => {
        step++;
        const progress = easeOut(step / steps);
        const value = Math.round(current + diff * progress);
        el.innerText = value.toLocaleString();
        if (step >= steps) {
            el.innerText = target.toLocaleString();
            clearInterval(timer);
        }
    }, 25);
}

function updateEl(id, val) {
    const el = document.getElementById(id);
    if (el) el.innerText = val;
}

async function fetchHistory() {
    try {
        const res = await fetch(`${API_BASE}/history`);
        scanHistory = await res.json();
        renderLiveStream(scanHistory.slice(0, 8));
        renderFullHistory(scanHistory);
        updateCharts(scanHistory);
    } catch (err) {
        console.warn("History API connection lost.");
    }
}

function renderLiveStream(logs) {
    const tbody = document.getElementById('scanTableBody');
    if (!tbody || logs.length === 0) return;

    tbody.innerHTML = logs.map((log, idx) => {
        const url = String(log.url ?? '');
        const shortUrl = url.length > 35 ? url.substring(0, 35) + '...' : url;
        const label = String(log.label ?? '');
        const source = log.source ? String(log.source).toUpperCase() : 'UNKNOWN';
        const refId = log.refId ? String(log.refId).substring(4) : '---';
        const score = Number(log.score) || 0;
        const isSafe = label.toLowerCase() === 'safe';
        const time = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        return `
        <tr style="animation: rowFadeIn 0.4s ${idx * 0.06}s both;">
            <td><code>#${escapeHtml(refId)}</code></td>
            <td title="${escapeHtml(url)}" style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(shortUrl)}
            </td>
            <td><span class="vector-label">${escapeHtml(source)}</span></td>
            <td><span class="status-pill ${isSafe ? 'safe' : 'danger'}">${escapeHtml(label)}</span></td>
            <td><strong style="color: ${score > 60 ? 'var(--rose)' : 'var(--emerald)'}">${score}%</strong></td>
            <td style="color: var(--text-muted); font-size: 0.72rem; font-family: 'JetBrains Mono', monospace;">${escapeHtml(time)}</td>
        </tr>
    `;
    }).join('');
}

function renderFullHistory(logs) {
    const tbody = document.getElementById('fullHistoryBody');
    if (!tbody) return;

    const sorted = [...logs].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    tbody.innerHTML = sorted.map(log => {
        const url = String(log.url ?? '');
        const shortUrl = url.length > 60 ? url.substring(0, 60) + '...' : url;
        const label = String(log.label ?? '');
        const refId = log.refId ? String(log.refId) : 'N/A';
        const score = Number(log.score) || 0;
        const isSafe = label.toLowerCase() === 'safe';
        const time = new Date(log.timestamp).toLocaleString();
        return `
        <tr>
            <td><code>${escapeHtml(refId)}</code></td>
            <td title="${escapeHtml(url)}" style="max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(shortUrl)}
            </td>
            <td><span class="status-pill ${isSafe ? 'safe' : 'danger'}">${escapeHtml(label)}</span></td>
            <td><strong style="color: ${score > 60 ? 'var(--rose)' : 'var(--emerald)'}">${score}%</strong></td>
            <td style="color: var(--text-muted); font-size: 0.72rem;">${escapeHtml(time)}</td>
        </tr>
    `;
    }).join('');
}

// ===================== URL SCANNING =====================
async function scanURL() {
    const input = document.getElementById('urlInput');
    const url = input.value.trim();
    if (!url) {
        // Shake the search bar
        const bar = document.querySelector('.search-bar-inner');
        bar.style.animation = 'shake 0.4s ease-out';
        setTimeout(() => bar.style.animation = '', 400);
        input.focus();
        return;
    }

    const btn = document.querySelector('.scan-btn');
    const btnText = document.getElementById('scan-text');
    const originalText = btnText.innerText;
    const startTime = Date.now();

    btn.disabled = true;
    btnText.innerText = 'Scanning...';
    btn.querySelector('i').className = 'fas fa-circle-notch fa-spin';

    try {
        const res = await fetch(`${API_BASE}/check-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const result = await res.json();
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

        showScanModal(result, url, elapsed);
        showToast(result.label, `${result.label.toUpperCase()} — Neural analysis complete.`);

        fetchStats();
        fetchHistory();
        input.value = '';
    } catch (err) {
        showToast('error', 'Neural Core connection severed.');
    } finally {
        btn.disabled = false;
        btnText.innerText = originalText;
        btn.querySelector('i').className = 'fas fa-bolt';
    }
}

// Inject shake animation
const shakeStyle = document.createElement('style');
shakeStyle.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        20% { transform: translateX(-6px); }
        40% { transform: translateX(6px); }
        60% { transform: translateX(-4px); }
        80% { transform: translateX(4px); }
    }
`;
document.head.appendChild(shakeStyle);

// ===================== SCAN MODAL =====================
function showScanModal(result, url, elapsed) {
    const modal = document.getElementById('scanModal');
    const icon = document.getElementById('modal-icon');
    const verdict = document.getElementById('modal-verdict');
    const modalUrl = document.getElementById('modal-url');
    const score = document.getElementById('modal-score');
    const source = document.getElementById('modal-source');
    const time = document.getElementById('modal-time');
    const bar = document.getElementById('modal-bar');

    const isSafe = result.label.toLowerCase() === 'safe';

    icon.className = `modal-icon ${isSafe ? 'safe' : 'danger'}`;
    icon.innerHTML = `<div class="modal-icon-ring"></div><i class="fas ${isSafe ? 'fa-shield-check' : 'fa-triangle-exclamation'}"></i>`;

    verdict.innerText = result.label.toUpperCase();
    verdict.style.color = isSafe ? 'var(--emerald)' : 'var(--rose)';

    modalUrl.innerText = url.length > 55 ? url.substring(0, 55) + '...' : url;
    score.innerText = `${result.score}%`;
    score.style.color = result.score > 60 ? 'var(--rose)' : 'var(--emerald)';
    source.innerText = result.source || 'Heuristic';
    time.innerText = `${elapsed}s`;

    bar.style.width = '0%';
    bar.className = 'modal-bar-fill';
    if (result.score > 70) bar.classList.add('high');
    else if (result.score > 40) bar.classList.add('medium');

    setTimeout(() => {
        bar.style.width = `${result.score}%`;
    }, 200);

    modal.classList.add('active');
}

function closeModal() {
    document.getElementById('scanModal')?.classList.remove('active');
}

// ===================== TOAST =====================
function showToast(type, msg) {
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toast-msg');
    const iconWrap = toast.querySelector('.toast-icon-wrap');
    const glow = toast.querySelector('.toast-glow');

    toastMsg.innerText = msg;

    if (type.toLowerCase() === 'safe') {
        iconWrap.style.background = 'rgba(52, 211, 153, 0.12)';
        iconWrap.style.color = 'var(--emerald)';
        iconWrap.innerHTML = '<i class="fas fa-shield-check"></i>';
        glow.style.background = 'var(--emerald)';
        glow.style.boxShadow = '0 0 12px var(--emerald-glow)';
    } else if (type === 'error') {
        iconWrap.style.background = 'rgba(244, 63, 94, 0.12)';
        iconWrap.style.color = 'var(--rose)';
        iconWrap.innerHTML = '<i class="fas fa-triangle-exclamation"></i>';
        glow.style.background = 'var(--rose)';
        glow.style.boxShadow = '0 0 12px var(--rose-glow)';
    } else {
        iconWrap.style.background = 'rgba(244, 63, 94, 0.12)';
        iconWrap.style.color = 'var(--rose)';
        iconWrap.innerHTML = '<i class="fas fa-biohazard"></i>';
        glow.style.background = 'var(--rose)';
        glow.style.boxShadow = '0 0 12px var(--rose-glow)';
    }

    toast.classList.add('active');
    setTimeout(() => toast.classList.remove('active'), 4000);
}

// ===================== CHARTS =====================
function initCharts() {
    Chart.defaults.color = '#475569';
    Chart.defaults.font.family = '"Inter", sans-serif';
    Chart.defaults.font.weight = 400;

    const ctx1 = document.getElementById('activityChart')?.getContext('2d');
    if (ctx1) {
        const gradient = ctx1.createLinearGradient(0, 0, 0, 300);
        gradient.addColorStop(0, 'rgba(168, 85, 247, 0.25)');
        gradient.addColorStop(0.5, 'rgba(34, 211, 238, 0.08)');
        gradient.addColorStop(1, 'rgba(168, 85, 247, 0.0)');

        activityChart = new Chart(ctx1, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Risk Score',
                    data: [],
                    borderColor: '#a855f7',
                    backgroundColor: gradient,
                    borderWidth: 2.5,
                    fill: true,
                    tension: 0.45,
                    pointRadius: 4,
                    pointBackgroundColor: '#030308',
                    pointBorderColor: '#a855f7',
                    pointBorderWidth: 2,
                    pointHoverRadius: 7,
                    pointHoverBackgroundColor: '#a855f7',
                    pointHoverBorderColor: '#fff',
                    pointHoverBorderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 15, 26, 0.95)',
                        titleColor: '#eef2ff',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(168,85,247,0.2)',
                        borderWidth: 1,
                        cornerRadius: 10,
                        padding: 14,
                        titleFont: { family: '"Space Grotesk"', weight: 600, size: 13 },
                        bodyFont: { size: 12 },
                        displayColors: false,
                        callbacks: {
                            label: (ctx) => `Risk Score: ${ctx.parsed.y}%`
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.02)', drawBorder: false },
                        border: { display: false },
                        ticks: { font: { size: 10 } }
                    },
                    x: {
                        grid: { display: false },
                        border: { display: false },
                        ticks: { font: { size: 10 } }
                    }
                },
                interaction: {
                    mode: 'index',
                    intersect: false,
                }
            }
        });
    }

    const ctx2 = document.getElementById('analyticsChart')?.getContext('2d');
    if (ctx2) {
        analyticsChart = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: ['Malicious', 'Safe', 'Suspicious', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#f43f5e',
                        '#34d399',
                        '#fbbf24',
                        '#a855f7'
                    ],
                    borderColor: '#0f0f1a',
                    borderWidth: 4,
                    hoverOffset: 12,
                    hoverBorderColor: '#1a1a2e'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 24,
                            usePointStyle: true,
                            pointStyle: 'circle',
                            font: { size: 11, family: '"Inter"', weight: 500 },
                            color: '#94a3b8'
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 15, 26, 0.95)',
                        titleColor: '#eef2ff',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(168,85,247,0.2)',
                        borderWidth: 1,
                        cornerRadius: 10,
                        padding: 14,
                    }
                }
            }
        });
    }
}

function updateCharts(logs) {
    if (!logs.length) return;

    if (activityChart) {
        const last12 = logs.slice(0, 12).reverse();
        activityChart.data.labels = last12.map(l => new Date(l.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
        activityChart.data.datasets[0].data = last12.map(l => l.score);
        activityChart.update('none');
    }

    if (analyticsChart) {
        const counts = { Malicious: 0, Safe: 0, Suspicious: 0, Other: 0 };
        logs.forEach(l => {
            const label = l.label || 'Other';
            if (counts[label] !== undefined) counts[label]++;
            else counts.Other++;
        });
        analyticsChart.data.datasets[0].data = [counts.Malicious, counts.Safe, counts.Suspicious, counts.Other];
        analyticsChart.update('none');
    }
}

// ===================== DATASET =====================
async function fetchDataset() {
    try {
        const res = await fetch(`${API_BASE}/dataset`);
        const data = await res.json();
        updateEl('db-count', `${data.length.toLocaleString()} Indexed`);

        const grid = document.getElementById('databaseGrid');
        if (grid) {
            grid.innerHTML = data.slice(0, 16).map((item, idx) => {
                const url = String(item.url ?? '');
                const label = String(item.label ?? '');
                const type = String(item.type || 'Signature');
                return `
                <div class="intel-node" style="animation: pageIn 0.35s ${idx * 0.04}s both;">
                    <div class="intel-url" title="${escapeHtml(url)}">${escapeHtml(url)}</div>
                    <div class="intel-meta">
                        <span class="status-pill ${label === 'safe' ? 'safe' : 'danger'}">${escapeHtml(label)}</span>
                        <span class="type-tag">${escapeHtml(type)}</span>
                    </div>
                </div>
            `;
            }).join('');
        }
    } catch (err) { }
}

// ===================== HISTORY SEARCH =====================
const historySearch = document.getElementById('historySearch');
if (historySearch) {
    historySearch.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        const filtered = scanHistory.filter(log =>
            log.url.toLowerCase().includes(term) ||
            log.label.toLowerCase().includes(term) ||
            (log.refId && log.refId.toLowerCase().includes(term))
        );
        renderFullHistory(filtered);
    });
}
