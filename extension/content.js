// SafeSurf Content Script - Warning Overlay
console.log("SafeSurf Content Script Loaded");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_WARNING") {
        createWarningOverlay(request.data);
    }
});

function createWarningOverlay(data) {
    data = data || {};
    // Check if overlay already exists
    if (document.getElementById('safesurf-warning-overlay')) return;

    // Create shadow DOM container to isolate styles
    const container = document.createElement('div');
    container.id = 'safesurf-warning-overlay';

    // Styling for container to ensure it covers everything
    container.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        z-index: 2147483647;
        pointer-events: auto;
    `;

    const shadow = container.attachShadow({ mode: 'open' });

    // Overlay HTML
    const overlayHTML = `
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Outfit:wght@400;600&display=swap');
            
            :host {
                font-family: 'Outfit', sans-serif;
            }
            .overlay {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                width: 100%;
                height: 100%;
                background: radial-gradient(circle, rgba(20, 10, 10, 0.95) 0%, rgba(3, 0, 0, 0.98) 100%);
                backdrop-filter: blur(10px);
                color: #fff;
            }
            .card {
                background: rgba(20, 5, 5, 0.7);
                border: 1px solid rgba(244, 63, 94, 0.3);
                border-radius: 20px;
                padding: 50px;
                max-width: 650px;
                text-align: center;
                box-shadow: 0 0 80px rgba(244, 63, 94, 0.2), inset 0 0 30px rgba(244, 63, 94, 0.05);
                backdrop-filter: blur(25px);
                position: relative;
                overflow: hidden;
            }
            /* Tech Corners */
            .card::before {
                content: '';
                position: absolute;
                top: 0; left: 0;
                width: 40px; height: 40px;
                border-top: 3px solid #f43f5e;
                border-left: 3px solid #f43f5e;
            }
            .card::after {
                content: '';
                position: absolute;
                bottom: 0; right: 0;
                width: 40px; height: 40px;
                border-bottom: 3px solid #f43f5e;
                border-right: 3px solid #f43f5e;
            }
            
            h1 {
                font-family: 'Orbitron', sans-serif;
                font-size: 36px;
                color: #f43f5e;
                margin-bottom: 20px;
                text-transform: uppercase;
                letter-spacing: 3px;
                text-shadow: 0 0 20px rgba(244, 63, 94, 0.6);
            }
            .icon {
                font-size: 80px;
                color: #f43f5e;
                margin-bottom: 30px;
                animation: pulse-icon 2s infinite;
                filter: drop-shadow(0 0 20px rgba(244, 63, 94, 0.6));
            }
            @keyframes pulse-icon {
                0% { transform: scale(1); opacity: 1; }
                50% { transform: scale(1.1); opacity: 0.8; }
                100% { transform: scale(1); opacity: 1; }
            }
            p {
                font-size: 18px;
                color: #cbd5e1;
                margin-bottom: 40px;
                line-height: 1.6;
                font-weight: 500;
            }
            .reasons {
                background: rgba(244, 63, 94, 0.1);
                border-left: 3px solid #f43f5e;
                padding: 20px;
                border-radius: 0 12px 12px 0;
                margin-bottom: 40px;
                text-align: left;
            }
            .reasons ul {
                margin: 10px 0 0 0;
                padding-left: 20px;
            }
            .reasons li {
                color: #fda4af;
                margin-bottom: 8px;
            }
            .actions {
                display: flex;
                gap: 24px;
                justify-content: center;
            }
            button {
                padding: 16px 36px;
                border-radius: 12px;
                font-size: 16px;
                font-family: 'Orbitron', sans-serif;
                font-weight: 700;
                letter-spacing: 1px;
                cursor: pointer;
                transition: all 0.3s;
                text-transform: uppercase;
                border: none;
            }
            button:active {
                transform: scale(0.95);
            }
            .btn-safety {
                background: #f43f5e;
                color: #fff;
                box-shadow: 0 0 30px rgba(244, 63, 94, 0.4);
            }
            .btn-safety:hover {
                background: #e11d48;
                box-shadow: 0 0 50px rgba(244, 63, 94, 0.6);
                transform: translateY(-2px);
            }
            .btn-proceed {
                background: transparent;
                border: 1px solid rgba(255, 255, 255, 0.2);
                color: #94a3b8;
            }
            .btn-proceed:hover {
                color: #fff;
                border-color: #fff;
                background: rgba(255, 255, 255, 0.05);
            }
        </style>
        <div class="overlay">
            <div class="card">
                <div class="icon">
                     <svg width="80" height="80" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                    </svg>
                </div>
                <h1>Hologram Shield Active</h1>
                <p>Access blocked. This node has been identified as a critical security threat to the network.</p>
                
                <div class="reasons">
                    <strong style="color: #fff; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 1px;">Threat Vectors Detected:</strong>
                    <ul id="safesurf-reason-list"></ul>
                </div>

                <div class="actions">
                    <button class="btn-safety" id="back-btn">Return to Safety</button>
                    <button class="btn-proceed" id="proceed-btn">Proceed (Unsafe)</button>
                </div>
            </div>
        </div>
    `;

    shadow.innerHTML = overlayHTML;
    document.body.appendChild(container);

    // Populate reasons safely via textContent (never innerHTML) — this overlay runs
    // on every page, so unescaped interpolation here would be XSS on any visited site.
    const reasonList = shadow.getElementById('safesurf-reason-list');
    if (reasonList && Array.isArray(data.reasons)) {
        data.reasons.forEach(r => {
            const li = document.createElement('li');
            li.textContent = String(r);
            reasonList.appendChild(li);
        });
    }

    // Event Listeners
    shadow.getElementById('back-btn').addEventListener('click', () => {
        window.history.back();
        setTimeout(() => window.close(), 500); // Try closing if back fails
    });

    shadow.getElementById('proceed-btn').addEventListener('click', () => {
        container.remove();
    });
}
