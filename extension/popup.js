// SafeSurf Hologram Engine
document.addEventListener('DOMContentLoaded', () => {
    const scoreText = document.getElementById('score-text');
    const progressPath = document.getElementById('progress-path');
    const statusChip = document.getElementById('status-chip');
    const intelFeed = document.getElementById('intel-feed');
    const ping = document.getElementById('radar-ping');

    const circumference = 2 * Math.PI * 90;

    function renderUI(risk, reasons) {
        const safety = 100 - risk;
        const offset = circumference - (safety / 100) * circumference;

        // Animate Circle
        progressPath.style.strokeDashoffset = offset;

        // Smooth Digit Counter
        let start = parseInt(scoreText.innerText) || 0;
        const duration = 1500;
        const startTime = performance.now();

        function countUp(time) {
            let elapsed = time - startTime;
            let progress = Math.min(elapsed / duration, 1);
            let val = Math.floor(start + (safety - start) * progress);
            scoreText.innerText = val;
            if (progress < 1) requestAnimationFrame(countUp);
        }
        requestAnimationFrame(countUp);

        // Hologram Color Sync
        let color = '#06b6d4'; // Cyber Cyan (Secondary)
        let status = 'PERIMETER_CLEAR';

        if (safety < 80) { color = '#f59e0b'; status = 'VULNERABILITY'; }
        if (safety < 50) { color = '#f43f5e'; status = 'CRITICAL_BREACH'; }

        progressPath.style.stroke = color;
        statusChip.style.color = color;
        statusChip.style.borderColor = color + '44';
        statusChip.style.background = color + '11';
        statusChip.innerText = status;
        ping.style.borderColor = color;

        // Feed Generation
        intelFeed.innerHTML = '';
        if (reasons && reasons.length > 0) {
            reasons.forEach(r => {
                const card = document.createElement('div');
                card.className = `intel-card ${safety < 50 ? 'danger' : ''}`;
                card.innerHTML = `
                    <div class="card-icon" style="color:${color}; border-color:${color}44;">
                        <i class="fas ${safety < 50 ? 'fa-biohazard' : 'fa-virus-slash'}"></i>
                    </div>
                    <div class="card-text"><span></span></div>
                `;
                // Reason text is set via textContent to avoid HTML injection.
                card.querySelector('.card-text span').textContent = String(r);
                intelFeed.appendChild(card);
            });
        }
    }

    document.getElementById('terminate-btn').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) chrome.tabs.remove(tabs[0].id);
        });
        window.close();
    });

    // BYPASS closes the popup. Wired here because MV3's content security policy
    // blocks inline onclick handlers in extension pages.
    document.getElementById('bypass-btn')?.addEventListener('click', () => window.close());

    // Storage Sync
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab || !tab.url || !tab.url.startsWith('http')) return;

        chrome.storage.local.get([tab.id.toString()], (res) => {
            const data = res[tab.id.toString()];
            if (data && data.url === tab.url) {
                renderUI(data.score || 0, data.reasons);
            } else {
                renderUI(0, ["NEURAL_CORE: STANDBY"]);
            }
        });
    });
});
