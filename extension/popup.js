document.addEventListener('DOMContentLoaded', async () => {
    const activeUrlEl = document.getElementById('active-url');
    const scanBtn = document.getElementById('scan-btn');
    const loadingState = document.getElementById('loading-state');
    const resultState = document.getElementById('result-state');
    
    const riskScoreEl = document.getElementById('risk-score');
    const statusAlertEl = document.getElementById('status-alert');
    const findingsList = document.getElementById('findings-list');

    let currentTabUrl = '';

    // 1. Get current active tab URL
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            currentTabUrl = tab.url;
            activeUrlEl.textContent = currentTabUrl;
        } else {
            activeUrlEl.textContent = "Unable to read active tab URL.";
            scanBtn.disabled = true;
        }
    } catch (e) {
        console.error(e);
        activeUrlEl.textContent = "Error reading active URL.";
        scanBtn.disabled = true;
    }

    // 2. Perform Scan
    scanBtn.addEventListener('click', async () => {
        if (!currentTabUrl) return;

        // Reset UI State
        scanBtn.disabled = true;
        loadingState.classList.remove('hidden');
        resultState.classList.add('hidden');

        try {
            const response = await fetch('http://localhost:5001/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: currentTabUrl })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Scan failed.');
            }

            const data = await response.json();
            
            // Render Result
            const riskVal = data.risk_score_pct;
            riskScoreEl.textContent = `${riskVal}%`;

            // Adjust Color Banners
            if (riskVal < 30) {
                statusAlertEl.textContent = 'SAFE LINK';
                statusAlertEl.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                statusAlertEl.style.color = '#10b981';
                riskScoreEl.style.color = '#10b981';
            } else if (riskVal < 70) {
                statusAlertEl.textContent = 'SUSPICIOUS LINK';
                statusAlertEl.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                statusAlertEl.style.color = '#f59e0b';
                riskScoreEl.style.color = '#f59e0b';
            } else {
                statusAlertEl.textContent = 'DANGEROUS LINK';
                statusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                statusAlertEl.style.color = '#ef4444';
                riskScoreEl.style.color = '#ef4444';
            }

            // Populate Findings
            findingsList.innerHTML = '';
            data.top_features.forEach(indicator => {
                const li = document.createElement('li');
                const val = indicator.value;
                const feat = indicator.feature;
                const isRiskInc = indicator.direction === 'increases';
                
                let desc = '';
                if (feat === 'time_domain_activation') {
                    desc = val < 0 ? 'Domain registration age cannot be verified.' : `Domain registered ${Math.round(val)} days ago.`;
                } else if (feat === 'qty_ip_resolved') {
                    desc = val <= 0 ? 'Fails to resolve to any IP address.' : `Resolves to ${Math.round(val)} active IP(s).`;
                } else if (feat === 'time_response') {
                    desc = val < 0 ? 'Web server connection timed out.' : `Server connection is responsive.`;
                } else if (feat === 'length_url') {
                    desc = `URL length is ${Math.round(val)} characters.`;
                } else if (feat.startsWith('qty_slash_')) {
                    desc = `Contains ${Math.round(val)} slash character(s).`;
                } else {
                    desc = `${feat.replace(/_/g, ' ')}: ${val} (${indicator.direction}s risk)`;
                }

                li.textContent = desc;
                findingsList.appendChild(li);
            });

            resultState.classList.remove('hidden');

        } catch (error) {
            console.error(error);
            alert(`Unable to contact scan backend. Ensure Flask is running at http://localhost:5001.`);
        } finally {
            loadingState.classList.add('hidden');
            scanBtn.disabled = false;
        }
    });
});
