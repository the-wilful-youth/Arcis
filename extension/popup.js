document.addEventListener('DOMContentLoaded', async () => {
    // Tab switching elements
    const tabButtons = document.querySelectorAll('.p-tab');
    const tabPanes = document.querySelectorAll('.p-pane');

    // URL Scanner elements
    const activeUrlEl = document.getElementById('active-url');
    const scanBtn = document.getElementById('scan-btn');
    const loadingState = document.getElementById('loading-state');
    const resultState = document.getElementById('result-state');
    const riskScoreEl = document.getElementById('risk-score');
    const statusAlertEl = document.getElementById('status-alert');
    const findingsList = document.getElementById('findings-list');

    // Email Scanner elements
    const emailForm = document.getElementById('email-form');
    const emailScanBtn = document.getElementById('email-scan-btn');
    const emailLoadingState = document.getElementById('email-loading-state');
    const emailResultState = document.getElementById('email-result-state');
    const emailRiskScoreEl = document.getElementById('email-risk-score');
    const emailStatusAlertEl = document.getElementById('email-status-alert');
    const emailFindingsList = document.getElementById('email-findings-list');

    let currentTabUrl = '';

    // --- 1. Tab Switching Logic ---
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('p-tab--active'));
            tabPanes.forEach(p => p.classList.add('hidden'));

            btn.classList.add('p-tab--active');
            const targetPane = document.getElementById(btn.dataset.tab);
            if (targetPane) {
                targetPane.classList.remove('hidden');
            }
        });
    });

    // --- 2. URL Scanner: Get active tab URL ---
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            currentTabUrl = tab.url;
            activeUrlEl.textContent = currentTabUrl;
            
            // Pre-populate email sender input if visiting a mailto link
            if (currentTabUrl.startsWith('mailto:')) {
                const mailAddr = currentTabUrl.replace('mailto:', '').split('?')[0];
                document.getElementById('email-sender').value = mailAddr;
            }
        } else {
            activeUrlEl.textContent = "Unable to read active tab URL.";
            scanBtn.disabled = true;
        }
    } catch (e) {
        console.error(e);
        activeUrlEl.textContent = "Error reading active URL.";
        scanBtn.disabled = true;
    }

    // --- 3. URL Scanner: Run Scan ---
    scanBtn.addEventListener('click', async () => {
        if (!currentTabUrl) return;

        scanBtn.disabled = true;
        loadingState.classList.remove('hidden');
        resultState.classList.add('hidden');

        try {
            const response = await fetch('http://127.0.0.1:5001/api/analyze/url', {
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

            findingsList.innerHTML = '';
            
            if (data.brand_alert && data.brand_alert.impersonated) {
                const brandLi = document.createElement('li');
                brandLi.style.color = '#ef4444';
                brandLi.style.fontWeight = '700';
                brandLi.textContent = `🚨 Brand Impersonation: Imitating "${data.brand_alert.brand.toUpperCase()}" (${data.brand_alert.type})`;
                findingsList.appendChild(brandLi);
            }

            data.top_features.forEach(indicator => {
                const li = document.createElement('li');
                const val = indicator.value;
                const feat = indicator.feature;
                
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

    // --- 4. Email Scanner: Run Scan ---
    emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const sender = document.getElementById('email-sender').value.trim();
        const subject = document.getElementById('email-subject').value.trim();
        const body = document.getElementById('email-body').value.trim();
        const spf = document.getElementById('email-spf').value;
        const dkim = document.getElementById('email-dkim').value;
        const dmarc = document.getElementById('email-dmarc').value;

        emailScanBtn.disabled = true;
        emailLoadingState.classList.remove('hidden');
        emailResultState.classList.add('hidden');

        try {
            const response = await fetch('http://127.0.0.1:5001/api/analyze/email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: sender,
                    subject: subject,
                    body: body,
                    spf: spf,
                    dkim: dkim,
                    dmarc: dmarc
                })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Email scan failed.');
            }

            const data = await response.json();
            
            // Render Result
            const riskVal = data.risk_score_pct;
            emailRiskScoreEl.textContent = `${riskVal}%`;

            if (riskVal < 30) {
                emailStatusAlertEl.textContent = 'SAFE SENDER';
                emailStatusAlertEl.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                emailStatusAlertEl.style.color = '#10b981';
                emailRiskScoreEl.style.color = '#10b981';
            } else if (riskVal < 70) {
                emailStatusAlertEl.textContent = 'SUSPICIOUS SENDER';
                emailStatusAlertEl.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                emailStatusAlertEl.style.color = '#f59e0b';
                emailRiskScoreEl.style.color = '#f59e0b';
            } else {
                emailStatusAlertEl.textContent = 'DANGEROUS SENDER';
                emailStatusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                emailStatusAlertEl.style.color = '#ef4444';
                emailRiskScoreEl.style.color = '#ef4444';
            }

            emailFindingsList.innerHTML = '';
            
            // List reasons/signals
            const reasons = data.details.reasons || [];
            reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                emailFindingsList.appendChild(li);
            });

            emailResultState.classList.remove('hidden');

        } catch (error) {
            console.error(error);
            alert(`Unable to contact scan backend. Ensure Flask is running at http://localhost:5001.`);
        } finally {
            emailLoadingState.classList.add('hidden');
            emailScanBtn.disabled = false;
        }
    });
});
