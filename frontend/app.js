document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyze-form');
    const urlInput = document.getElementById('url-input');
    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = submitBtn.querySelector('.spinner');
    
    const resultsSection = document.getElementById('results-section');
    const riskProgress = document.getElementById('risk-progress');
    const riskPercentage = document.getElementById('risk-percentage');
    const riskLabel = document.getElementById('risk-label');
    const verdictDesc = document.getElementById('verdict-desc');
    const indicatorsList = document.getElementById('indicators-list');
    
    // Stats elements
    const statDomainAge = document.getElementById('stat-domain-age');
    const statDomainExpiry = document.getElementById('stat-domain-expiry');
    const statResolvedIps = document.getElementById('stat-resolved-ips');
    const statResponseTime = document.getElementById('stat-response-time');
    const statUrlLength = document.getElementById('stat-url-length');
    const statDomainLength = document.getElementById('stat-domain-length');
    const statDirSlashes = document.getElementById('stat-dir-slashes');
    const statParamsCount = document.getElementById('stat-params-count');

    // History elements
    const historyTimeline = document.getElementById('history-timeline');
    const clearHistoryBtn = document.getElementById('clear-history-btn');

    // Circular Gauge Constants
    const RADIUS = 90;
    const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
    
    riskProgress.style.strokeDasharray = `${CIRCUMFERENCE} ${CIRCUMFERENCE}`;
    riskProgress.style.strokeDashoffset = CIRCUMFERENCE;

    // Load Scan History from localStorage
    let scanHistory = JSON.parse(localStorage.getItem('arcis_scans')) || [];
    renderHistory();

    function setGaugeValue(percent) {
        const offset = CIRCUMFERENCE - (percent / 100) * CIRCUMFERENCE;
        riskProgress.style.strokeDashoffset = offset;
        
        if (percent < 30) {
            riskProgress.style.stroke = '#10b981'; // safe
            riskLabel.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
            riskLabel.style.color = '#10b981';
            riskLabel.textContent = 'SAFE';
            verdictDesc.textContent = 'This link appears safe and exhibits typical legitimate characteristics.';
        } else if (percent < 70) {
            riskProgress.style.stroke = '#f59e0b'; // suspicious
            riskLabel.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
            riskLabel.style.color = '#f59e0b';
            riskLabel.textContent = 'SUSPICIOUS';
            verdictDesc.textContent = 'Caution: This link has borderline structural patterns or unverified registry details.';
        } else {
            riskProgress.style.stroke = '#ef4444'; // dangerous
            riskLabel.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
            riskLabel.style.color = '#ef4444';
            riskLabel.textContent = 'DANGEROUS';
            verdictDesc.textContent = 'Warning: This link matches known phishing structures and is likely dangerous.';
        }
    }

    // Save Scan to History
    function saveToHistory(url, riskScore, isPhishing) {
        scanHistory = scanHistory.filter(item => item.url !== url);
        scanHistory.unshift({
            url: url,
            risk: riskScore,
            isPhishing: isPhishing,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        });

        if (scanHistory.length > 15) {
            scanHistory.pop();
        }

        localStorage.setItem('arcis_scans', JSON.stringify(scanHistory));
        renderHistory();
    }

    // Render History Timeline
    function renderHistory() {
        historyTimeline.innerHTML = '';
        if (scanHistory.length === 0) {
            historyTimeline.innerHTML = '<div class="no-history">No URLs scanned yet.</div>';
            clearHistoryBtn.classList.add('hidden');
            return;
        }

        clearHistoryBtn.classList.remove('hidden');

        scanHistory.forEach(item => {
            const historyCard = document.createElement('div');
            historyCard.className = `history-item ${item.isPhishing ? 'is-phishing' : 'is-safe'}`;
            historyCard.addEventListener('click', () => {
                urlInput.value = item.url;
                form.dispatchEvent(new Event('submit'));
            });

            const pillClass = item.isPhishing ? 'phishing' : 'safe';
            const pillLabel = item.isPhishing ? 'PHISHING' : 'SAFE';

            historyCard.innerHTML = `
                <div class="history-header">
                    <span class="history-pill ${pillClass}">${pillLabel} (${item.risk}%)</span>
                    <span class="history-time">${item.timestamp}</span>
                </div>
                <div class="history-url" title="${item.url}">${item.url}</div>
            `;
            historyTimeline.appendChild(historyCard);
        });
    }

    // Clear History Button
    clearHistoryBtn.addEventListener('click', () => {
        scanHistory = [];
        localStorage.removeItem('arcis_scans');
        renderHistory();
    });

    // Form Submit Event
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlToAnalyze = urlInput.value.trim();
        if (!urlToAnalyze) return;

        btnText.textContent = 'Analyzing...';
        spinner.classList.remove('hidden');
        submitBtn.disabled = true;
        
        try {
            const response = await fetch('http://localhost:5001/api/analyze/url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: urlToAnalyze })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Failed to analyze URL');
            }

            const data = await response.json();
            
            // Show results
            resultsSection.classList.remove('hidden');
            resultsSection.scrollIntoView({ behavior: 'smooth' });

            // Set gauge
            const riskVal = data.risk_score_pct;
            riskPercentage.textContent = `${riskVal}%`;
            setGaugeValue(riskVal);

            // Save to history
            saveToHistory(urlToAnalyze, riskVal, data.is_phishing);

            // Populate technical stats
            const f = data.features;
            
            const ageDays = f.time_domain_activation;
            statDomainAge.textContent = ageDays >= 0 ? `${Math.round(ageDays)} d` : 'Unresolved';
            
            const expiryDays = f.time_domain_expiration;
            statDomainExpiry.textContent = expiryDays >= 0 ? `${Math.round(expiryDays)} d` : 'Unresolved';
            
            statResolvedIps.textContent = f.qty_ip_resolved >= 0 ? Math.round(f.qty_ip_resolved) : '0';
            statResponseTime.textContent = f.time_response >= 0 ? `${(f.time_response * 1000).toFixed(0)} ms` : 'Offline';

            // Lexical stats
            statUrlLength.textContent = Math.round(f.length_url);
            statDomainLength.textContent = Math.round(f.domain_length);
            statDirSlashes.textContent = f.qty_slash_directory >= 0 ? Math.round(f.qty_slash_directory) : '0';
            statParamsCount.textContent = f.qty_params >= 0 ? Math.round(f.qty_params) : '0';

            // Key indicators list
            indicatorsList.innerHTML = '';

            // 1. Add Brand Impersonation Alert Badge
            if (data.brand_alert && data.brand_alert.impersonated) {
                const brandItem = document.createElement('div');
                brandItem.className = 'indicator-item';
                brandItem.style.border = '1px solid rgba(239, 68, 68, 0.3)';
                brandItem.style.background = 'rgba(239, 68, 68, 0.05)';
                brandItem.innerHTML = `
                    <span class="indicator-badge up"></span>
                    <span class="indicator-text" style="color: #ef4444; font-weight: 600;">
                        🚨 Brand Impersonation Alert: Imitating "${data.brand_alert.brand.toUpperCase()}" (${data.brand_alert.type})
                    </span>
                `;
                indicatorsList.appendChild(brandItem);
            }

            // 2. Add technical indicators
            data.top_features.forEach(indicator => {
                const item = document.createElement('div');
                item.className = 'indicator-item';
                
                const isRiskInc = indicator.direction === 'increases';
                const badgeClass = isRiskInc ? 'up' : 'down';
                
                let desc = '';
                const feat = indicator.feature;
                const val = indicator.value;

                if (feat === 'time_domain_activation') {
                    desc = val < 0 ? 'Domain registration age cannot be verified.' : `Domain is active for ${Math.round(val)} days.`;
                } else if (feat === 'time_response') {
                    desc = val < 0 ? 'Server is unresponsive or timed out.' : `Server response time is fast (${(val * 1000).toFixed(0)}ms).`;
                } else if (feat === 'qty_ip_resolved') {
                    desc = val <= 0 ? 'Domain fails to resolve to any IP address.' : `Domain resolves to ${Math.round(val)} active IP(s).`;
                } else if (feat === 'length_url') {
                    desc = `URL length is ${Math.round(val)} characters (long URLs can hide phishing subdomains).`;
                } else if (feat === 'domain_length') {
                    desc = `Domain name length is ${Math.round(val)} characters.`;
                } else if (feat.startsWith('qty_slash_')) {
                    desc = `Contains ${Math.round(val)} slash character(s) in path segments.`;
                } else if (feat.startsWith('qty_dot_')) {
                    desc = `Contains ${Math.round(val)} dot(s) in URL segments.`;
                } else {
                    desc = `Feature '${feat}' has value ${val} which ${indicator.direction}s risk.`;
                }

                item.innerHTML = `
                    <span class="indicator-badge ${badgeClass}"></span>
                    <span class="indicator-text">${desc}</span>
                `;
                indicatorsList.appendChild(item);
            });

        } catch (error) {
            console.error(error);
            alert(`Analysis failed: ${error.message}. Make sure the Flask API server is running on http://localhost:5001`);
        } finally {
            btnText.textContent = 'Quick Scan';
            spinner.classList.add('hidden');
            submitBtn.disabled = false;
        }
    });

    // --- Tab Switching Logic ---
    const dashTabs = document.querySelectorAll('.dash-tab');
    const dashTabPanes = document.querySelectorAll('.dash-tab-pane');

    dashTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            dashTabs.forEach(t => t.classList.remove('active'));
            dashTabPanes.forEach(p => p.classList.add('hidden'));

            tab.classList.add('active');
            const targetPane = document.getElementById(tab.dataset.tab);
            if (targetPane) {
                targetPane.classList.remove('hidden');
            }
        });
    });

    // --- Email Scanner Form Submit Logic ---
    const emailForm = document.getElementById('email-analyze-form');
    const emailSenderInput = document.getElementById('email-sender-input');
    const emailReplyInput = document.getElementById('email-reply-input');
    const emailSubjectInput = document.getElementById('email-subject-input');
    const emailBodyInput = document.getElementById('email-body-input');
    const emailSpfSelect = document.getElementById('email-spf-select');
    const emailDkimSelect = document.getElementById('email-dkim-select');
    const emailDmarcSelect = document.getElementById('email-dmarc-select');

    const emailSubmitBtn = document.getElementById('email-submit-btn');
    const emailBtnText = emailSubmitBtn.querySelector('.btn-text');
    const emailSpinner = emailSubmitBtn.querySelector('.spinner');

    const emailResultsSection = document.getElementById('email-results-section');
    const emailRiskProgress = document.getElementById('email-risk-progress');
    const emailRiskPercentage = document.getElementById('email-risk-percentage');
    const emailRiskLabel = document.getElementById('email-risk-label');
    const emailVerdictDesc = document.getElementById('email-verdict-desc');
    const emailIndicatorsList = document.getElementById('email-indicators-list');

    // Stats elements
    const statEmailMx = document.getElementById('stat-email-mx');
    const statEmailSpf = document.getElementById('stat-email-spf');
    const statEmailDmarc = document.getElementById('stat-email-dmarc');
    const statEmailFree = document.getElementById('stat-email-free');

    emailRiskProgress.style.strokeDasharray = `${CIRCUMFERENCE} ${CIRCUMFERENCE}`;
    emailRiskProgress.style.strokeDashoffset = CIRCUMFERENCE;

    function setEmailGaugeValue(percent) {
        const offset = CIRCUMFERENCE - (percent / 100) * CIRCUMFERENCE;
        emailRiskProgress.style.strokeDashoffset = offset;
        
        if (percent < 30) {
            emailRiskProgress.style.stroke = '#10b981';
            emailRiskLabel.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
            emailRiskLabel.style.color = '#10b981';
            emailRiskLabel.textContent = 'SAFE SENDER';
            emailVerdictDesc.textContent = 'The email headers and sender parameters present safe signals.';
        } else if (percent < 70) {
            emailRiskProgress.style.stroke = '#f59e0b';
            emailRiskLabel.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
            emailRiskLabel.style.color = '#f59e0b';
            emailRiskLabel.textContent = 'SUSPICIOUS SENDER';
            emailVerdictDesc.textContent = 'Caution: border threat signals detected. Possible spoofing indicators found.';
        } else {
            emailRiskProgress.style.stroke = '#ef4444';
            emailRiskLabel.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
            emailRiskLabel.style.color = '#ef4444';
            emailRiskLabel.textContent = 'DANGEROUS SENDER';
            emailVerdictDesc.textContent = 'Warning: Strong matching patterns for email phishing or header authentication failure.';
        }
    }

    emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const sender = emailSenderInput.value.trim();
        const replyTo = emailReplyInput.value.trim();
        const subject = emailSubjectInput.value.trim();
        const body = emailBodyInput.value.trim();
        const spf = emailSpfSelect.value;
        const dkim = emailDkimSelect.value;
        const dmarc = emailDmarcSelect.value;

        emailBtnText.textContent = 'Analyzing...';
        emailSpinner.classList.remove('hidden');
        emailSubmitBtn.disabled = true;

        try {
            const response = await fetch('http://localhost:5001/api/analyze/email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: sender,
                    reply_to: replyTo,
                    subject: subject,
                    body: body,
                    spf: spf,
                    dkim: dkim,
                    dmarc: dmarc
                })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Failed to analyze email');
            }

            const data = await response.json();

            emailResultsSection.classList.remove('hidden');
            emailResultsSection.scrollIntoView({ behavior: 'smooth' });

            const riskVal = data.risk_score_pct;
            emailRiskPercentage.textContent = `${riskVal}%`;
            setEmailGaugeValue(riskVal);

            // Populate stats
            const dns = data.dns_checks || {};
            statEmailMx.textContent = dns.has_mx ? 'YES' : 'NO';
            statEmailSpf.textContent = dns.has_spf ? 'YES' : 'NO';
            statEmailDmarc.textContent = dns.has_dmarc ? 'YES' : 'NO';
            statEmailFree.textContent = data.details.is_free_provider ? 'YES' : 'NO';

            // Populate indicators list
            emailIndicatorsList.innerHTML = '';
            const reasons = data.details.reasons || [];
            
            if (reasons.length === 0) {
                const item = document.createElement('div');
                item.className = 'indicator-item';
                item.innerHTML = `
                    <span class="indicator-badge down"></span>
                    <span class="indicator-text">No immediate threat anomalies resolved.</span>
                `;
                emailIndicatorsList.appendChild(item);
            } else {
                reasons.forEach(reason => {
                    const item = document.createElement('div');
                    item.className = 'indicator-item';
                    item.innerHTML = `
                        <span class="indicator-badge up"></span>
                        <span class="indicator-text">${reason}</span>
                    `;
                    emailIndicatorsList.appendChild(item);
                });
            }

        } catch (error) {
            console.error(error);
            alert(`Analysis failed: ${error.message}. Make sure the Flask API server is running on http://localhost:5001`);
        } finally {
            emailBtnText.textContent = 'Verify Sender Risk';
            emailSpinner.classList.add('hidden');
            emailSubmitBtn.disabled = false;
        }
    });
});
