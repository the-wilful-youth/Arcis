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

    // Circular Gauge Constants
    const RADIUS = 90;
    const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
    
    riskProgress.style.strokeDasharray = `${CIRCUMFERENCE} ${CIRCUMFERENCE}`;
    riskProgress.style.strokeDashoffset = CIRCUMFERENCE;

    function setGaugeValue(percent) {
        const offset = CIRCUMFERENCE - (percent / 100) * CIRCUMFERENCE;
        riskProgress.style.strokeDashoffset = offset;
        
        // Color transition
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

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlToAnalyze = urlInput.value.trim();
        if (!urlToAnalyze) return;

        // UI state: loading
        btnText.textContent = 'Analyzing...';
        spinner.classList.remove('hidden');
        submitBtn.disabled = true;
        
        try {
            const response = await fetch('http://localhost:5001/api/analyze', {
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

            // Populate technical stats
            const f = data.features;
            
            // Format days active
            const ageDays = f.time_domain_activation;
            statDomainAge.textContent = ageDays >= 0 ? `${Math.round(ageDays)} d` : 'Unresolved';
            
            // Format days to expiry
            const expiryDays = f.time_domain_expiration;
            statDomainExpiry.textContent = expiryDays >= 0 ? `${Math.round(expiryDays)} d` : 'Unresolved';
            
            // DNS & Response Time
            statResolvedIps.textContent = f.qty_ip_resolved >= 0 ? Math.round(f.qty_ip_resolved) : '0';
            statResponseTime.textContent = f.time_response >= 0 ? `${(f.time_response * 1000).toFixed(0)} ms` : 'Offline';

            // Lexical stats
            statUrlLength.textContent = Math.round(f.length_url);
            statDomainLength.textContent = Math.round(f.domain_length);
            statDirSlashes.textContent = f.qty_slash_directory >= 0 ? Math.round(f.qty_slash_directory) : '0';
            statParamsCount.textContent = f.qty_params >= 0 ? Math.round(f.qty_params) : '0';

            // Key indicators list
            indicatorsList.innerHTML = '';
            data.top_features.forEach(indicator => {
                const item = document.createElement('div');
                item.className = 'indicator-item';
                
                const isRiskInc = indicator.direction === 'increases';
                const badgeClass = isRiskInc ? 'up' : 'down';
                
                // Format indicator descriptions nicely
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
            // Restore UI state
            btnText.textContent = 'Analyze Link';
            spinner.classList.add('hidden');
            submitBtn.disabled = false;
        }
    });
});
