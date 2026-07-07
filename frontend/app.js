/* ═══════════════════════════════════════════════════════════
   ARCIS — app.js
   UI interactions, API calls, history management
   ═══════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', async () => {

    /* ── Constants ─────────────────────────────────────────── */
    const API_BASE      = window.location.origin;
    const CIRCUMFERENCE = 2 * Math.PI * 80; // r=80 → 502.65

    const COMPONENT_WEIGHTS = {
        ml_classifier: 0.35,
        url_analysis: 0.30,
        sensitive_request: 0.15,
        polite_request: 0.10,
        short_email_risk: 0.10
    };

    /* ── Bootstrap API key from backend (never hardcoded in client JS) ── */
    let _apiKey = localStorage.getItem('arcis_api_key') || '';
    if (!_apiKey) {
        try {
            const cfgRes = await fetch(`${API_BASE}/api/config`);
            if (cfgRes.ok) {
                const cfg = await cfgRes.json();
                _apiKey = cfg.api_key || '';
                if (_apiKey) localStorage.setItem('arcis_api_key', _apiKey);
            }
        } catch (_) {
            // Backend unreachable — key stays empty, requests will show 403 prompt
        }
    }
    const getApiKey = () => localStorage.getItem('arcis_api_key') || _apiKey;

    /* ── URL Scanner elements ──────────────────────────────── */
    const form          = document.getElementById('analyze-form');
    const urlInput      = document.getElementById('url-input');
    const submitBtn     = document.getElementById('submit-btn');
    const resultsPanel  = document.getElementById('results-section');

    const riskProgress  = document.getElementById('risk-progress');
    const riskPct       = document.getElementById('risk-percentage');
    const riskLabel     = document.getElementById('risk-label');
    const verdictBadge  = document.getElementById('verdict-badge');
    const verdictDesc   = document.getElementById('verdict-desc');
    const verdictStrip  = document.getElementById('verdict-strip');
    const indicatorsList = document.getElementById('indicators-list');
    const indicatorCount = document.getElementById('indicator-count');

    const statDomainAge    = document.getElementById('stat-domain-age');
    const statDomainExpiry = document.getElementById('stat-domain-expiry');
    const statResolvedIps  = document.getElementById('stat-resolved-ips');
    const statResponseTime = document.getElementById('stat-response-time');
    const statUrlLength    = document.getElementById('stat-url-length');
    const statDomainLength = document.getElementById('stat-domain-length');
    const statDirSlashes   = document.getElementById('stat-dir-slashes');
    const statParamsCount  = document.getElementById('stat-params-count');

    /* ── Email Scanner elements ────────────────────────────── */
    const emailForm           = document.getElementById('email-analyze-form');
    const emailSenderInput    = document.getElementById('email-sender-input');
    const emailReplyInput     = document.getElementById('email-reply-input');
    const emailSubjectInput   = document.getElementById('email-subject-input');
    const emailBodyInput      = document.getElementById('email-body-input');
    const emailSpfSelect      = document.getElementById('email-spf-select');
    const emailDkimSelect     = document.getElementById('email-dkim-select');
    const emailDmarcSelect    = document.getElementById('email-dmarc-select');
    const emailSubmitBtn      = document.getElementById('email-submit-btn');
    const emailResultsPanel   = document.getElementById('email-results-section');

    const emailRiskProgress   = document.getElementById('email-risk-progress');
    const emailRiskPct        = document.getElementById('email-risk-percentage');
    const emailRiskLabel      = document.getElementById('email-risk-label');
    const emailVerdictBadge   = document.getElementById('email-verdict-badge');
    const emailVerdictDesc    = document.getElementById('email-verdict-desc');
    const emailVerdictStrip   = document.getElementById('email-verdict-strip');
    const emailIndicatorsList = document.getElementById('email-indicators-list');
    const emailIndicatorCount = document.getElementById('email-indicator-count');

    const statEmailMx    = document.getElementById('stat-email-mx');
    const statEmailSpf   = document.getElementById('stat-email-spf');
    const statEmailDmarc = document.getElementById('stat-email-dmarc');
    const statEmailFree  = document.getElementById('stat-email-free');

    /* ── History elements ──────────────────────────────────── */
    const historyFeed     = document.getElementById('history-timeline');
    const historyCount    = document.getElementById('history-count');
    const clearHistoryBtn = document.getElementById('clear-history-btn');

    /* ── Init gauges ───────────────────────────────────────── */
    [riskProgress, emailRiskProgress].forEach(el => {
        el.style.strokeDasharray  = `${CIRCUMFERENCE} ${CIRCUMFERENCE}`;
        el.style.strokeDashoffset = CIRCUMFERENCE;
    });

    /* ── Animated metric counters ──────────────────────────── */
    document.querySelectorAll('[data-counter]').forEach(el => {
        const target   = parseInt(el.dataset.counter, 10);
        const duration = 1600;
        const start    = performance.now();
        const step     = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            const eased    = 1 - Math.pow(1 - progress, 3); // ease-out cubic
            el.textContent = Math.floor(eased * target).toLocaleString();
            if (progress < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    });

    /* ── Crypto and HTML escape Helpers ────────────────────── */
    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;")
                  .replace(/"/g, "&quot;")
                  .replace(/'/g, "&#039;");
    }

    function encryptData(text) {
        const key = 42;
        let result = "";
        for (let i = 0; i < text.length; i++) {
            result += String.fromCharCode(text.charCodeAt(i) ^ key);
        }
        return btoa(unescape(encodeURIComponent(result)));
    }

    function decryptData(ciphertext) {
        if (!ciphertext) return "[]";
        try {
            const decoded = decodeURIComponent(escape(atob(ciphertext)));
            const key = 42;
            let result = "";
            for (let i = 0; i < decoded.length; i++) {
                result += String.fromCharCode(decoded.charCodeAt(i) ^ key);
            }
            return result;
        } catch (e) {
            return "[]";
        }
    }

    /* ── History state ─────────────────────────────────────── */
    let scanHistory = [];
    try {
        const rawHistory = localStorage.getItem('arcis_scans');
        if (rawHistory) {
            scanHistory = JSON.parse(decryptData(rawHistory));
        }
    } catch (e) {
        console.error("Failed to load/decrypt history", e);
    }
    renderHistory();

    /* ════════════════════════════════════════════════════════
       SHARED HELPERS
       ════════════════════════════════════════════════════════ */

    /**
     * Set the gauge ring stroke and all associated UI state.
     */
    function applyGaugeState(progressEl, pctEl, labelEl, badgeEl, descEl, stripEl, percent, isEmail = false) {
        const offset = CIRCUMFERENCE - (percent / 100) * CIRCUMFERENCE;
        progressEl.style.strokeDashoffset = offset;
        pctEl.textContent = `${percent}%`;

        let color, badgeClass, labelText, verdictText, iconSvg, badgeIcon;

        if (percent < 30) {
            color       = 'var(--safe)';
            badgeClass  = 'card__badge--safe';
            labelText   = isEmail ? 'SAFE SENDER' : 'SAFE';
            verdictText = isEmail
                ? 'Email headers and authentication signals appear legitimate.'
                : 'This URL exhibits typical safe structural patterns.';
            iconSvg   = `<svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M2 5.5L4 7.5L8 3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
            badgeIcon = iconSvg;
        } else if (percent < 50) {
            color       = 'var(--warn)';
            badgeClass  = 'card__badge--warn';
            labelText   = 'SUSPICIOUS';
            verdictText = isEmail
                ? 'Caution: borderline signals detected. Possible spoofing indicators.'
                : 'Caution: borderline structural patterns or unverifiable registry data.';
            iconSvg   = `<svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M5 1.5L1 8.5h8L5 1.5z" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 4.5V6M5 7.5V8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
            badgeIcon = iconSvg;
        } else {
            color       = 'var(--danger)';
            badgeClass  = 'card__badge--danger';
            labelText   = isEmail ? 'DANGEROUS SENDER' : 'DANGEROUS';
            verdictText = isEmail
                ? 'Warning: strong phishing pattern match. Header authentication failed.'
                : 'Warning: matches known phishing URL structures. Highly likely malicious.';
            iconSvg   = `<svg width="10" height="10" viewBox="0 0 10 10" fill="none"><circle cx="5" cy="5" r="4" stroke="currentColor" stroke-width="1.4"/><path d="M3.5 3.5l3 3M6.5 3.5l-3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
            badgeIcon = iconSvg;
        }

        progressEl.style.stroke = color;

        // Gauge label pill — icon + text (using textContent safely for text, and clear/append for icon)
        labelEl.textContent = '';
        const tempSpan = document.createElement('span');
        tempSpan.innerHTML = iconSvg;
        labelEl.appendChild(tempSpan.firstChild);
        labelEl.appendChild(document.createTextNode(` ${labelText}`));
        
        labelEl.style.cssText = '';   // reset any inline from previous run
        if (percent < 30) {
            labelEl.style.background = 'rgba(111,207,151,0.14)';
            labelEl.style.color      = 'var(--safe)';
        } else if (percent < 50) {
            labelEl.style.background = 'rgba(242,201,76,0.14)';
            labelEl.style.color      = 'var(--warn)';
        } else {
            labelEl.style.background = 'rgba(235,87,87,0.14)';
            labelEl.style.color      = 'var(--danger)';
        }

        // Card badge pill
        badgeEl.className = `card__badge ${badgeClass}`;
        badgeEl.textContent = '';
        const tempBadgeSpan = document.createElement('span');
        tempBadgeSpan.innerHTML = badgeIcon;
        badgeEl.appendChild(tempBadgeSpan.firstChild);
        badgeEl.appendChild(document.createTextNode(` ${labelText}`));

        descEl.textContent = verdictText;
        stripEl.querySelector('.verdict-strip__icon').style.color = color;
    }

    /**
     * Build a single indicator row with stagger animation delay.
     */
    function makeIndicator(text, tone = 'danger', index = 0) {
        const item = document.createElement('div');
        const itemToneClass = tone === 'brand' ? 'indicator-item--brand'
                    : tone === 'safe'  ? 'indicator-item--safe'
                    : tone === 'danger' ? 'indicator-item--danger'
                    : '';
        item.className = `indicator-item${itemToneClass ? ' ' + itemToneClass : ''}`;
        item.style.animationDelay = `${index * 60}ms`;

        const dotClass = tone === 'safe' ? 'indicator-dot--safe'
                       : tone === 'warn' ? 'indicator-dot--warn'
                       : 'indicator-dot--danger';

        const dotColor = tone === 'safe'  ? 'var(--safe)'
                       : tone === 'warn'  ? 'var(--warn)'
                       : tone === 'brand' ? 'var(--danger)'
                       : 'var(--danger)';

        const dotSpan = document.createElement('span');
        dotSpan.className = `indicator-dot ${dotClass}`;
        dotSpan.style.background = dotColor;
        dotSpan.style.marginTop = '5px';

        const textSpan = document.createElement('span');
        textSpan.className = 'indicator-text';
        textSpan.innerHTML = text;

        item.appendChild(dotSpan);
        item.appendChild(textSpan);
        return item;
    }

    /**
     * Set a stat cell value and optionally colour-code it.
     */
    function setStat(el, value, tone = null) {
        el.textContent = value;
        el.className   = 'stat-cell__value';
        if (tone) el.classList.add(`stat-cell__value--${tone}`);
    }

    /**
     * Renders a ranked list of risk_signals entries (either the 'increasing'
     * or 'decreasing' group from the API) into a container, as horizontal
     * bars scaled relative to the largest impact in the group.
     *
     * getLabel(item) resolves the display label for a signal - the URL
     * scanner groups raw SHAP features via a feature->label map, while the
     * email classifier's signals already carry a human-readable `label`.
     */
    function renderRankingGroup(container, signals, getLabel, signPrefix = '') {
        if (!container) return;
        container.innerHTML = "";

        // Group signals by their display label, summing magnitude for duplicates
        const grouped = {};
        signals.forEach(item => {
            const label = getLabel(item);
            if (!grouped[label]) {
                grouped[label] = { label, impact: 0 };
            }
            grouped[label].impact += Math.abs(item.impact);
        });

        const groupedSignals = Object.values(grouped)
            .sort((a, b) => b.impact - a.impact);

        const maxImpact = Math.max(...groupedSignals.map(s => s.impact), 0.0001);

        groupedSignals.forEach(item => {
            const pct = Math.round((item.impact / maxImpact) * 100);
            const row = document.createElement("div");
            row.className = "ranking-row";
            row.innerHTML = `
                <div class="ranking-row__label">${item.label}</div>
                <div class="ranking-row__bar">
                    <div class="ranking-row__fill" style="width:${pct}%"></div>
                </div>
                <div class="ranking-row__pct">${signPrefix}${pct}%</div>
            `;
            container.appendChild(row);
        });
    }

    /**
     * Toggle loading state on a submit button.
     */
    function setLoading(btn, loading, defaultText) {
        const textEl    = btn.querySelector('.btn-text');
        const spinnerEl = btn.querySelector('.spinner');
        const arrowEl   = btn.querySelector('.btn-arrow');
        btn.disabled    = loading;
        textEl.textContent = loading ? 'Analyzing…' : defaultText;
        spinnerEl.classList.toggle('hidden', !loading);
        if (arrowEl) arrowEl.classList.toggle('hidden', loading);
    }

    /* ════════════════════════════════════════════════════════
       HISTORY
       ════════════════════════════════════════════════════════ */

    function saveToHistory(url, risk, isPhishing) {
        scanHistory = scanHistory.filter(i => i.url !== url);
        scanHistory.unshift({
            url,
            risk,
            isPhishing,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        });
        if (scanHistory.length > 20) scanHistory.pop();
        localStorage.setItem('arcis_scans', encryptData(JSON.stringify(scanHistory)));
        renderHistory();
    }

    function renderHistory() {
        historyFeed.innerHTML = '';
        historyCount.textContent = scanHistory.length;

        if (scanHistory.length === 0) {
            clearHistoryBtn.classList.add('hidden');
            historyFeed.innerHTML = `
                <div class="history-empty">
                    <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
                        <circle cx="16" cy="16" r="12" stroke="currentColor" stroke-width="1.5" stroke-dasharray="3 3"/>
                        <path d="M16 10V16M16 20V22" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
                    </svg>
                    <p>No scans yet</p>
                    <span>Results will appear here</span>
                </div>`;
            return;
        }

        clearHistoryBtn.classList.remove('hidden');

        scanHistory.forEach(item => {
            const el = document.createElement('div');
            el.className = `history-item ${item.isPhishing ? 'is-phishing' : 'is-safe'}`;

            const pillClass = item.isPhishing ? 'phishing' : 'safe';
            const pillLabel = item.isPhishing ? 'PHISHING' : 'SAFE';
            const pillIcon  = item.isPhishing
                ? `<svg width="8" height="8" viewBox="0 0 8 8" fill="none"><circle cx="4" cy="4" r="3" stroke="currentColor" stroke-width="1.3"/><path d="M2.5 2.5l3 3M5.5 2.5l-3 3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>`
                : `<svg width="8" height="8" viewBox="0 0 8 8" fill="none"><path d="M1.5 4.5l2 2 3-4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

            const escapedUrl = escapeHtml(item.url);

            el.innerHTML = `
                <div class="history-item__top">
                    <span class="history-pill ${pillClass}"></span>
                    <span class="history-time">${item.timestamp}</span>
                </div>
                <div class="history-url" title="${escapedUrl}">${escapedUrl}</div>
            `;
            
            // Build the pill HTML contents safely
            const pillSpan = el.querySelector('.history-pill');
            const tempIconSpan = document.createElement('span');
            tempIconSpan.innerHTML = pillIcon;
            pillSpan.appendChild(tempIconSpan.firstChild);
            pillSpan.appendChild(document.createTextNode(` ${pillLabel} · ${item.risk}%`));

            el.addEventListener('click', () => {
                const cleanUrl = item.url.replace(/["'<>]/g, '');
                urlInput.value = cleanUrl;
                // Switch to URL tab if needed
                activateTab('url-scanner-workspace');
                form.dispatchEvent(new Event('submit'));
            });

            historyFeed.appendChild(el);
        });
    }

    clearHistoryBtn.addEventListener('click', () => {
        scanHistory = [];
        localStorage.removeItem('arcis_scans');
        renderHistory();
    });

    /* ════════════════════════════════════════════════════════
       TAB SWITCHING
       ════════════════════════════════════════════════════════ */

    const tabBtns  = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    function activateTab(targetId) {
        tabBtns.forEach(btn => {
            const isActive = btn.dataset.tab === targetId;
            btn.classList.toggle('tab-btn--active', isActive);
            btn.setAttribute('aria-selected', isActive);
        });
        tabPanes.forEach(pane => {
            pane.classList.toggle('hidden', pane.id !== targetId);
        });
    }

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => activateTab(btn.dataset.tab));
    });

    /* ════════════════════════════════════════════════════════
       EXAMPLE URL BUTTONS
       ════════════════════════════════════════════════════════ */

    document.querySelectorAll('.scan-example').forEach(btn => {
        btn.addEventListener('click', () => {
            urlInput.value = btn.dataset.url;
            urlInput.focus();
        });
    });

    /* ════════════════════════════════════════════════════════
       URL SCANNER
       ════════════════════════════════════════════════════════ */

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        setLoading(submitBtn, true, 'Scan URL');

        try {
            const res = await fetch(`${API_BASE}/api/analyze/url`, {
                method:  'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-API-Key': getApiKey()
                },
                body:    JSON.stringify({ url })
            });

            if (res.status === 403 || res.status === 401) {
                const userKey = prompt("Unauthorized: Please enter a valid Arcis API Key:");
                if (userKey) {
                    localStorage.setItem('arcis_api_key', userKey);
                }
                throw new Error("Unauthorized: API Key has been updated. Please scan again.");
            }

            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.error || `HTTP ${res.status}`);
            }

            const data = await res.json();

            /* Show results */
            resultsPanel.classList.remove('hidden');
            setTimeout(() => resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);

            const risk = data.risk_score_pct;

            /* Gauge */
            applyGaugeState(
                riskProgress, riskPct, riskLabel,
                verdictBadge, verdictDesc, verdictStrip,
                risk, false
            );

            /* History */
            saveToHistory(url, risk, data.is_phishing);

            /* DNS / Registry stats */
            const f = data.features || {};

            const age = f.time_domain_activation;
            setStat(statDomainAge,
                age >= 0 ? `${Math.round(age)} d` : 'N/A',
                age >= 0 && age > 180 ? 'safe' : age >= 0 ? 'warn' : 'danger');

            const expiry = f.time_domain_expiration;
            setStat(statDomainExpiry,
                expiry >= 0 ? `${Math.round(expiry)} d` : 'N/A',
                expiry >= 0 && expiry > 60 ? 'safe' : 'warn');

            const ips = f.qty_ip_resolved;
            setStat(statResolvedIps,
                ips >= 0 ? Math.round(ips) : '0',
                ips > 0 ? 'safe' : 'danger');

            const latency = f.time_response;
            setStat(statResponseTime,
                latency >= 0 ? `${(latency * 1000).toFixed(0)} ms` : 'Offline',
                latency >= 0 ? 'safe' : 'danger');

            /* Lexical stats */
            setStat(statUrlLength,    Math.round(f.length_url    || 0));
            setStat(statDomainLength, Math.round(f.domain_length || 0));
            setStat(statDirSlashes,   Math.round(f.qty_slash_directory >= 0 ? f.qty_slash_directory : 0));
            setStat(statParamsCount,  Math.round(f.qty_params >= 0 ? f.qty_params : 0));

            /* Risk indicators */
            indicatorsList.innerHTML = '';
            let count = 0;

            /* Brand alert (always first if present) */
            if (data.brand_alert?.impersonated) {
                indicatorsList.appendChild(makeIndicator(
                    `Brand Impersonation: imitating ${data.brand_alert.brand.toUpperCase()} (${data.brand_alert.type})`,
                    'brand', count++
                ));
            }

            const featureLabels = {
                // Domain
                time_domain_activation: "Domain Age",
                time_domain_expiration: "Domain Registration",
                domain_length: "Domain Structure",
                qty_dot_domain: "Domain Structure",
                qty_hyphen_domain: "Domain Structure",
                qty_vowels_domain: "Domain Structure",
                qty_numbers_domain: "Domain Structure",

                // URL
                length_url: "URL Length",
                directory_length: "URL Structure",
                qty_slash_directory: "URL Structure",
                qty_dot_directory: "URL Structure",
                qty_slash_url: "URL Structure",
                qty_dot_url: "URL Structure",
                qty_hyphen_url: "URL Structure",
                qty_questionmark_url: "URL Structure",
                qty_equal_url: "URL Structure",
                qty_at_url: "URL Structure",

                // DNS
                qty_ip_resolved: "DNS Resolution",
                qty_nameservers: "DNS Configuration",
                qty_mx_servers: "Mail Server Configuration",
                ttl_hostname: "DNS Stability",
                time_response: "Server Availability",
                asn_ip: "Hosting Network"
            };

            /* Top feature indicators (from risk_signals.increasing / .decreasing) */
            const riskSignals = data.risk_signals || { increasing: { signals: [] }, decreasing: { signals: [] } };
            const increasingSignals = (riskSignals.increasing?.signals || []).map(s => ({ ...s, direction: 'increases' }));
            const decreasingSignals = (riskSignals.decreasing?.signals || []).map(s => ({ ...s, direction: 'decreases' }));
            if (data.brand_alert?.impersonated) {

                const highestImpact = Math.max(
                    ...increasingSignals.map(s => Math.abs(s.impact)),
                    1
                );

                increasingSignals.unshift({
                    feature: "brand_impersonation",
                    label: `Brand Impersonation (${data.brand_alert.brand})`,
                    impact: highestImpact + 1,
                    direction: "increases"
                });
            }

            const allSignals = data.is_phishing ? increasingSignals : decreasingSignals;

            allSignals.forEach((ind) => {
                const isUp = ind.direction === 'increases';
                const tone = isUp ? 'danger' : 'safe';
                const feat = ind.feature;
                const val  = ind.value;
                let desc = '';

                if (feat === "brand_impersonation") {
                    // Already rendered separately above; skip duplicate.
                    return;
                }

                if (feat === "time_domain_activation") {
                    desc = val < 0
                        ? "Domain registration age could not be verified."
                        : `Domain has existed for ${Math.round(val)} days.`;
                }

                else if (feat === "time_domain_expiration") {
                    desc = val < 0
                        ? "Domain expiration information is unavailable."
                        : `Domain registration remains valid for ${Math.round(val)} more days.`;
                }

                else if (feat === "time_response") {
                    desc = val < 0
                        ? "Server could not be reached."
                        : `Server responded in ${(val * 1000).toFixed(0)} ms.`;
                }

                else if (feat === "qty_ip_resolved") {
                    desc = val <= 0
                        ? "Domain could not be resolved to an IP address."
                        : `Domain resolves to ${Math.round(val)} IP address(es).`;
                }

                else if (feat === "length_url") {
                    desc = `URL contains ${Math.round(val)} characters.`;
                }

                else if (feat === "domain_length") {
                    desc = `Domain name contains ${Math.round(val)} characters.`;
                }

                else if (feat === "directory_length") {
                    desc = val < 0
                        ? "URL contains no directory path."
                        : `Directory path length is ${Math.round(val)} characters.`;
                }

                else if (feat === "qty_slash_directory") {
                    desc = `${Math.round(val)} directory separator(s) detected in the URL path.`;
                }

                else if (feat === "qty_dot_directory") {
                    desc = `${Math.round(val)} dot character(s) detected inside URL directories.`;
                }

                else if (feat === "qty_dot_url") {
                    desc = `${Math.round(val)} dot character(s) found in the URL.`;
                }

                else if (feat === "qty_hyphen_url") {
                    desc = `${Math.round(val)} hyphen character(s) found in the URL.`;
                }

                else if (feat === "qty_mx_servers") {
                    desc = val < 0
                        ? "No mail exchange (MX) records were found."
                        : `${Math.round(val)} mail server(s) detected.`;
                }

                else if (feat === "ttl_hostname") {
                    desc = `DNS cache lifetime (TTL) is ${Math.round(val)} seconds.`;
                }

                else if (feat === "asn_ip") {
                    desc = val < 0
                        ? "Hosting network could not be identified."
                        : "Hosting network information was successfully identified.";
                }

                else {
                    desc = `${featureLabels[feat] || feat} was analyzed.`;
            /* Friendly feature name helper */
            function getFriendlyFeatureName(key) {
                const customNames = {
                    time_domain_activation: 'Domain Registration Age',
                    time_domain_expiration: 'Domain Expiry Window',
                    qty_ip_resolved:        'Resolved IP Addresses',
                    time_response:          'Server Response Time',
                    length_url:             'URL Length',
                    domain_length:          'Domain Name Length',
                    directory_length:       'Directory Path Length',
                    file_length:            'File Name Length',
                    params_length:          'Query Parameters Length',
                    ttl_hostname:           'DNS Time-to-Live (TTL)',
                    asn_ip:                 'Network Provider (ASN)',
                    qty_nameservers:        'Nameservers Count',
                    qty_mx_servers:         'Mail Servers Count',
                    qty_vowels_domain:      'Vowel Count in Domain',
                    tld_present_params:     'Domain Extensions in Parameters'
                };

                if (customNames[key]) {
                    return customNames[key];
                }

                if (key.startsWith('qty_')) {
                    const parts = key.split('_');
                    if (parts.length >= 3) {
                        const charMap = {
                            dot: 'dot (.)',
                            slash: 'slash (/)',
                            hyphen: 'hyphen (-)',
                            underline: 'underscore (_)',
                            at: 'at symbol (@)',
                            questionmark: 'question mark (?)',
                            equal: 'equal sign (=)',
                            and: 'ampersand (&)',
                            exclamation: 'exclamation mark (!)',
                            space: 'space',
                            tilde: 'tilde (~)',
                            comma: 'comma (,)',
                            plus: 'plus sign (+)',
                            asterisk: 'asterisk (*)',
                            hashtag: 'hashtag (#)',
                            dollar: 'dollar sign ($)',
                            percent: 'percent sign (%)'
                        };

                        const locMap = {
                            directory: 'directory path',
                            file: 'file name',
                            url: 'URL',
                            domain: 'domain name',
                            params: 'query parameters'
                        };

                        const charName = charMap[parts[1]] || parts[1];
                        const locName = locMap[parts[2]] || parts[2];
                        return `Count of "${charName}" in ${locName}`;
                    }
                }

                return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            }

            /* Top feature indicators */
            (data.top_features || []).forEach((ind, i) => {
                const isUp  = ind.direction === 'increases';
                const tone  = isUp ? 'danger' : 'safe';
                const feat  = ind.feature;
                const val   = ind.value;
                let desc = '';

                if      (feat === 'time_domain_activation')  desc = val < 0 ? 'Domain registration age cannot be verified.' : `Domain is ${Math.round(val)} days old.`;
                else if (feat === 'time_response')            desc = val < 0 ? 'Server is unresponsive or timed out.' : `Server responded in ${(val * 1000).toFixed(0)} ms.`;
                else if (feat === 'qty_ip_resolved')          desc = val <= 0 ? 'Domain fails to resolve to any IP address.' : `Resolved to ${Math.round(val)} active IP address(es).`;
                else if (feat === 'length_url')               desc = `URL is ${Math.round(val)} characters long — long URLs can mask phishing paths.`;
                else if (feat === 'domain_length')            desc = `Domain name is ${Math.round(val)} characters.`;
                else if (feat.startsWith('qty_slash_'))       desc = `${Math.round(val)} slash character(s) in URL path segments.`;
                else if (feat.startsWith('qty_dot_'))         desc = `${Math.round(val)} dot(s) present in URL segments.`;
                else {
                    const friendlyName = getFriendlyFeatureName(feat);
                    desc = `${friendlyName}: ${val} (${isUp ? 'increases' : 'decreases'} risk score).`;
                }

                indicatorsList.appendChild(makeIndicator(desc, tone, count++));
            });

            indicatorCount.textContent = `${count} signal${count !== 1 ? 's' : ''}`;

            /* Ranked risk factor breakdown for URL analysis — split by direction */
            const increaseContainer = document.getElementById('url-risk-ranking-increasing');
            const decreaseContainer = document.getElementById('url-risk-ranking-decreasing');
            const increaseTotalEl   = document.getElementById('url-ranking-increase-total');
            const decreaseTotalEl   = document.getElementById('url-ranking-decrease-total');

            const urlLabelResolver = (item) => featureLabels[item.feature] || item.feature.replace(/_/g, " ");

            // Only show the group matching the verdict — increasing factors
            // for a phishing verdict, decreasing factors for a safe verdict.
            if (data.is_phishing) {
                renderRankingGroup(increaseContainer, increasingSignals, urlLabelResolver, '+');
                if (decreaseContainer) decreaseContainer.innerHTML = '';
                if (increaseTotalEl) {
                    increaseTotalEl.textContent =
                        `+${(riskSignals.increasing?.total_influence ?? 0).toFixed(2)}`;
                }
                if (decreaseTotalEl) decreaseTotalEl.textContent = '—';
            } else {
                renderRankingGroup(decreaseContainer, decreasingSignals, urlLabelResolver, '−');
                if (increaseContainer) increaseContainer.innerHTML = '';
                if (decreaseTotalEl) {
                    decreaseTotalEl.textContent =
                        `${(riskSignals.decreasing?.total_influence ?? 0).toFixed(2)}`;
                }
                if (increaseTotalEl) increaseTotalEl.textContent = '—';
            /* Ranked risk factor breakdown for URL analysis */
            const urlRankingContainer = document.getElementById('url-risk-ranking');
            if (urlRankingContainer) {
                urlRankingContainer.innerHTML = '';

                const rankedFeatures = [...(data.top_features || [])]
                    .sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));

                rankedFeatures.forEach(item => {
                    const label = getFriendlyFeatureName(item.feature);
                    const isRisky = item.direction === 'increases';
                    // Normalize impact magnitude to a 0-100 bar width
                    const maxImpact = Math.max(...rankedFeatures.map(f => Math.abs(f.impact)), 0.0001);
                    const pct = Math.round((Math.abs(item.impact) / maxImpact) * 100);
                    const tone = isRisky ? 'danger' : 'safe';

                    const row = document.createElement('div');
                    row.className = 'ranking-row';
                    row.innerHTML = `
                        <div class="ranking-row__label">${label}</div>
                        <div class="ranking-row__bar">
                            <div class="ranking-row__fill ranking-row__fill--${tone}" style="width:${pct}%"></div>
                        </div>
                        <div class="ranking-row__pct">${isRisky ? '+' : '−'}${pct}%</div>
                    `;
                    urlRankingContainer.appendChild(row);
                });
            }

        } catch (err) {
            console.error('[Arcis URL]', err);
            showError(`Analysis failed: ${err.message}. Ensure the Flask API is running on ${API_BASE}`);
        } finally {
            setLoading(submitBtn, false, 'Scan URL');
        }
    });

    /* ════════════════════════════════════════════════════════
       EMAIL SCANNER
       ════════════════════════════════════════════════════════ */

    emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const sender  = emailSenderInput.value.trim();
        if (!sender) return;

        setLoading(emailSubmitBtn, true, 'Analyze Email Risk');

        try {
            const res = await fetch(`${API_BASE}/api/analyze/email`, {
                method:  'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-API-Key': getApiKey()
                },
                body: JSON.stringify({
                    email:    sender,
                    reply_to: emailReplyInput.value.trim(),
                    subject:  emailSubjectInput.value.trim(),
                    body:     emailBodyInput.value.trim(),
                    spf:      emailSpfSelect.value,
                    dkim:     emailDkimSelect.value,
                    dmarc:    emailDmarcSelect.value
                })
            });

            if (res.status === 403 || res.status === 401) {
                const userKey = prompt("Unauthorized: Please enter a valid Arcis API Key:");
                if (userKey) {
                    localStorage.setItem('arcis_api_key', userKey);
                }
                throw new Error("Unauthorized: API Key has been updated. Please scan again.");
            }

            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.error || `HTTP ${res.status}`);
            }

            const data = await res.json();

            /* Show results */
            emailResultsPanel.classList.remove('hidden');
            setTimeout(() => emailResultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);

            const risk = data.risk_score_pct;

            /* Gauge */
            applyGaugeState(
                emailRiskProgress, emailRiskPct, emailRiskLabel,
                emailVerdictBadge, emailVerdictDesc, emailVerdictStrip,
                risk, true
            );

            /* DNS telemetry stats */
            const dns = data.dns_checks || {};
            setStat(statEmailMx,    dns.has_mx    ? 'YES' : 'NO', dns.has_mx    ? 'safe' : 'danger');
            setStat(statEmailSpf,   dns.has_spf   ? 'YES' : 'NO', dns.has_spf   ? 'safe' : 'warn');
            setStat(statEmailDmarc, dns.has_dmarc ? 'YES' : 'NO', dns.has_dmarc ? 'safe' : 'warn');
            setStat(statEmailFree,
                data.details?.is_free_provider ? 'YES' : 'NO',
                data.details?.is_free_provider ? 'warn' : 'safe');

            /* Ranked risk factor breakdown - same two-panel pattern as the URL
               scanner: show the group matching the verdict (risk-increasing
               factors for a phishing verdict, risk-decreasing/safe factors
               for a legitimate verdict), scaled by real weighted impact. */
            const emailRiskSignals = data.risk_signals || { increasing: { signals: [] }, decreasing: { signals: [] } };
            const emailIncreasing = emailRiskSignals.increasing?.signals || [];
            const emailDecreasing = emailRiskSignals.decreasing?.signals || [];
            const emailLabelResolver = (item) => item.label || item.feature.replace(/_/g, " ");

            const emailIncreaseContainer = document.getElementById('email-risk-ranking-increasing');
            const emailDecreaseContainer = document.getElementById('email-risk-ranking-decreasing');
            const emailIncreaseTotalEl   = document.getElementById('email-ranking-increase-total');
            const emailDecreaseTotalEl   = document.getElementById('email-ranking-decrease-total');

            if (data.is_phishing) {
                renderRankingGroup(emailIncreaseContainer, emailIncreasing, emailLabelResolver, '+');
                if (emailDecreaseContainer) emailDecreaseContainer.innerHTML = '';
                if (emailIncreaseTotalEl) {
                    emailIncreaseTotalEl.textContent =
                        `+${(emailRiskSignals.increasing?.total_influence ?? 0).toFixed(2)}`;
                }
                if (emailDecreaseTotalEl) emailDecreaseTotalEl.textContent = '—';
            } else {
                renderRankingGroup(emailDecreaseContainer, emailDecreasing, emailLabelResolver, '−');
                if (emailIncreaseContainer) emailIncreaseContainer.innerHTML = '';
                if (emailDecreaseTotalEl) {
                    emailDecreaseTotalEl.textContent =
                        `${(emailRiskSignals.decreasing?.total_influence ?? 0).toFixed(2)}`;
                }
                if (emailIncreaseTotalEl) emailIncreaseTotalEl.textContent = '—';
            /* Ranked risk factor breakdown (from confidence_scorer) */
            const componentScores = data.details?.component_scores || {};
            const componentLabels = {
                ml_classifier:     'ML Classifier',
                url_analysis:      'Embedded URL Analysis',
                sensitive_request: 'Sensitive Info Request',
                polite_request:    'Generic Greeting Pattern',
                short_email_risk:  'Short/Urgent Email Pattern'
            };

            const rankedComponents = Object.entries(componentScores)
                .sort((a, b) => {
                    const weightA = COMPONENT_WEIGHTS[a[0]] || 0;
                    const weightB = COMPONENT_WEIGHTS[b[0]] || 0;
                    return (b[1] * weightB) - (a[1] * weightA);
                });

            const rankingContainer = document.getElementById('email-risk-ranking');
            if (rankingContainer) {
                rankingContainer.innerHTML = '';
                rankedComponents.forEach(([key, score]) => {
                    const pct = Math.round(score * 100);
                    const tone = pct >= 50 ? 'danger' : pct >= 30 ? 'warn' : 'safe';

                    const row = document.createElement('div');
                    row.className = 'ranking-row';
                    row.innerHTML = `
                        <div class="ranking-row__label">${componentLabels[key] || key}</div>
                        <div class="ranking-row__bar">
                            <div class="ranking-row__fill ranking-row__fill--${tone}" style="width:${pct}%"></div>
                        </div>
                        <div class="ranking-row__pct">${pct}%</div>
                    `;
                    rankingContainer.appendChild(row);
                });
            }

            /* Risk indicators */
            emailIndicatorsList.innerHTML = '';
            const reasons = data.details?.reasons || [];

            if (reasons.length === 0) {
                emailIndicatorsList.appendChild(makeIndicator('No immediate threat anomalies detected.', 'safe', 0));
                emailIndicatorCount.textContent = '0 signals';
            } else {
                const reasonTone = data.is_phishing ? 'danger' : 'safe';
                reasons.forEach((reason, i) => {
                    emailIndicatorsList.appendChild(makeIndicator(reason, reasonTone, i));
                });
                emailIndicatorCount.textContent = `${reasons.length} signal${reasons.length !== 1 ? 's' : ''}`;
            }

        } catch (err) {
            console.error('[Arcis Email]', err);
            showError(`Analysis failed: ${err.message}. Ensure the Flask API is running on ${API_BASE}`);
        } finally {
            setLoading(emailSubmitBtn, false, 'Analyze Email Risk');
        }
    });

    /* ════════════════════════════════════════════════════════
       UTILITY
       ════════════════════════════════════════════════════════ */

    function showError(message) {
        // Non-blocking inline toast instead of blocking alert
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
            background: rgba(5, 18, 18, 0.96); border: 1px solid rgba(244,63,94,0.35);
            color: #fca5a5; font-size: 13px; font-weight: 500;
            padding: 12px 20px; border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            z-index: 9999; max-width: 480px; text-align: center;
            backdrop-filter: blur(16px);
            animation: fade-up 0.3s cubic-bezier(0.16,1,0.3,1) forwards;
        `;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 6000);
    }

});