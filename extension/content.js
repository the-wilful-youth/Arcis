/* ============================================================
   Arcis Phishing Shield — Gmail Content Script
   Spider avatar widget: bottom-left float → expand → scan → contract
   ============================================================ */

(function () {
  'use strict';

  /* Prevent double injection */
  if (document.getElementById('arcis-widget-root')) return;

  /* ── State ─────────────────────────────────────────────── */
  let isExpanded = false;
  let isScanning = false;
  let lastVerdict = null; // { safe, risk, reasons }

  /* ── Build DOM ─────────────────────────────────────────── */
  const root = document.createElement('div');
  root.id = 'arcis-widget-root';
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-label', 'Arcis Phishing Shield');

  root.innerHTML = `
    <!-- Floating Avatar Bubble -->
    <div id="arcis-avatar" title="Arcis Phishing Shield — click to scan this email">
      <svg id="arcis-spider-svg" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <style>
          @keyframes arcis-float {
            0%,100%{transform:translateY(0)} 50%{transform:translateY(-4px)}
          }
          @keyframes arcis-blink {
            0%,90%,100%{transform:scaleY(1)} 95%{transform:scaleY(0.1)}
          }
          @keyframes arcis-leg-l {
            0%,100%{transform:rotate(0deg)} 50%{transform:rotate(-5deg)}
          }
          @keyframes arcis-leg-r {
            0%,100%{transform:rotate(0deg)} 50%{transform:rotate(5deg)}
          }
          @keyframes arcis-lens {
            0%,100%{transform:translate(0,0) rotate(0deg)}
            25%{transform:translate(3px,-2px) rotate(5deg)}
            75%{transform:translate(-3px,1px) rotate(-5deg)}
          }
          @keyframes arcis-glow {
            0%,100%{filter:drop-shadow(0 0 2px #A3E635)}
            50%{filter:drop-shadow(0 0 8px #A3E635)}
          }
          .arcis-char { animation:arcis-float 3s ease-in-out infinite; transform-origin:center; }
          .arcis-eye  { fill:white; transform-origin:center; animation:arcis-blink 4s infinite; }
          .arcis-ll   { transform-origin:40px 50px; animation:arcis-leg-l 1.5s ease-in-out infinite; }
          .arcis-lr   { transform-origin:60px 50px; animation:arcis-leg-r 1.5s ease-in-out infinite; }
          .arcis-mag  { animation:arcis-lens 4s ease-in-out infinite; transform-origin:center; }
          .arcis-glow { animation:arcis-glow 2s ease-in-out infinite; }
        </style>
        <rect fill="transparent" width="100" height="100"/>
        <g class="arcis-char">
          <!-- Legs -->
          <g fill="none" stroke="#52525b" stroke-linecap="round" stroke-width="3">
            <path class="arcis-ll" d="M35 45 Q20 40 15 55"/>
            <path class="arcis-ll" d="M35 55 Q20 60 15 75" style="animation-delay:.2s"/>
            <path class="arcis-lr" d="M65 45 Q80 40 85 55"/>
            <path class="arcis-lr" d="M65 55 Q80 60 85 75" style="animation-delay:.2s"/>
          </g>
          <!-- Body -->
          <circle cx="50" cy="55" r="22" fill="#71717a"/>
          <circle cx="50" cy="55" r="18" fill="#52525b" opacity=".3"/>
          <!-- Eyes -->
          <circle class="arcis-eye" cx="42" cy="52" r="6"/>
          <circle class="arcis-eye" cx="58" cy="52" r="6"/>
          <circle cx="43" cy="51" r="2" fill="#18181b"/>
          <circle cx="57" cy="51" r="2" fill="#18181b"/>
          <circle cx="34" cy="58" r="1.5" fill="white" opacity=".8"/>
          <circle cx="66" cy="58" r="1.5" fill="white" opacity=".8"/>
          <!-- Detective Hat -->
          <path d="M32 38 L68 38 L72 46 L28 46 Z" fill="#94A3B8"/>
          <path d="M40 38 L40 30 Q50 28 60 30 L60 38" fill="#94A3B8" stroke="#64748b" stroke-width="1"/>
          <rect x="32" y="42" width="36" height="2" fill="#475569"/>
          <!-- Magnifier -->
          <g class="arcis-mag">
            <path class="arcis-glow" d="M45 68 Q50 75 55 68" fill="none" stroke="#A3E635" stroke-linecap="round" stroke-width="3"/>
            <g transform="translate(50,78)">
              <circle cx="0" cy="0" r="10" fill="#2DD4BF" opacity=".2"/>
              <circle cx="0" cy="0" r="10" fill="none" stroke="#94A3B8" stroke-width="2"/>
              <line x1="7" y1="7" x2="12" y2="12" stroke="#94A3B8" stroke-linecap="round" stroke-width="3"/>
              <path d="M-5 -3 Q0 -5 5 -3" fill="none" stroke="white" stroke-linecap="round" stroke-width="1" opacity=".6"/>
            </g>
          </g>
        </g>
      </svg>
      <!-- Pulse ring -->
      <div id="arcis-pulse"></div>
    </div>

    <!-- Expanded Panel -->
    <div id="arcis-panel" aria-hidden="true">
      <!-- Panel Header -->
      <div id="arcis-panel-header">
        <div id="arcis-panel-brand">
          <svg width="22" height="22" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0">
            <circle cx="50" cy="55" r="22" fill="#71717a"/>
            <circle class="arcis-eye" cx="42" cy="52" r="6"/>
            <circle class="arcis-eye" cx="58" cy="52" r="6"/>
            <circle cx="43" cy="51" r="2" fill="#18181b"/>
            <circle cx="57" cy="51" r="2" fill="#18181b"/>
            <path d="M32 38 L68 38 L72 46 L28 46 Z" fill="#94A3B8"/>
            <path d="M40 38 L40 30 Q50 28 60 30 L60 38" fill="#94A3B8"/>
            <rect x="32" y="42" width="36" height="2" fill="#475569"/>
          </svg>
          <div>
            <span id="arcis-title">Arcis Shield</span>
            <span id="arcis-subtitle">Email Phishing Detector</span>
          </div>
        </div>
        <button id="arcis-close-btn" title="Close" aria-label="Close Arcis panel">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M2 2L12 12M12 2L2 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </button>
      </div>

      <!-- Idle State: prompt user to scan -->
      <div id="arcis-idle-state" class="arcis-state">
        <div id="arcis-idle-icon">
          <svg width="36" height="36" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <g fill="none" stroke="#52525b" stroke-linecap="round" stroke-width="4">
              <path d="M35 45 Q20 40 15 55"/>
              <path d="M35 55 Q20 60 15 75"/>
              <path d="M65 45 Q80 40 85 55"/>
              <path d="M65 55 Q80 60 85 75"/>
            </g>
            <circle cx="50" cy="55" r="22" fill="#71717a"/>
            <circle cx="42" cy="52" r="6" fill="white"/>
            <circle cx="58" cy="52" r="6" fill="white"/>
            <circle cx="43" cy="51" r="2" fill="#18181b"/>
            <circle cx="57" cy="51" r="2" fill="#18181b"/>
            <path d="M32 38 L68 38 L72 46 L28 46 Z" fill="#94A3B8"/>
            <path d="M40 38 L40 30 Q50 28 60 30 L60 38" fill="#94A3B8"/>
            <rect x="32" y="42" width="36" height="2" fill="#475569"/>
          </svg>
        </div>
        <p id="arcis-idle-text">Ready to inspect this email for phishing threats.</p>
        <button id="arcis-scan-btn" class="arcis-btn arcis-btn--primary">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
            <circle cx="5.5" cy="5.5" r="4" stroke="currentColor" stroke-width="1.5"/>
            <path d="M8.5 8.5L11.5 11.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          </svg>
          Scan This Email
        </button>
        <p id="arcis-no-email-msg" class="arcis-hint" style="display:none">
          ⚠️ No email open. Please open an email first.
        </p>
      </div>

      <!-- Scanning State -->
      <div id="arcis-scanning-state" class="arcis-state" style="display:none">
        <div id="arcis-spider-scan-anim">
          <div class="arcis-scan-ring arcis-ring1"></div>
          <div class="arcis-scan-ring arcis-ring2"></div>
          <div class="arcis-scan-ring arcis-ring3"></div>
          <svg width="40" height="40" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" style="position:relative;z-index:2">
            <circle cx="50" cy="55" r="22" fill="#71717a"/>
            <circle cx="42" cy="52" r="6" fill="white"/>
            <circle cx="58" cy="52" r="6" fill="white"/>
            <circle cx="43" cy="51" r="2" fill="#18181b"/>
            <circle cx="57" cy="51" r="2" fill="#18181b"/>
            <path d="M32 38 L68 38 L72 46 L28 46 Z" fill="#94A3B8"/>
            <path d="M40 38 L40 30 Q50 28 60 30 L60 38" fill="#94A3B8"/>
            <rect x="32" y="42" width="36" height="2" fill="#475569"/>
          </svg>
        </div>
        <p class="arcis-scanning-label">Analysing email…</p>
        <div id="arcis-scan-dots">
          <span></span><span></span><span></span>
        </div>
      </div>

      <!-- Result State -->
      <div id="arcis-result-state" class="arcis-state" style="display:none">
        <div id="arcis-verdict-badge">
          <span id="arcis-verdict-icon">✓</span>
          <span id="arcis-verdict-label">SAFE</span>
        </div>
        <div id="arcis-risk-bar-wrap">
          <div id="arcis-risk-bar">
            <div id="arcis-risk-fill"></div>
          </div>
          <div id="arcis-risk-labels">
            <span>Risk</span>
            <span id="arcis-risk-pct">0%</span>
          </div>
        </div>
        <div id="arcis-findings-box">
          <span class="arcis-findings-title">Signals Detected</span>
          <ul id="arcis-findings-list"></ul>
        </div>
        <a id="arcis-more-link" href="http://localhost:5001" target="_blank" rel="noopener noreferrer">
          <svg width="11" height="11" viewBox="0 0 11 11" fill="none">
            <path d="M1 5.5h9M6.5 1.5l4 4-4 4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          For full report, launch Arcis Dashboard
        </a>
        <button id="arcis-rescan-btn" class="arcis-btn arcis-btn--ghost">
          Scan Again
        </button>
      </div>

      <!-- Panel Footer -->
      <div id="arcis-panel-footer">
        Arcis Threat Labs · Privacy-first · Only scans the open email
      </div>
    </div>
  `;

  document.body.appendChild(root);

  /* ── Refs ───────────────────────────────────────────────── */
  const avatar      = root.querySelector('#arcis-avatar');
  const panel       = root.querySelector('#arcis-panel');
  const closeBtn    = root.querySelector('#arcis-close-btn');
  const scanBtn     = root.querySelector('#arcis-scan-btn');
  const rescanBtn   = root.querySelector('#arcis-rescan-btn');
  const idleState   = root.querySelector('#arcis-idle-state');
  const scanState   = root.querySelector('#arcis-scanning-state');
  const resultState = root.querySelector('#arcis-result-state');
  const noEmailMsg  = root.querySelector('#arcis-no-email-msg');

  const verdictBadge = root.querySelector('#arcis-verdict-badge');
  const verdictIcon  = root.querySelector('#arcis-verdict-icon');
  const verdictLabel = root.querySelector('#arcis-verdict-label');
  const riskFill     = root.querySelector('#arcis-risk-fill');
  const riskPct      = root.querySelector('#arcis-risk-pct');
  const findingsList = root.querySelector('#arcis-findings-list');

  /* ── Expand / Contract ──────────────────────────────────── */
  function expand() {
    isExpanded = true;
    root.classList.add('arcis-expanded');
    panel.setAttribute('aria-hidden', 'false');
    avatar.setAttribute('aria-expanded', 'true');
    /* reset to idle unless there is a cached verdict */
    if (!lastVerdict) showState('idle');
    else showState('result');
  }

  function contract() {
    isExpanded = false;
    root.classList.remove('arcis-expanded');
    panel.setAttribute('aria-hidden', 'true');
    avatar.setAttribute('aria-expanded', 'false');
  }

  avatar.addEventListener('click', () => {
    isExpanded ? contract() : expand();
  });

  closeBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    contract();
  });

  /* ── State helpers ──────────────────────────────────────── */
  function showState(name) {
    idleState.style.display   = name === 'idle'    ? 'flex' : 'none';
    scanState.style.display   = name === 'scan'    ? 'flex' : 'none';
    resultState.style.display = name === 'result'  ? 'flex' : 'none';
  }

  /* ── Gmail email extraction ─────────────────────────────── */
  function extractEmailData() {
    /* Gmail renders the open email in .h7 / .a3s.aiL containers */
    const subjectEl = document.querySelector('h2.hP');
    const senderEl  = document.querySelector('.gD');          // sender name+email
    const bodyEl    = document.querySelector('.a3s.aiL');     // email body text

    if (!subjectEl && !senderEl && !bodyEl) return null;

    // 1. Extract CC recipients
    const ccEmails = [];
    const ccContainer = document.querySelector('.az9'); // Gmail CC container class
    if (ccContainer) {
      const ccSpans = ccContainer.querySelectorAll('[email]');
      ccSpans.forEach(span => {
        const email = span.getAttribute('email');
        if (email && !ccEmails.includes(email)) {
          ccEmails.push(email.trim().toLowerCase());
        }
      });
    } else {
      // Fallback: look for spans with class 'hb' or elements containing CC
      const ccElements = document.querySelectorAll('span.hb [email], .hb [email]');
      ccElements.forEach(el => {
        const email = el.getAttribute('email');
        if (email && !ccEmails.includes(email)) {
          ccEmails.push(email.trim().toLowerCase());
        }
      });
    }

    // 2. Extract links in the email body
    const links = [];
    if (bodyEl) {
      const anchors = bodyEl.querySelectorAll('a[href]');
      anchors.forEach(a => {
        const href = a.getAttribute('href');
        if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
          // Resolve Google redirection links if necessary
          let targetUrl = href;
          if (href.includes('google.com/url?q=')) {
            try {
              const urlObj = new URL(href);
              targetUrl = urlObj.searchParams.get('q') || href;
            } catch(e) {}
          }
          if (!links.includes(targetUrl)) {
            links.push(targetUrl);
          }
        }
      });
    }

    return {
      subject : subjectEl ? subjectEl.textContent.trim() : '',
      sender  : senderEl  ? (senderEl.getAttribute('email') || senderEl.textContent.trim()) : '',
      body    : bodyEl    ? bodyEl.innerText.trim().slice(0, 2000) : '',   // cap at 2 KB
      cc      : ccEmails,
      links   : links
    };
  }

  /* ── Scan logic ─────────────────────────────────────────── */
  async function runScan() {
    if (isScanning) return;

    const emailData = extractEmailData();
    if (!emailData) {
      noEmailMsg.style.display = 'block';
      return;
    }
    noEmailMsg.style.display = 'none';
    isScanning = true;
    showState('scan');

    try {
      chrome.runtime.sendMessage({
        action: 'analyze_email',
        data: {
          email  : emailData.sender,
          subject: emailData.subject,
          body   : emailData.body,
          spf    : 'none',
          dkim   : 'none',
          dmarc  : 'none'
        },
        cc: emailData.cc,
        links: emailData.links
      }, response => {
        let data;
        if (response && response.success) {
          data = response.data;
        } else {
          console.warn('API fetch failed or was blocked, falling back to demo mode:', response ? response.error : 'No response');
          data = buildDemoVerdict(emailData);
        }
        renderVerdict(data);
      });
    } catch (_) {
      /* Backend offline – show demo verdict so UI still demonstrates */
      renderVerdict(buildDemoVerdict(emailData));
    } finally {
      isScanning = false;
    }
  }

  /* Demo verdict when backend is unavailable */
  function buildDemoVerdict(emailData) {
    const phishKeywords = ['verify', 'urgent', 'account', 'click', 'password', 'login', 'bank', 'suspend'];
    const bodyLower = emailData.body.toLowerCase() + emailData.subject.toLowerCase();
    const hits = phishKeywords.filter(k => bodyLower.includes(k));
    const risk = Math.min(95, hits.length * 15);
    return {
      risk_score_pct: risk,
      details: {
        reasons: hits.length
          ? hits.map(k => `Phishing keyword detected: "${k}"`)
          : ['No immediate threats detected in email content.']
      }
    };
  }

  function renderVerdict(data) {
    const risk = data.risk_score_pct || 0;
    lastVerdict = data;

    riskPct.textContent   = `${risk}%`;
    riskFill.style.width  = `${risk}%`;

    /* Clear old verdict classes */
    verdictBadge.className = '';

    if (risk < 30) {
      verdictBadge.classList.add('arcis-safe');
      verdictIcon.textContent  = '✓';
      verdictLabel.textContent = 'SAFE';
      riskFill.style.background = 'linear-gradient(90deg,#10b981,#34d399)';
    } else if (risk < 70) {
      verdictBadge.classList.add('arcis-warn');
      verdictIcon.textContent  = '⚠';
      verdictLabel.textContent = 'SUSPICIOUS';
      riskFill.style.background = 'linear-gradient(90deg,#f59e0b,#fbbf24)';
    } else {
      verdictBadge.classList.add('arcis-danger');
      verdictIcon.textContent  = '✕';
      verdictLabel.textContent = 'PHISHING';
      riskFill.style.background = 'linear-gradient(90deg,#ef4444,#f87171)';
    }

    findingsList.innerHTML = '';
    const reasons = (data.details && data.details.reasons) || [];
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      findingsList.appendChild(li);
    });
    if (!reasons.length) {
      const li = document.createElement('li');
      li.textContent = 'No specific signals detected.';
      findingsList.appendChild(li);
    }

    showState('result');

    /* Auto-contract after 8 s */
    setTimeout(() => { if (isExpanded) contract(); }, 8000);
  }

  /* ── Button listeners ───────────────────────────────────── */
  scanBtn.addEventListener('click', (e) => { e.stopPropagation(); runScan(); });
  rescanBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    lastVerdict = null;
    showState('idle');
  });

  /* ── Keyboard dismiss ───────────────────────────────────── */
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isExpanded) contract();
  });

})();
