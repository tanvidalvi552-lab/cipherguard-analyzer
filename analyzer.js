// ==========================================================================
// 1. CLIENT-SIDE PASSWORD ANALYSIS ENGINE
// ==========================================================================

/**
 * Core analysis — runs entirely in the browser. No backend required.
 */
async function analyzePassword(password) {
    const score    = calcScore(password);
    const entropy  = calcEntropy(password);
    const crackTime = calcCrackTime(entropy);
    const patterns = detectPatterns(password);
    const verdict  = ['CRITICAL', 'WEAK', 'MODERATE', 'STRONG', 'FORTRESS'][score];
    const breachCount = await checkBreach(password);
    const suggestedAlternative = generateSecurePassphrase();

    return { score, entropy, crackTime, patterns, verdict, breachCount, suggestedAlternative };
}

// --------------------------------------------------------------------------
// Score  (0–4)                                                         
// --------------------------------------------------------------------------
function calcScore(pw) {
    let s = 0;
    if (pw.length >= 8)  s++;
    if (pw.length >= 14) s++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++;
    if (/[^a-zA-Z0-9]/.test(pw)) s++;
    // Cap at 4
    return Math.min(s, 4);
}

// --------------------------------------------------------------------------
// Shannon entropy
// --------------------------------------------------------------------------
function calcEntropy(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw))        pool += 26;
    if (/[A-Z]/.test(pw))        pool += 26;
    if (/[0-9]/.test(pw))        pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
    if (pool === 0) return 0;
    return parseFloat((pw.length * Math.log2(pool)).toFixed(1));
}

// --------------------------------------------------------------------------
// Human-readable crack time based on entropy
// (assuming 10 billion guesses/sec — bcrypt/scrypt would be much slower,
//  but we model raw MD5/SHA1 style which is the worst case for users)
// --------------------------------------------------------------------------
function calcCrackTime(entropy) {
    const guessesPerSec = 1e10;
    const combinations  = Math.pow(2, entropy);
    const avgGuesses    = combinations / 2;
    const seconds       = avgGuesses / guessesPerSec;

    if (seconds < 1)         return 'Instant';
    if (seconds < 60)        return `${Math.round(seconds)} Seconds`;
    if (seconds < 3600)      return `${Math.round(seconds / 60)} Minutes`;
    if (seconds < 86400)     return `${Math.round(seconds / 3600)} Hours`;
    if (seconds < 2592000)   return `${Math.round(seconds / 86400)} Days`;
    if (seconds < 31536000)  return `${Math.round(seconds / 2592000)} Months`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000).toLocaleString()} Years`;
    if (seconds < 3.154e13)  return `${Math.round(seconds / 3153600000).toLocaleString()} Centuries`;
    return 'Heat Death of Universe';
}

// --------------------------------------------------------------------------
// Pattern detection
// --------------------------------------------------------------------------
function detectPatterns(pw) {
    const findings = [];
    const lower = pw.toLowerCase();

    if (pw.length < 8)
        findings.push('Too short — minimum 8 characters recommended.');
    if (/^[a-zA-Z]+$/.test(pw))
        findings.push('Letters only — no digits or symbols detected.');
    if (/^[0-9]+$/.test(pw))
        findings.push('Digits only — extremely vulnerable to numeric brute force.');
    if (/(.)\1{2,}/.test(pw))
        findings.push('Repeated characters detected (e.g. "aaa", "111").');
    if (/^(.+?)\1+$/.test(pw))
        findings.push('Repeating pattern found — string is cyclically predictable.');
    if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(pw))
        findings.push('Sequential alphabetic run detected (e.g. "abcd").');
    if (/(?:012|123|234|345|456|567|678|789|890)/.test(pw))
        findings.push('Sequential numeric run detected (e.g. "1234").');
    if (['password','passw0rd','qwerty','letmein','welcome','monkey','dragon','master',
         'admin','login','iloveyou','sunshine','princess','football','shadow'].includes(lower))
        findings.push('Common dictionary word — appears in top-10K leaked password lists.');
    if (/^[A-Z][a-z]+\d{1,4}[!@#$]?$/.test(pw))
        findings.push('Classic "Word + Numbers + Symbol" template — well-known attack pattern.');

    return findings;
}

// --------------------------------------------------------------------------
// Breach check via HaveIBeenPwned k-anonymity API (no full hash sent)
// --------------------------------------------------------------------------
async function checkBreach(pw) {
    try {
        const msgBuffer  = new TextEncoder().encode(pw);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
        const hashArray  = Array.from(new Uint8Array(hashBuffer));
        const hashHex    = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        const prefix  = hashHex.slice(0, 5);
        const suffix  = hashHex.slice(5);

        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { 'Add-Padding': 'true' }
        });

        if (!response.ok) return 0;

        const text = await response.text();
        const match = text.split('\n').find(line => line.startsWith(suffix));
        return match ? parseInt(match.split(':')[1].trim(), 10) : 0;
    } catch {
        // Network blocked or API unavailable — return 0 gracefully
        return 0;
    }
}

// --------------------------------------------------------------------------
// Secure passphrase generator
// --------------------------------------------------------------------------
function generateSecurePassphrase() {
    const adjectives = ['Crimson','Stellar','Quantum','Arctic','Oblique','Vortex','Silent','Nimble','Frozen','Galactic'];
    const nouns      = ['Cipher','Phantom','Nexus','Forge','Vector','Specter','Matrix','Apex','Bastion','Helix'];
    const symbols    = ['!','@','#','$','%','&','*'];
    const rand       = (arr) => arr[Math.floor(Math.random() * arr.length)];
    const num        = Math.floor(Math.random() * 900) + 100; // 3-digit
    return `${rand(adjectives)}-${rand(nouns)}-${num}${rand(symbols)}`;
}


// ==========================================================================
// 2. MAIN ENTRY POINT — exposed globally for HTML onclick attributes
// ==========================================================================
window.runAnalysis = async function () {
    const passwordInput   = document.getElementById('passwordInput');
    const analyzeBtn      = document.getElementById('analyzeBtn');
    const resultsPanel    = document.getElementById('resultsPanel');

    if (!passwordInput || !analyzeBtn || !resultsPanel) {
        console.error('Critical: required DOM elements missing.');
        return;
    }

    const password = passwordInput.value.trim();
    if (!password) {
        alert('INPUT BUFFER EMPTY: Please enter a string sequence to evaluate.');
        return;
    }

    analyzeBtn.textContent = 'Decrypting...';
    analyzeBtn.disabled = true;

    try {
        const data = await analyzePassword(password);
        renderResults(data);

        resultsPanel.classList.remove('hidden');
        resultsPanel.scrollIntoView({ behavior: 'smooth' });

        // Staggered card reveal animations
        const metricCards    = document.querySelectorAll('.metrics-grid .metric-card');
        const patternCard    = document.getElementById('card-patterns');
        const suggestionCard = document.getElementById('card-suggestion');

        metricCards.forEach(c => c.classList.remove('visible'));
        patternCard    && patternCard.classList.remove('visible');
        suggestionCard && suggestionCard.classList.remove('visible');

        metricCards.forEach((card, i) => {
            setTimeout(() => card.classList.add('visible'), i * 200);
        });
        setTimeout(() => patternCard    && patternCard.classList.add('visible'),    4 * 200);
        setTimeout(() => suggestionCard && suggestionCard.classList.add('visible'), 5 * 200);

    } catch (err) {
        console.error('Analysis error:', err);
        alert('Analysis failed — please try again.');
    } finally {
        analyzeBtn.textContent = 'Bypass Firewall & Scan';
        analyzeBtn.disabled = false;
    }
};


// ==========================================================================
// 3. RENDER RESULTS TO DOM
// ==========================================================================
function renderResults(data) {
    const $ = id => document.getElementById(id);

    const scoreValue      = $('scoreValue');
    const scoreBar        = $('scoreProgressBar');
    const statusBadge     = $('overallStatusBadge');
    const entropyValue    = $('entropyValue');
    const entropyDesc     = $('entropyDesc');
    const crackTimeValue  = $('crackTimeValue');
    const crackTimeDesc   = $('crackTimeDesc');
    const breachValue     = $('breachValue');
    const breachDesc      = $('breachDesc');
    const patternList     = $('patternList');
    const suggestedPw     = $('suggestedPassword');

    if (scoreValue)     scoreValue.textContent    = `${data.score} / 4`;
    if (statusBadge)    statusBadge.textContent   = data.verdict;
    if (crackTimeValue) crackTimeValue.textContent = data.crackTime;
    if (crackTimeDesc)  crackTimeDesc.textContent  = 'Calculated at a speed of 10 Billion variants/sec';
    if (suggestedPw)    suggestedPw.textContent    = data.suggestedAlternative || '••••••••••••••••';

    // Entropy counter + description
    if (entropyValue) animateNumericCounter(entropyValue, 0, data.entropy, 800, ' Bits');
    if (entropyDesc) {
        if      (data.entropy < 28) entropyDesc.textContent = 'Very low entropy — easily predictable.';
        else if (data.entropy < 50) entropyDesc.textContent = 'Moderate entropy — some complexity present.';
        else if (data.entropy < 70) entropyDesc.textContent = 'Good entropy — reasonably complex.';
        else                         entropyDesc.textContent = 'High entropy — cryptographically strong.';
    }

// ==========================================================================
    // POSITION TO REPLACE: Dynamic Breach Warning State Controller inside analyzer.js
    // ==========================================================================
    const breachCard = document.getElementById('card-breach');
    const alarmBanner = document.getElementById('breachAlarmBanner');

    if (breachValue && breachCard && alarmBanner) {
        // Clear any leftover state filters from previous scan runs
        breachCard.classList.remove('hazard-active-pulse');
        alarmBanner.style.display = 'none';

        if (data.breachCount > 0) {
            // TARGET DETECTED: Fire dynamic counters and engage crimson alert states
            animateNumericCounter(breachValue, 0, data.breachCount, 1000, ' Incidents');
            breachValue.style.color = '#ff0055';
            
            // Map our cinematic breathing pulses and make the warning label wire visible
            breachCard.classList.add('hazard-active-pulse');
            alarmBanner.style.display = 'block';
            if(breachDesc) breachDesc.textContent = "CRITICAL: String signature flagged in public leak indexes.";
        } else {
            // TARGET CLEAR: Establish green baseline parameters safely
            breachValue.textContent = '0 Incidents';
            breachValue.style.color = '#00ff66';
            if(breachDesc) breachDesc.textContent = "Clean Registry: No malicious credential history cached.";
        }
    }

    // Timeline needle
    const needle      = $('timelineExpansionNeedle');
    const tickSeconds = $('tick-seconds');
    const tickYears   = $('tick-years');
    const tickCenturies = $('tick-centuries');

    if (needle && tickSeconds && tickYears && tickCenturies) {
        needle.style.width = '0%';
        [tickSeconds, tickYears, tickCenturies].forEach(t => {
            t.style.color = '#506578'; t.style.textShadow = 'none';
        });

        const t = data.crackTime.toLowerCase();
        if (['instant','second','minute','hour'].some(k => t.includes(k))) {
            needle.style.width = '10%';
            needle.style.backgroundColor  = '#ff0055';
            needle.style.boxShadow        = '0 0 10px #ff0055';
            tickSeconds.style.color       = '#ff0055';
            tickSeconds.style.textShadow  = '0 0 8px rgba(255,0,85,0.6)';
        } else if (['day','month','year'].some(k => t.includes(k))) {
            needle.style.width = '50%';
            needle.style.backgroundColor = '#ffaa00';
            needle.style.boxShadow       = '0 0 10px #ffaa00';
            tickSeconds.style.color      = '#00f0ff';
            tickYears.style.color        = '#ffaa00';
            tickYears.style.textShadow   = '0 0 8px rgba(255,170,0,0.6)';
        } else {
            needle.style.width = '100%';
            needle.style.backgroundColor   = '#00ff66';
            needle.style.boxShadow         = '0 0 10px #00ff66';
            tickSeconds.style.color        = '#00f0ff';
            tickYears.style.color          = '#00f0ff';
            tickCenturies.style.color      = '#00ff66';
            tickCenturies.style.textShadow = '0 0 8px rgba(0,255,102,0.6)';
        }
    }

    // Score progress bar
    if (scoreBar) {
        const colors = ['#ff0055','#ff0055','#ffaa00','#a3e635','#00ff66','#00ff66'];
        scoreBar.style.width           = `${(data.score / 4) * 100}%`;
        scoreBar.style.backgroundColor = colors[data.score];
    }

    // Pattern list
    if (patternList) {
        patternList.innerHTML = '';
        if (!data.patterns || data.patterns.length === 0) {
            patternList.innerHTML = '<li>✓ Layout passes structural heuristic benchmarks.</li>';
        } else {
            data.patterns.forEach(p => {
                const li = document.createElement('li');
                li.textContent = `⚠ ${p}`;
                patternList.appendChild(li);
            });
        }
    }
}


// ==========================================================================
// 4. ANIMATION UTILITY
// ==========================================================================
function animateNumericCounter(el, start, end, duration, suffix = '') {
    const startTime = performance.now();
    const isFloat   = end % 1 !== 0;

    function tick(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        const eased    = 1 - Math.pow(1 - progress, 3);
        const current  = start + (end - start) * eased;
        el.textContent = (isFloat ? current.toFixed(1) : Math.floor(current).toLocaleString()) + suffix;
        if (progress < 1) requestAnimationFrame(tick);
        else el.textContent = (isFloat ? end.toFixed(1) : end.toLocaleString()) + suffix;
    }
    requestAnimationFrame(tick);
}


// ==========================================================================
// 5. DOM-READY BINDINGS
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('passwordInput');
    const copyBtn       = document.getElementById('copyBtn');

    // Enter key triggers analysis
    if (passwordInput) {
        passwordInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') window.runAnalysis();
        });
    }

    // Copy suggested password
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const suggested = document.getElementById('suggestedPassword');
            if (suggested && navigator.clipboard) {
                navigator.clipboard.writeText(suggested.textContent).then(() => {
                    const orig = copyBtn.textContent;
                    copyBtn.textContent = 'Copied!';
                    setTimeout(() => { copyBtn.textContent = orig; }, 1500);
                });
            }
        });
    }
});