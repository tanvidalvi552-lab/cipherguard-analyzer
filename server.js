// ==========================================================================
//  CIPHERGUARD — PASSWORD ANALYZER SERVER
//  Stack : Express · Node.js crypto/https · OpenAI SDK
// ==========================================================================


// ── 1. IMPORTS & BOOTSTRAP ─────────────────────────────────────────────────

require('dotenv').config();

const express = require('express');
const crypto  = require('node:crypto');
const https   = require('node:https');

const OpenAI = require('openai');

const app  = express();
const PORT = process.env.PORT || 3000;

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

app.use(express.json());
app.use(express.static('./'));


// ── 2. ENTROPY ENGINE ──────────────────────────────────────────────────────

function calculateEntropy(password) {

    if (!password || password.length === 0) return 0;

    let pool = 0;

    if (/[a-z]/.test(password))         pool += 26;
    if (/[A-Z]/.test(password))         pool += 26;
    if (/[0-9]/.test(password))         pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 32;

    return +(password.length * Math.log2(pool)).toFixed(1);
}


// ── 3. CRACK-TIME ESTIMATOR ────────────────────────────────────────────────

const GUESSES_PER_SEC = 10_000_000_000n;

function estimateCrackTime(entropy) {

    if (entropy <= 0) return 'Instantly';

    const combinations = 2n ** BigInt(Math.floor(entropy));
    const seconds = combinations / (2n * GUESSES_PER_SEC);

    if (seconds === 0n) return 'Instantly';
    if (seconds < 60n) return `${seconds} seconds`;
    if (seconds < 3600n) return `${seconds / 60n} minutes`;
    if (seconds < 86400n) return `${seconds / 3600n} hours`;
    if (seconds < 2592000n) return `${seconds / 86400n} days`;
    if (seconds < 31536000n) return `${seconds / 2592000n} months`;
    if (seconds < 3153600000n) return `${seconds / 31536000n} years`;

    return 'Centuries+';
}


// ── 4. PATTERN SCANNER ─────────────────────────────────────────────────────

const COMMON_PATTERNS = [
    'password',
    '123456',
    'qwerty',
    'abc123',
    'letmein',
    'iloveyou',
    'monkey',
    'dragon',
    'master',
    'welcome'
];

function scanPatterns(password) {

    const warnings = [];
    const lp = password.toLowerCase();

    if (password.length < 8)
        warnings.push('Critically short — minimum 8 characters required.');
    else if (password.length < 12)
        warnings.push('Short password — aim for at least 12 characters.');

    if (/(.)\1{2,}/.test(password))
        warnings.push('Repeating character sequence detected.');

    if (hasSequentialPattern(password))
        warnings.push('Sequential pattern detected.');

    if (COMMON_PATTERNS.some(p => lp.includes(p)))
        warnings.push('Common password string detected.');

    const typeCount = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/]
        .filter(r => r.test(password)).length;

    if (typeCount < 2)
        warnings.push('Use at least two character types.');
    else if (typeCount < 3)
        warnings.push('Add more variety.');

    return warnings;
}

function hasSequentialPattern(password) {

    for (let i = 0; i < password.length - 2; i++) {

        const a = password.charCodeAt(i);
        const b = password.charCodeAt(i + 1);
        const c = password.charCodeAt(i + 2);

        if (
            (b === a + 1 && c === b + 1) ||
            (b === a - 1 && c === b - 1)
        ) {
            return true;
        }
    }

    return false;
}


// ── 5. STRENGTH SCORER ─────────────────────────────────────────────────────

function calculateScore(password, entropy, breachCount) {

    let score = 0;

    if (password.length >= 12) score++;
    if (entropy >= 60) score++;

    const types = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/]
        .filter(r => r.test(password)).length;

    if (types >= 3) score++;

    if (breachCount === 0 && password.length >= 8)
        score++;

    return score;
}


// ── 6. BREACH CHECKER ──────────────────────────────────────────────────────

function checkBreachExposure(password) {

    const hash = crypto
        .createHash('sha1')
        .update(password)
        .digest('hex')
        .toUpperCase();

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    return new Promise((resolve) => {

        const options = {
            hostname : 'api.pwnedpasswords.com',
            path     : `/range/${prefix}`,
            method   : 'GET',
            headers  : {
                'User-Agent'  : 'CipherGuard',
                'Add-Padding' : 'true'
            }
        };

        const req = https.request(options, (res) => {

            let body = '';

            res.on('data', chunk => body += chunk);

            res.on('end', () => {

                if (res.statusCode !== 200) {
                    return resolve({ count: 0, apiError: true });
                }

                for (const line of body.split('\n')) {

                    const sep = line.indexOf(':');

                    if (sep === -1) continue;

                    const lineSuffix = line.slice(0, sep).trim();
                    const lineCount  = line.slice(sep + 1).trim();

                    if (lineSuffix === suffix) {
                        return resolve({
                            count: parseInt(lineCount, 10) || 0,
                            apiError: false
                        });
                    }
                }

                resolve({ count: 0, apiError: false });
            });
        });

        req.on('error', () => {
            resolve({ count: 0, apiError: true });
        });

        req.setTimeout(6000, () => {
            req.destroy();
            resolve({ count: 0, apiError: true });
        });

        req.end();
    });
}


// ── 7. AI PASSWORD GENERATOR ───────────────────────────────────────────────

async function generateAIPassword() {

    const seed = crypto.randomBytes(16).toString('hex');

    const styles = [
        'cyberpunk',
        'quantum',
        'stealth',
        'encrypted',
        'neural',
        'matrix',
        'entropy'
    ];

    const randomStyle = styles[crypto.randomInt(styles.length)];

    const targetLength = crypto.randomInt(16, 21);

    try {

        const response = await openai.chat.completions.create({

            model: 'gpt-4.1-mini',

            temperature: 1.4,

            messages: [
                {
                    role: 'system',
                    content:
                        'You generate highly secure passwords only.'
                },

                {
                    role: 'user',
                    content:
`Generate ONE highly secure password.

Theme: ${randomStyle}
Seed: ${seed}

Requirements:
- Length exactly ${targetLength}
- Include uppercase
- Include lowercase
- Include numbers
- Include symbols
- Avoid common patterns
- Avoid dictionary words
- Avoid repeated characters
- Return ONLY the password`
                }
            ]
        });

        const pw =
            response.choices[0]?.message?.content?.trim() || '';

        const valid =
            pw.length >= 16 &&
            pw.length <= 20 &&
            /[A-Z]/.test(pw) &&
            /[a-z]/.test(pw) &&
            /[0-9]/.test(pw) &&
            /[^a-zA-Z0-9]/.test(pw);

        if (valid) return pw;

        throw new Error('Invalid AI password');

    } catch (err) {

        console.warn('[OpenAI Generator Fallback]', err.message);

        return generateLocalPassword();
    }
}


// ── 8. LOCAL FALLBACK GENERATOR ────────────────────────────────────────────

function generateLocalPassword() {

    const sets = {
        upper   : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lower   : 'abcdefghijklmnopqrstuvwxyz',
        digits  : '0123456789',
        symbols : '!@#$%^&*-_+='
    };

    const all = Object.values(sets).join('');

    const pick = (charset) =>
        charset[crypto.randomInt(charset.length)];

    let chars = [
        pick(sets.upper),
        pick(sets.lower),
        pick(sets.digits),
        pick(sets.symbols),
        pick(sets.symbols)
    ];

    for (let i = chars.length; i < 18; i++) {
        chars.push(pick(all));
    }

    for (let i = chars.length - 1; i > 0; i--) {

        const j = crypto.randomInt(i + 1);

        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join('');
}


// ── 9. ROUTES ──────────────────────────────────────────────────────────────

app.post('/api/analyze', async (req, res) => {

    const { password } = req.body;

    if (!password || typeof password !== 'string') {
        return res.status(400).json({
            error: 'Invalid password.'
        });
    }

    const [breachResult, suggestedPassword] =
        await Promise.all([
            checkBreachExposure(password),
            generateAIPassword()
        ]);

    const entropy   = calculateEntropy(password);
    const crackTime = estimateCrackTime(entropy);
    const patterns  = scanPatterns(password);
    const score     = calculateScore(
        password,
        entropy,
        breachResult.count
    );

    if (breachResult.apiError) {
        patterns.push(
            '⚡ Breach database temporarily unreachable.'
        );
    }
    else if (breachResult.count > 0) {

        patterns.push(
            `🚨 Breached! Found in ${breachResult.count.toLocaleString()} leaks.`
        );

    } else {

        patterns.push(
            '✅ Not found in known breaches.'
        );
    }

    return res.json({

        score,
        maxScore: 4,

        entropy,

        breachCount : breachResult.count,
        breachError : breachResult.apiError,

        patterns,

        crackTime,

        guessingSpeed : '10 Billion',

        verdict :
            score >= 3
            ? 'Resilient Configuration'
            : 'Vulnerable String Pattern',

        suggestedAlternative : suggestedPassword
    });
});


// ── 10. GENERATE ROUTE ─────────────────────────────────────────────────────

app.get('/api/generate', async (_req, res) => {

    try {

        const password = await generateAIPassword();

        return res.json({ password });

    } catch {

        return res.status(500).json({
            error: 'Generation failed.'
        });
    }
});


// ── 11. START SERVER ───────────────────────────────────────────────────────

app.listen(PORT, () => {

    const line = '═'.repeat(66);

    console.log(line);
    console.log(
        `🔐 CipherGuard Online → http://localhost:${PORT}/analyzer.html`
    );
    console.log(line);
});