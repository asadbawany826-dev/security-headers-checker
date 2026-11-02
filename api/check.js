// Security Headers Checker — serverless API (Vercel)
// Fetches a site's response headers server-side (browsers can't read
// another site's headers because of CORS) and grades them.

const TIMEOUT_MS = 9000;

function isPrivateHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h === '::1' || h === '0.0.0.0') return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
  }
  return false;
}

function gradeFor(score) {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

function analyze(headers, finalUrl) {
  const https = finalUrl.startsWith('https://');
  const get = (name) => headers[name] || null;
  const results = [];
  const warnings = [];
  let score = 0;

  // --- Content-Security-Policy (25) ---
  const csp = get('content-security-policy');
  if (csp) {
    const scriptPart = (csp.match(/script-src[^;]*/) || csp.match(/default-src[^;]*/) || [''])[0];
    const unsafeInline = /'unsafe-inline'/.test(scriptPart);
    const unsafeEval = /'unsafe-eval'/.test(scriptPart);
    if (!unsafeInline && !unsafeEval) {
      score += 25;
      results.push({ name: 'Content-Security-Policy', status: 'good', value: csp,
        note: 'Present and strict — no unsafe-inline or unsafe-eval for scripts.' });
    } else {
      score += 15;
      results.push({ name: 'Content-Security-Policy', status: 'weak', value: csp,
        note: 'Present, but it allows ' + (unsafeInline ? "'unsafe-inline'" : "'unsafe-eval'") + ' for scripts, which weakens XSS protection.',
        fix: "Remove 'unsafe-inline' / 'unsafe-eval' from script-src and use nonces or hashes instead." });
    }
  } else {
    results.push({ name: 'Content-Security-Policy', status: 'missing', value: null,
      note: 'Not set. This header controls which scripts and resources a page may load and is the main defence against injected-script (XSS) attacks.',
      fix: "Add a Content-Security-Policy header, starting with: default-src 'self'" });
  }

  // --- Strict-Transport-Security (20) ---
  const hsts = get('strict-transport-security');
  if (!https) {
    results.push({ name: 'Strict-Transport-Security', status: 'missing', value: hsts,
      note: 'The site answered over plain HTTP. HSTS only works on HTTPS, and an HTTP site can be intercepted or downgraded.',
      fix: 'Move the site to HTTPS first, then add the HSTS header.' });
  } else if (hsts) {
    const m = hsts.match(/max-age\s*=\s*(\d+)/i);
    const age = m ? parseInt(m[1], 10) : 0;
    if (age >= 31536000) {
      score += 20;
      results.push({ name: 'Strict-Transport-Security', status: 'good', value: hsts,
        note: 'Present with a max-age of one year or more — browsers will always use HTTPS for this site.' });
    } else if (age >= 15552000) {
      score += 15;
      results.push({ name: 'Strict-Transport-Security', status: 'weak', value: hsts,
        note: 'Present, but max-age is under one year, so browsers forget the HTTPS-only rule sooner.',
        fix: 'Raise max-age to at least 31536000 (one year).' });
    } else if (age > 0) {
      score += 8;
      results.push({ name: 'Strict-Transport-Security', status: 'weak', value: hsts,
        note: 'Present, but max-age is very short, so the protection barely lasts.',
        fix: 'Raise max-age to at least 31536000 (one year).' });
    } else {
      score += 4;
      results.push({ name: 'Strict-Transport-Security', status: 'weak', value: hsts,
        note: 'Present but without a usable max-age value.',
        fix: 'Use: Strict-Transport-Security: max-age=31536000; includeSubDomains' });
    }
  } else {
    results.push({ name: 'Strict-Transport-Security', status: 'missing', value: null,
      note: 'Not set. Without HSTS a browser can be tricked into loading the site over plain HTTP (SSL stripping).',
      fix: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains' });
  }

  // --- Clickjacking: X-Frame-Options or CSP frame-ancestors (15) ---
  const xfo = get('x-frame-options');
  const frameAncestors = csp && /frame-ancestors/.test(csp);
  if (xfo && /^(deny|sameorigin)$/i.test(xfo.trim())) {
    score += 15;
    results.push({ name: 'X-Frame-Options', status: 'good', value: xfo,
      note: 'Present — other sites cannot put this page inside a frame, which blocks clickjacking.' });
  } else if (frameAncestors) {
    score += 15;
    results.push({ name: 'X-Frame-Options', status: 'good', value: 'Set via CSP frame-ancestors',
      note: 'No X-Frame-Options header, but the CSP frame-ancestors rule gives the same clickjacking protection.' });
  } else if (xfo) {
    score += 6;
    results.push({ name: 'X-Frame-Options', status: 'weak', value: xfo,
      note: 'Present but with an unusual value (' + xfo + ') that browsers may not enforce.',
      fix: 'Use X-Frame-Options: DENY or SAMEORIGIN.' });
  } else {
    results.push({ name: 'X-Frame-Options', status: 'missing', value: null,
      note: 'Not set, and the CSP has no frame-ancestors rule. Another site could embed this page in a frame and trick visitors into clicking (clickjacking).',
      fix: 'Add X-Frame-Options: DENY (or SAMEORIGIN), or a CSP frame-ancestors rule.' });
  }

  // --- X-Content-Type-Options (10) ---
  const xcto = get('x-content-type-options');
  if (xcto && xcto.trim().toLowerCase() === 'nosniff') {
    score += 10;
    results.push({ name: 'X-Content-Type-Options', status: 'good', value: xcto,
      note: 'nosniff is set — browsers will not guess file types, which prevents MIME-sniffing attacks.' });
  } else if (xcto) {
    score += 4;
    results.push({ name: 'X-Content-Type-Options', status: 'weak', value: xcto,
      note: 'Present but the value is not "nosniff".', fix: 'Use X-Content-Type-Options: nosniff' });
  } else {
    results.push({ name: 'X-Content-Type-Options', status: 'missing', value: null,
      note: 'Not set. Browsers may guess the type of a file, which attackers can abuse with uploaded files.',
      fix: 'Add: X-Content-Type-Options: nosniff' });
  }

  // --- Referrer-Policy (10) ---
  const rp = get('referrer-policy');
  const rpVal = rp ? rp.split(',').pop().trim().toLowerCase() : null;
  if (rp && ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'].includes(rpVal)) {
    score += 10;
    results.push({ name: 'Referrer-Policy', status: 'good', value: rp,
      note: 'Present with a privacy-safe value — full page URLs are not leaked to other sites when visitors click links.' });
  } else if (rp && ['origin', 'origin-when-cross-origin'].includes(rpVal)) {
    score += 6;
    results.push({ name: 'Referrer-Policy', status: 'weak', value: rp,
      note: 'Present, but a stricter value leaks less information.',
      fix: 'Use Referrer-Policy: strict-origin-when-cross-origin' });
  } else if (rp) {
    score += 2;
    results.push({ name: 'Referrer-Policy', status: 'weak', value: rp,
      note: 'Present, but this value can leak full page URLs to other sites.',
      fix: 'Use Referrer-Policy: strict-origin-when-cross-origin' });
  } else {
    results.push({ name: 'Referrer-Policy', status: 'missing', value: null,
      note: 'Not set. The browser default may send the full page URL (including paths and queries) to other sites.',
      fix: 'Add: Referrer-Policy: strict-origin-when-cross-origin' });
  }

  // --- Permissions-Policy (10) ---
  const pp = get('permissions-policy');
  if (pp) {
    score += 10;
    results.push({ name: 'Permissions-Policy', status: 'good', value: pp,
      note: 'Present — the site controls which browser features (camera, microphone, location) pages may use.' });
  } else {
    results.push({ name: 'Permissions-Policy', status: 'missing', value: null,
      note: 'Not set. Any script on the page could try to use powerful browser features like camera or microphone.',
      fix: 'Add a Permissions-Policy header that disables features the site does not need, e.g. camera=(), microphone=(), geolocation=()' });
  }

  // --- Information-leak warnings ---
  if (get('server')) warnings.push('The Server header reveals the server software: "' + get('server') + '". Attackers use this to pick known exploits. Hide or genericise it if you can.');
  if (get('x-powered-by')) warnings.push('The X-Powered-By header reveals the platform: "' + get('x-powered-by') + '". Remove it if you can.');

  return { results, warnings, score: Math.max(0, Math.min(100, score)) };
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  const raw = (req.query && req.query.url) || '';
  if (!raw) { res.status(400).json({ error: 'Missing url parameter.' }); return; }

  let target = String(raw).trim();
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

  let parsed;
  try { parsed = new URL(target); } catch { res.status(400).json({ error: 'That does not look like a valid URL.' }); return; }
  if (!/^https?:$/.test(parsed.protocol)) { res.status(400).json({ error: 'Only http:// and https:// sites can be checked.' }); return; }
  if (isPrivateHost(parsed.hostname)) { res.status(400).json({ error: 'Private or local addresses cannot be checked.' }); return; }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response;
  try {
    response = await fetch(parsed.toString(), {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityHeadersChecker/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
      },
    });
  } catch (e) {
    clearTimeout(timer);
    res.status(502).json({ error: 'Could not reach that site (' + (e.name === 'AbortError' ? 'it took too long to answer' : 'connection failed') + '). Check the address and try again.' });
    return;
  }
  clearTimeout(timer);

  const headers = {};
  response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

  // Cookie flags
  let cookies = [];
  if (typeof response.headers.getSetCookie === 'function') cookies = response.headers.getSetCookie();
  else if (headers['set-cookie']) cookies = [headers['set-cookie']];

  const finalUrl = response.url || parsed.toString();
  const { results, warnings, score } = analyze(headers, finalUrl);

  const cookieFindings = cookies.map((c) => {
    const name = (c.split('=')[0] || 'cookie').trim();
    const flags = [];
    if (!/;\s*secure/i.test(c) && finalUrl.startsWith('https://')) flags.push('no Secure flag');
    if (!/;\s*httponly/i.test(c)) flags.push('no HttpOnly flag');
    if (!/;\s*samesite/i.test(c)) flags.push('no SameSite flag');
    return flags.length ? 'Cookie "' + name + '" has ' + flags.join(', ') + '.' : null;
  }).filter(Boolean);
  warnings.push(...cookieFindings);

  try { await response.text(); } catch { /* body not needed */ }

  res.status(200).json({
    inputUrl: raw,
    finalUrl,
    statusCode: response.status,
    https: finalUrl.startsWith('https://'),
    score,
    grade: gradeFor(score),
    results,
    warnings,
  });
};
