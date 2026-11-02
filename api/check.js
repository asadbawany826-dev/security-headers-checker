// Website Security Checker — serverless API (Vercel)
// Fetches a site server-side (browsers can't read another site's headers
// because of CORS), checks its SSL certificate, HTTPS enforcement,
// cookies, mixed content and the six main security headers, and returns
// one overall grade plus a breakdown.

const tls = require('tls');

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

async function fetchWithTimeout(url, options, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms || TIMEOUT_MS);
  try {
    return await fetch(url, Object.assign({}, options, { signal: controller.signal }));
  } finally {
    clearTimeout(timer);
  }
}

// ---------- SSL certificate check (15 points) ----------

function certCoversHost(cert, hostname) {
  const names = [];
  if (cert.subject && cert.subject.CN) names.push(cert.subject.CN);
  if (cert.subjectaltname) {
    cert.subjectaltname.split(',').forEach((part) => {
      const t = part.trim();
      if (t.indexOf('DNS:') === 0) names.push(t.slice(4));
    });
  }
  const host = hostname.toLowerCase();
  return names.some((raw) => {
    const n = raw.toLowerCase();
    if (n.indexOf('*.') === 0) {
      return host.endsWith(n.slice(1)) && host.split('.').length === n.split('.').length;
    }
    return n === host;
  });
}

function getCertificate(hostname) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    let socket;
    try {
      socket = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: false }, () => {
        const cert = socket.getPeerCertificate();
        const info = {
          authorized: socket.authorized,
          authError: socket.authorizationError ? String(socket.authorizationError) : null,
          protocol: socket.getProtocol(),
        };
        socket.end();
        if (!cert || !cert.valid_to) { done({ ok: false, error: 'The server did not present a certificate.' }); return; }
        info.issuer = cert.issuer && (cert.issuer.O || cert.issuer.CN || 'unknown');
        info.validTo = cert.valid_to;
        info.daysLeft = Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86400000);
        info.coversHost = certCoversHost(cert, hostname);
        done(Object.assign({ ok: true }, info));
      });
    } catch (e) {
      done({ ok: false, error: String(e && e.message || e) });
      return;
    }
    socket.setTimeout(6000, () => { socket.destroy(); done({ ok: false, error: 'Certificate check timed out.' }); });
    socket.on('error', (e) => done({ ok: false, error: String(e && e.message || e) }));
  });
}

async function checkSsl(finalUrl) {
  const u = new URL(finalUrl);
  if (u.protocol !== 'https:') {
    return { id: 'ssl', name: 'SSL Certificate', status: 'missing', pill: 'NO SSL', points: 0, maxPoints: 15,
      note: 'The site is served over plain HTTP, so there is no SSL certificate and nothing encrypts the connection. Anyone on the network can read or change the traffic.',
      fix: 'Install an SSL certificate and serve the site over HTTPS (free certificates are available from Let\'s Encrypt and most hosts).' };
  }
  const cert = await getCertificate(u.hostname);
  if (!cert.ok) {
    return { id: 'ssl', name: 'SSL Certificate', status: 'weak', pill: 'UNVERIFIED', points: 7, maxPoints: 15,
      note: 'The site uses HTTPS, but the certificate itself could not be verified from here (' + cert.error + ').',
      fix: 'Check the certificate in a browser — open the site and click the padlock icon.' };
  }
  const detail = 'Issued by ' + cert.issuer + ', ' + (cert.protocol || 'TLS') + ', expires ' + cert.validTo + ' (' + cert.daysLeft + ' days left).';
  if (!cert.authorized) {
    return { id: 'ssl', name: 'SSL Certificate', status: 'missing', pill: 'INVALID', points: 0, maxPoints: 15,
      note: 'The certificate is not trusted (' + (cert.authError || 'validation failed') + '). Browsers will warn visitors that the site is not safe. ' + detail,
      fix: 'Replace the certificate with a valid one from a trusted issuer.' };
  }
  if (!cert.coversHost) {
    return { id: 'ssl', name: 'SSL Certificate', status: 'missing', pill: 'WRONG NAME', points: 0, maxPoints: 15,
      note: 'The certificate does not cover this exact address, so browsers reject it. ' + detail,
      fix: 'Get a certificate that includes this domain name.' };
  }
  if (cert.daysLeft < 0) {
    return { id: 'ssl', name: 'SSL Certificate', status: 'missing', pill: 'EXPIRED', points: 0, maxPoints: 15,
      note: 'The certificate has expired. Browsers block the site with a security warning. ' + detail,
      fix: 'Renew the certificate immediately.' };
  }
  if (cert.daysLeft <= 30) {
    return { id: 'ssl', name: 'SSL Certificate', status: 'weak', pill: 'EXPIRING SOON', points: 9, maxPoints: 15,
      note: 'Valid, but it expires soon. ' + detail,
      fix: 'Renew the certificate before it expires, or turn on auto-renewal.' };
  }
  return { id: 'ssl', name: 'SSL Certificate', status: 'good', pill: 'VALID', points: 15, maxPoints: 15,
    note: 'Valid and trusted. ' + detail };
}

// ---------- HTTPS enforcement check (10 points) ----------

async function checkHttpsEnforcement(finalUrl) {
  const u = new URL(finalUrl);
  if (u.protocol !== 'https:') {
    return { id: 'https', name: 'HTTPS Enforcement', status: 'missing', pill: 'HTTP ONLY', points: 0, maxPoints: 10,
      note: 'The site loads over plain HTTP. Visitors get no encryption at all.',
      fix: 'Serve the site over HTTPS and redirect every HTTP address to HTTPS.' };
  }
  const httpUrl = 'http://' + u.host + '/';
  try {
    const r = await fetchWithTimeout(httpUrl, { method: 'GET', redirect: 'manual',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebsiteSecurityChecker/1.0)' } }, 7000);
    const loc = r.headers.get('location') || '';
    if (r.status >= 300 && r.status < 400 && loc.indexOf('https://') === 0) {
      return { id: 'https', name: 'HTTPS Enforcement', status: 'good', pill: 'ENFORCED', points: 10, maxPoints: 10,
        note: 'Typing the plain HTTP address automatically sends the visitor to the secure HTTPS version (HTTP ' + r.status + ' redirect).' };
    }
    if (r.status >= 300 && r.status < 400) {
      return { id: 'https', name: 'HTTPS Enforcement', status: 'weak', pill: 'WRONG REDIRECT', points: 3, maxPoints: 10,
        note: 'The HTTP address redirects, but not to the HTTPS version of the site.',
        fix: 'Redirect all HTTP traffic to the same address on HTTPS.' };
    }
    return { id: 'https', name: 'HTTPS Enforcement', status: 'missing', pill: 'NOT ENFORCED', points: 0, maxPoints: 10,
      note: 'The plain HTTP version of the site still loads (HTTP ' + r.status + '), so visitors can end up on the unencrypted version.',
      fix: 'Redirect all HTTP traffic to HTTPS (a permanent 301/308 redirect).' };
  } catch (e) {
    return { id: 'https', name: 'HTTPS Enforcement', status: 'good', pill: 'HTTPS ONLY', points: 8, maxPoints: 10,
      note: 'The plain HTTP address does not answer at all — the site appears to exist only on HTTPS, which is safe.' };
  }
}

// ---------- Cookie check (10 points) ----------

function checkCookies(cookies, https) {
  if (!cookies.length) {
    return { id: 'cookies', name: 'Cookies', status: 'good', pill: 'NO COOKIES', points: 10, maxPoints: 10,
      note: 'The site sets no cookies on this page, so there is nothing here for an attacker to steal.' };
  }
  let points = 10;
  const findings = [];
  let anyNoSecure = false, anyNoHttpOnly = false, anyNoSameSite = false;
  cookies.forEach((c) => {
    const name = (c.split('=')[0] || 'cookie').trim();
    const missing = [];
    if (!/;\s*secure/i.test(c)) { missing.push('Secure'); anyNoSecure = true; }
    if (!/;\s*httponly/i.test(c)) { missing.push('HttpOnly'); anyNoHttpOnly = true; }
    if (!/;\s*samesite/i.test(c)) { missing.push('SameSite'); anyNoSameSite = true; }
    if (missing.length) findings.push('Cookie "' + name + '" is missing: ' + missing.join(', ') + '.');
  });
  if (anyNoSecure) points -= 4;
  if (anyNoHttpOnly) points -= 3;
  if (anyNoSameSite) points -= 3;
  points = Math.max(0, points);
  if (!findings.length) {
    return { id: 'cookies', name: 'Cookies', status: 'good', pill: 'PROTECTED', points: 10, maxPoints: 10,
      note: 'Every cookie carries the Secure, HttpOnly and SameSite flags, which protect them from theft and misuse.' };
  }
  return { id: 'cookies', name: 'Cookies', status: points >= 5 ? 'weak' : 'missing', pill: 'FLAGS MISSING', points, maxPoints: 10,
    note: 'The site sets ' + cookies.length + ' cookie(s), but some are missing protective flags. Secure keeps a cookie on HTTPS only, HttpOnly hides it from scripts, and SameSite stops other sites from abusing it.',
    findings,
    fix: 'Add the Secure, HttpOnly and SameSite flags to every cookie.' };
}

// ---------- Mixed content check (5 points) ----------

function checkMixedContent(bodyText, contentType, https) {
  if (!https) {
    return { id: 'mixed', name: 'Mixed Content', status: 'missing', pill: 'UNENCRYPTED', points: 0, maxPoints: 5,
      note: 'The whole page is unencrypted HTTP, which is worse than mixed content — everything on it can be read or changed in transit.',
      fix: 'Move the site to HTTPS.' };
  }
  if (!contentType || contentType.indexOf('text/html') === -1 || bodyText == null) {
    return { id: 'mixed', name: 'Mixed Content', status: 'good', pill: 'N/A', points: 5, maxPoints: 5,
      note: 'The address did not return an HTML page, so mixed content does not apply here.' };
  }
  const sample = bodyText.slice(0, 1000000);
  const matches = sample.match(/(src|href)\s*=\s*["']http:\/\/(?!www\.w3\.org|schemas\.|localhost)/gi) || [];
  if (!matches.length) {
    return { id: 'mixed', name: 'Mixed Content', status: 'good', pill: 'CLEAN', points: 5, maxPoints: 5,
      note: 'No insecure (HTTP) files are loaded inside this secure page.' };
  }
  return { id: 'mixed', name: 'Mixed Content', status: matches.length <= 3 ? 'weak' : 'missing', pill: 'MIXED CONTENT',
    points: matches.length <= 3 ? 2 : 0, maxPoints: 5,
    note: 'This secure page loads about ' + matches.length + ' file(s) over plain HTTP. Those files can be intercepted or replaced, and browsers may block them.',
    fix: 'Change every http:// link in the page\'s files to https://.' };
}

// ---------- Security headers analysis (60 points when scaled) ----------

function analyzeHeaders(headers, finalUrl) {
  const https = finalUrl.startsWith('https://');
  const get = (name) => headers[name] || null;
  const results = [];
  const warnings = [];
  let score = 0;

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

  if (get('server')) warnings.push({
    text: 'The Server header reveals the server software: "' + get('server') + '". Attackers use this to pick known exploits for that exact software.',
    solution: 'Remove the Server header, or set it to a short generic value with no software name or version number. Most hosts and CDNs have a setting or one config line for this.'
  });
  if (get('x-powered-by')) warnings.push({
    text: 'The X-Powered-By header reveals the platform: "' + get('x-powered-by') + '". Attackers use this to target known weaknesses of that platform.',
    solution: 'Remove the X-Powered-By header — in most frameworks it is one setting (for example, Express: app.disable(\'x-powered-by\'); PHP: expose_php = Off).'
  });

  return { results, warnings, score: Math.max(0, Math.min(100, score)) };
}

// ---------- Main handler ----------

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

  let response;
  try {
    response = await fetchWithTimeout(parsed.toString(), {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WebsiteSecurityChecker/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
      },
    });
  } catch (e) {
    res.status(502).json({ error: 'Could not reach that site (' + (e.name === 'AbortError' ? 'it took too long to answer' : 'connection failed') + '). Check the address and try again.' });
    return;
  }

  const headers = {};
  response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

  let cookies = [];
  if (typeof response.headers.getSetCookie === 'function') cookies = response.headers.getSetCookie();
  else if (headers['set-cookie']) cookies = [headers['set-cookie']];

  const finalUrl = response.url || parsed.toString();
  const https = finalUrl.startsWith('https://');
  const contentType = headers['content-type'] || '';

  let bodyText = null;
  try { bodyText = await response.text(); } catch { /* body not essential */ }

  const headerAnalysis = analyzeHeaders(headers, finalUrl);
  // The six header weights add up to 90 raw points; scale to a true /100 so
  // a site with every header set perfectly scores 100, not 90.
  const headerScore = Math.min(100, Math.round((headerAnalysis.score / 90) * 100));
  const headerPoints = Math.round(headerScore * 0.6);

  const [sslCheck, httpsCheck] = await Promise.all([
    checkSsl(finalUrl),
    checkHttpsEnforcement(finalUrl),
  ]);
  const cookieCheck = checkCookies(cookies, https);
  const mixedCheck = checkMixedContent(bodyText, contentType, https);

  const checks = [sslCheck, httpsCheck, cookieCheck, mixedCheck];
  const overall = Math.max(0, Math.min(100,
    headerPoints + sslCheck.points + httpsCheck.points + cookieCheck.points + mixedCheck.points));

  res.status(200).json({
    inputUrl: raw,
    finalUrl,
    statusCode: response.status,
    https,
    score: overall,
    grade: gradeFor(overall),
    headerScore,
    headerGrade: gradeFor(headerScore),
    checks,
    results: headerAnalysis.results,
    warnings: headerAnalysis.warnings,
  });
};
