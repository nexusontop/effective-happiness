// Vercel Serverless Function (Node 18+)
// Path: api/refresh.js
export default async function handler(req, res) {
  try {
    // Optional: require an API key if set in Vercel (Environment Variable: API_KEY)
    const requiredApiKey = process.env.API_KEY;
    if (requiredApiKey) {
      const provided = req.headers['x-api-key'] || req.query.api_key || null;
      if (!provided || provided !== requiredApiKey) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
    }

    const method = (req.method || 'GET').toUpperCase();
    let cookie = null;

    if (method === 'POST') {
      // Vercel automatically parses JSON when Content-Type: application/json
      cookie = (req.body && (req.body.cookie || req.body?.cookie)) || null;
    } else {
      // allow GET for compatibility but it's insecure
      cookie = req.query?.cookie || req.query?.c || null;
    }

    if (!cookie) {
      return res.status(400).json({
        error:
          'Missing cookie parameter. Provide .ROBLOSECURITY token (value only) as JSON POST { "cookie": "..." } or ?cookie=... in query (not recommended).',
      });
    }

    // Normalize token if user included "ROBLOSECURITY=" or ".ROBLOSECURITY="
    if (/ROBLOSECURITY=/i.test(cookie)) {
      const m = cookie.match(/(?:\.?ROBLOSECURITY=)?([^;]+)/i);
      cookie = m ? m[1] : cookie;
    }

    const USER_AGENT =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0';

    async function getCsrf(cookieValue) {
      const resp = await fetch('https://auth.roblox.com/v2/login', {
        method: 'POST',
        headers: {
          'User-Agent': USER_AGENT,
          'Content-Type': 'application/json',
          Cookie: `.ROBLOSECURITY=${cookieValue}`,
        },
        body: JSON.stringify({}),
      });
      // X-CSRF-TOKEN should be in response headers
      let token = resp.headers.get('x-csrf-token');
      if (token) return token;
      // fallback: iterate headers
      for (const [k, v] of resp.headers) {
        if (k.toLowerCase() === 'x-csrf-token') return v;
      }
      return null;
    }

    async function getNonce(cookieValue) {
      const resp = await fetch('https://apis.roblox.com/hba-service/v1/getServerNonce', {
        method: 'GET',
        headers: {
          'User-Agent': USER_AGENT,
          'Content-Type': 'application/json',
          Cookie: `.ROBLOSECURITY=${cookieValue}`,
        },
      });
      const txt = await resp.text().catch(() => '');
      return txt.replace(/^"+|"+$/g, '').trim();
    }

    async function getEpoch(cookieValue) {
      const resp = await fetch(
        'https://apis.roblox.com/token-metadata-service/v1/sessions?nextCursor=&desiredLimit=25',
        {
          method: 'GET',
          headers: {
            'User-Agent': USER_AGENT,
            'Content-Type': 'application/json',
            Cookie: `.ROBLOSECURITY=${cookieValue}`,
          },
        }
      );
      const json = await resp.json().catch(() => null);
      return json?.sessions?.[0]?.lastAccessedTimestampEpochMilliseconds ?? null;
    }

    async function refreshCookie(cookieValue) {
      // run the three preparatory calls in parallel
      const [nonce, csrf, epoch] = await Promise.allSettled([
        getNonce(cookieValue),
        getCsrf(cookieValue),
        getEpoch(cookieValue),
      ]).then((results) =>
        results.map((r) => (r.status === 'fulfilled' ? r.value : null))
      );

      const payload = {
        secureAuthenticationIntent: {
          clientEpochTimestamp: epoch,
          clientPublicKey: null,
          saiSignature: null,
          serverNonce: nonce,
        },
      };

      const headers = {
        'User-Agent': USER_AGENT,
        'Content-Type': 'application/json',
        Cookie: `.ROBLOSECURITY=${cookieValue}`,
        Origin: 'https://roblox.com',
        Referer: 'https://roblox.com',
        Accept: 'application/json',
      };
      if (csrf) headers['X-Csrf-Token'] = csrf;

      const resp = await fetch(
        'https://auth.roblox.com/v1/logoutfromallsessionsandreauthenticate',
        {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
        }
      );

      // Collect set-cookie headers (there may be multiple)
      const setCookies = [];
      for (const [k, v] of resp.headers) {
        if (k.toLowerCase() === 'set-cookie') setCookies.push(v);
      }
      // fallback
      const single = resp.headers.get('set-cookie');
      if (single && !setCookies.includes(single)) setCookies.push(single);

      // If no set-cookie returned, return body for debugging
      if (setCookies.length === 0) {
        const bodyText = await resp.text().catch(() => '');
        let parsed = null;
        try {
          parsed = JSON.parse(bodyText);
        } catch (e) {
          parsed = null;
        }
        return { success: false, status: resp.status, body: parsed ?? bodyText };
      }

      // Look for ROBLOSECURITY in set-cookie values
      for (const sc of setCookies) {
        const match = sc.match(/(?:\.?ROBLOSECURITY|ROBLOSECURITY)=([^;]+)/i);
        if (match && match[1]) {
          // Return the refreshed token (value only) and the raw set-cookie string for debugging
          return { success: true, refreshed_cookie: match[1], raw_set_cookie: sc };
        }
      }

      // If ROBLOSECURITY not present explicitly, return all set-cookie values
      return { success: true, set_cookies: setCookies };
    }

    const result = await refreshCookie(cookie);

    if (result.success) {
      return res.status(200).json(result);
    } else {
      return res.status(400).json({ error: 'Failed to refresh', details: result });
    }
  } catch (err) {
    console.error('refresh error', err);
    return res.status(500).json({ error: 'Internal error', message: String(err) });
  }
        }
