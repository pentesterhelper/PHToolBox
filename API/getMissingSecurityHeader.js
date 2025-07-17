const axios = require('axios');
const { URL } = require('url');

const importantHeaders = {
  'strict-transport-security': 'HSTS (Strict-Transport-Security)',
  'content-security-policy': 'Content Security Policy',
  'x-content-type-options': 'X-Content-Type-Options',
  'x-frame-options': 'X-Frame-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
  'x-xss-protection': 'X-XSS-Protection (deprecated)'
};

async function checkSecurityHeaders(fullUrl) {
  let parsedUrl;

  try {
    parsedUrl = new URL(fullUrl);
  } catch {
    return [{
      url: fullUrl,
      error: 'Invalid URL'
    }];
  }

  const host = parsedUrl.host;

  const config = {
    method: 'GET',
    url: fullUrl,
    headers: {
      'Host': host,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'Accept': '*/*',
      'Accept-Encoding': 'gzip, deflate',
      'Connection': 'close'
    },
    timeout: 5000,
    maxRedirects: 0,
    validateStatus: () => true,
    proxy: false // 👈 disables proxy usage completely
  };

  try {
    const response = await axios(config);
    const headers = Object.fromEntries(
      Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v])
    );

    const missingHeaders = [];
    const presentHeaders = [];

    for (const key in importantHeaders) {
      if (headers[key]) {
        // Normalize CSP value if needed
        const value = headers[key].replace(/^Content-Security-Policy:\s*/i, '');
        presentHeaders.push({ header: key, value });
      } else {
        missingHeaders.push({ header: key, description: importantHeaders[key] });
      }
    }

    return [{
      url: fullUrl,
      host,
      protocol: response.request.protocol.replace(':', '').toUpperCase(),
      status: response.status,
      method: 'GET',
      presentHeaders,
      missingHeaders,
      response: {
        status: response.status,
        headers: response.headers,
        body: typeof response.data === 'object' ? JSON.stringify(response.data) : response.data
      },
      request: {
        method: config.method,
        headers: config.headers,
        body: null // or config.data if you send POST data later
      }
    }];

  } catch (err) {
    return [{
      url: fullUrl,
      host,
      error: err.message
    }];
  }
}

module.exports = { checkSecurityHeaders };
