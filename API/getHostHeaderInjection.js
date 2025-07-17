import { exec } from 'child_process';
import { URL } from 'url';

function runCurlWithHostHeader(fullUrl, customHost = null) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(fullUrl);
    } catch {
      return resolve({ url: fullUrl, error: 'Invalid URL' });
    }

    const host = customHost || parsed.host;
    const cmd = `curl -i -L --max-time 10 -H "Host: ${host}" -A "Mozilla/5.0" "${fullUrl}"`;

    exec(cmd, (err, stdout, stderr) => {
      if (err) {
        return resolve({ url: fullUrl, host, error: stderr || err.message });
      }

      const [headerPart, ...bodyParts] = stdout.split(/\r?\n\r?\n/);
      const headers = {};
      let status = null;

      const lines = headerPart.split(/\r?\n/);
      if (lines.length > 0 && lines[0].includes('HTTP')) {
        const statusMatch = lines[0].match(/HTTP\/[\d.]+\\s+(\\d+)/);
        if (statusMatch) status = parseInt(statusMatch[1]);
      }

      lines.slice(1).forEach(line => {
        const [key, value] = line.split(/:\\s(.+)/);
        if (key && value) headers[key.toLowerCase()] = value.trim();
      });

      const body = bodyParts.join('\\n\\n').trim();

      resolve({
        type: customHost ? 'spoofed' : 'original',
        method: 'GET',
        url: fullUrl,
        host,
        status,
        request: {
          headers: {
            'Host': host,
            'User-Agent': 'Mozilla/5.0'
          }
        },
        response: {
          status,
          headers,
          body
        },
        reflectedInBody: customHost && body.includes(customHost),
        reflectedInHeaders: customHost && JSON.stringify(headers).includes(customHost),
        mightBeVulnerable: customHost && (status >= 200 && status < 400),
        message: customHost
          ? ((status >= 200 && status < 400)
              ? 'Might be vulnerable to Host Header Injection.'
              : 'No obvious injection detected.')
          : 'Original request'
      });
    });
  });
}

export async function checkHostHeaderInjection(url) {
  const results = [];
  const original = await runCurlWithHostHeader(url);
  results.push(original);

  if (original.status >= 200 && original.status < 400) {
    const spoofHosts = ['evil.com', 'fintakeai.com'];
    for (const spoof of spoofHosts) {
      const spoofed = await runCurlWithHostHeader(url, spoof);
      results.push(spoofed);
    }
  }

  return results;
}
