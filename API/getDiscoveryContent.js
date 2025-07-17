const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

async function runDiscovery(domain, wordlistPath) {
  if (!domain.startsWith('http')) {
    domain = 'http://' + domain;
  }

  if (!fs.existsSync(wordlistPath)) {
    return [{ domain, error: 'Wordlist file not found at ' + wordlistPath }];
  }

  const words = fs.readFileSync(wordlistPath, 'utf-8').split('\n').filter(Boolean);
  const results = [];

  const checkUrl = (url) => {
    return new Promise((resolve) => {
      const cmd = `curl -s -o /dev/null -w "%{http_code}" ${url}`;
      exec(cmd, { timeout: 8000 }, (err, stdout) => {
        if (err) {
          return resolve({ url, status: 'error', error: err.message });
        }

        const statusCode = stdout.trim();
        if (statusCode !== '000' && statusCode !== '404') {
          resolve({ url, status: parseInt(statusCode) });
        } else {
          resolve(null);
        }
      });
    });
  };

  for (const word of words) {
    const testUrl = `${domain.replace(/\/$/, '')}/${word}`;
    try {
      const result = await checkUrl(testUrl);
      if (result) results.push(result);
    } catch (e) {
      results.push({ url: testUrl, status: 'error', error: e.message });
    }
  }

  return results;
}

module.exports = { runDiscovery };
