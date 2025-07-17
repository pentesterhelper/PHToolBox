const { exec } = require('child_process');
const { URL } = require('url');

async function checkWeakSSL(fullUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(fullUrl);
  } catch {
    return [{ url: fullUrl, error: 'Invalid URL' }];
  }

  const host = parsedUrl.hostname;
  const port = parsedUrl.port || 443;

  return new Promise((resolve) => {
    const cmd = `nmap -Pn --script ssl-enum-ciphers ${host} -p ${port}`;
    exec(cmd, { timeout: 1500000 }, (error, stdout, stderr) => {
      if (error) {
        return resolve([{
          url: fullUrl,
          host,
          port,
          error: `Nmap error: ${stderr || error.message}`
        }]);
      }

      resolve([{
        url: fullUrl,
        host,
        port,
        method: 'NMAP',
        protocol: 'HTTPS',
        request: {
          method: 'nmap',
          headers: {
            'Tool': 'nmap',
            'Script': 'ssl-enum-ciphers'
          },
          body: null
        },
        response: {
          status: 200,
          headers: {},
          body: stdout
        }
      }]);
    });
  });
}

module.exports = { checkWeakSSL };
