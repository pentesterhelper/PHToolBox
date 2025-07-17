const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const axios = require('axios');
const multer = require('multer');
const { exec, spawn } = require('child_process');
const { GoogleGenAI } = require('@google/genai');
const { GEMINI_API_KEY, VIRUSTOTAL_API_KEY } = require('./keys');
const isAdmin = require('is-administrator');
// API Modules
const { testAllMethods } = require('./API/getVerbRequest');
const { checkSecurityHeaders } = require('./API/getMissingSecurityHeader');
const { checkWeakSSL } = require('./API/getWeakSSL');
const { testServerHeaders } = require('./API/getServerHeader');
const { checkHostHeaderInjection } = require('./API/getHostHeaderInjection');
const { runDiscovery } = require('./API/getDiscoveryContent');

// App
const app = express();
const PORT = 9999;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use('/wordlists', express.static(path.join(__dirname, 'wordlists')));
app.use(express.static(path.join(__dirname, 'public')));

isAdmin()
  .then(isAdmin => {
    if (!isAdmin) {
      console.warn('⚠️  Please run "node run.js" as Administrator or root.');
      process.exit(1); // Exit with error code
    }
  })
  .catch(error => {
    console.error('❌ Failed to check admin/root status:', error);
    process.exit(1); // Exit on error as well
  });


// Auto-route HTML files
fs.readdirSync(path.join(__dirname, 'public'))
  .filter(f => f.endsWith('.html'))
  .forEach(f => {
    const route = '/' + f.replace('.html', '');
    app.get(route, (req, res) => res.sendFile(path.join(__dirname, 'public', f)));
  });

// Checklist subroutes
const checklistDir = path.join(__dirname, 'public', 'Checklist');
if (fs.existsSync(checklistDir)) {
  fs.readdirSync(checklistDir).filter(f => f.endsWith('.html')).forEach(f => {
    const route = '/Checklist/' + f.replace('.html', '');
    app.get(route, (req, res) => res.sendFile(path.join(checklistDir, f)));
  });
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// API: Security Tests
app.post('/API/testAllMethods', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try { res.json(await testAllMethods(url, { proxy: false })); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/API/checkSecurityHeaders', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try { res.json(await checkSecurityHeaders(url)); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/API/checkWeakSSL', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try { res.json(await checkWeakSSL(url)); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

const isValidHttpUrl = (string) => {
  try {
    const url = new URL(string);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch (_) {
    return false;
  }
};

app.get('/api/getServerHeader', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  if (!isValidHttpUrl(url)) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  try {
    const results = await testServerHeaders(url, { proxy: false });
    res.json({ url, results });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch server headers' });
  }
});

app.get('/waybackurls', async (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: 'Please provide a domain as query param (?domain=example.com)' });
  }

  try {
    const url = `http://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&fl=original&collapse=urlkey`;

    const response = await axios.get(url, { proxy: false });
    const data = response.data;

    if (data.length <= 1) {
      return res.json([]);
    }

    const urls = data.slice(1).flat();
    res.json(urls);

  } catch (error) {
    console.error('Error fetching from Wayback Machine:', error.message);
    res.status(500).json({ error: 'Failed to fetch Wayback URLs' });
  }
});


app.get('/api/host-header-injection', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'Missing ?url parameter' });
  try { res.json(await checkHostHeaderInjection(url)); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/getDomainIP', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'Missing domain parameter' });
  try {
    const result = await dns.lookup(domain);
    res.json({ domain, ip: result.address, family: `IPv${result.family}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/getStaticWebChecklist', (req, res) => {
  const checklistPath = path.join(__dirname, '/Json/static_web_application_checklist.json');
  if (!fs.existsSync(checklistPath)) {
    return res.status(404).json({ error: 'Checklist file not found' });
  }

  try {
    const data = JSON.parse(fs.readFileSync(checklistPath, 'utf8'));
    res.json(data.static_web_application_checkList || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to parse checklist JSON' });
  }
});


// ========================
// 📁 Wordlist Upload + Listing
// ========================
const upload = multer({ dest: 'wordlists/' });
app.post('/api/upload-wordlist', upload.single('wordlist'), (req, res) => {
  if (!req.file) return res.status(400).send('Upload failed');
  const newPath = path.join('wordlists', req.file.originalname);
  fs.renameSync(req.file.path, newPath);
  res.send('./' + newPath.replace(/\\/g, '/'));
});

const supload = multer({ dest: 'subdomain_wordlists/' });
app.post('/api/subdomain-upload-wordlist', supload.single('subdomain_wordlists'), (req, res) => {
  if (!req.file) return res.status(400).send('Upload failed');
  const newPath = path.join('subdomain_wordlists', req.file.originalname);
  fs.renameSync(req.file.path, newPath);
  res.send('./' + newPath.replace(/\\/g, '/'));
});

app.get('/api/wordlists', (req, res) => {
  const folder = path.join(__dirname, 'wordlists');
  fs.readdir(folder, (err, files) => {
    if (err) return res.status(500).send([]);
    res.json(files.filter(f => f.endsWith('.txt')).map(f => './wordlists/' + f));
  });
});

app.get('/api/wordlist-count', (req, res) => {
  const path = req.query.path;
  const fullPath = path.startsWith('./') ? path : './' + path;
  const fs = require('fs');
  try {
    const lines = fs.readFileSync(fullPath, 'utf-8').split('\n').filter(Boolean);
    res.json(lines.length);
  } catch {
    res.status(500).json(0);
  }
});


app.get('/api/subdomain-wordlists', (req, res) => {
  const folder = path.join(__dirname, 'subdomain_wordlists');
  fs.readdir(folder, (err, files) => {
    if (err) return res.status(500).send([]);
    res.json(files.filter(f => f.endsWith('.txt')).map(f => './subdomain_wordlists/' + f));
  });
});

function checkUrl(url) {
  return new Promise(resolve => {
    exec(`curl --noproxy "*" -s -o NUL -w "%{http_code}" ${url}`, { timeout: 7000 }, (err, stdout) => {
      resolve({ url, status: stdout.trim() || '000' });
    });
  });
}


app.get('/api/discovery-stream', async (req, res) => {
  const { domain, wordlistPath, startIndex = 0 } = req.query;
  if (!domain || !wordlistPath) return res.status(400).send('Missing domain or wordlistPath');
  
  let words;
  try {
    words = fs.readFileSync(path.resolve(wordlistPath), 'utf-8')
              .split(/\r?\n/).filter(Boolean).slice(parseInt(startIndex, 10));
  } catch {
    return res.status(500).send('Failed to read wordlist');
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  for (let i = 0; i < words.length; i++) {
    const testUrl = `${domain.replace(/\/$/, '')}/${words[i].replace(/^\//, '')}`;
    const result = await checkUrl(testUrl);
    res.write(`data: ${JSON.stringify(result)}\n\n`);
  }

  res.write(`event: done\ndata: done\n\n`);
  res.end();
});

app.get('/api/subdomain-discovery-stream', async (req, res) => {
  const { domain, wordlistPath, startIndex = 0 } = req.query;
  if (!domain || !wordlistPath) return res.status(400).send('Missing domain or wordlistPath');

  let subs;
  try {
    subs = fs.readFileSync(path.resolve(wordlistPath), 'utf-8')
             .split(/\r?\n/).filter(Boolean).slice(parseInt(startIndex, 10));
  } catch {
    return res.status(500).send('Failed to read wordlist');
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  for (let i = 0; i < subs.length; i++) {
    const fullDomain = `${subs[i]}.${domain}`;
    const url = `http://${fullDomain}`;
    const result = await checkUrl(url);
    res.write(`data: ${JSON.stringify({ url, status: result.status, index: parseInt(startIndex, 10) + i + 1 })}\n\n`);
  }

  res.write(`event: done\ndata: done\n\n`);
  res.end();
});

app.get('/api/subdomains-online', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Missing domain param' });

  const vtSubs = new Set();
  const wbSubs = new Set();

  try {
    // === VirusTotal API ===
    let cursor = null;
    do {
      const vtUrl = `https://www.virustotal.com/api/v3/domains/${domain}/subdomains${cursor ? `?cursor=${cursor}` : ''}`;
      const vtRes = await axios.get(vtUrl, {
        headers: { 'x-apikey': VIRUSTOTAL_API_KEY },
        proxy: false
      });

      vtRes.data?.data?.forEach(e => {
        if (e.id?.endsWith(domain)) vtSubs.add(e.id);
      });

      cursor = vtRes.data?.meta?.cursor;
    } while (cursor);

    // === Wayback Machine ===
    const wbRes = await axios.get(
      `http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original&collapse=urlkey`,
      { proxy: false }
    );

    wbRes.data?.slice(1).forEach(entry => {
      try {
        const sub = new URL(entry[0]).hostname;
        if (sub.endsWith(domain)) wbSubs.add(sub);
      } catch (e) {
        // Ignore malformed URLs
      }
    });

    // === Merge and Sort ===
    const merged = Array.from(new Set([...vtSubs, ...wbSubs])).sort();

    res.json({
      virustotal: [...vtSubs],
      waybackurls: [...wbSubs],
      merged
    });

  } catch (err) {
    console.error('Subdomain fetch error:', err.message);
    res.status(500).json({
      error: 'Failed to fetch subdomains',
      details: err.message
    });
  }
});

app.post('/gemini-AI-generate', async (req, res) => {
  const { prompt, typemode } = req.body;
  const apiKey = GEMINI_API_KEY;

  console.log('🔍 Debug:', { prompt, typemode, apiKey });

  if (!prompt) return res.status(400).json({ error: 'Prompt is required' });
  if (!apiKey) return res.status(400).json({ error: 'API key is missing' });

  try {
    const phpAPI = 'https://pentesterhelper.in/PHToolBox/geminiAPI.php';

    const response = await axios.post(phpAPI, {
      prompt,
      typemode,
      apikey: apiKey
    }, {
      proxy: false
    });

    res.json(response.data);
  } catch (err) {
    console.error('AXIOS ERROR:', {
      message: err.message,
      code: err.code,
      response: err.response?.data,
      status: err.response?.status,
    });

    res.status(500).json({ error: 'Failed to call PHP Gemini API' });
  }
});



app.get(/^\/WaybackUrlView\.html\/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'WaybackUrlView.html'));
});


const { SocksClient } = require('socks');
const { execSync} = require('child_process');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const net = require('net');
const http = require('http');

const TOR_PATH = path.join(__dirname, 'tor.exe');
const TOR_SOCKS_PORT = 9050;
const TOR_CONTROL_PORT = 9051;
const TOR_PASSWORD = '123';
const LOCAL_PORT = 9081;

let torProcess = null;
let torReady = false;
let proxyStarted = false;

// === Start Tor only when requested ===
app.get('/start-tor', (req, res) => {
  if (torProcess) return res.send('⚠️ Tor is already running.');

  console.log('[*] Starting tor.exe...');
  torProcess = spawn(TOR_PATH, [], { cwd: __dirname });

  torProcess.stdout.on('data', async (data) => {
    const msg = data.toString();
    console.log('[tor]', msg);

    if (msg.includes('Bootstrapped 100%') && !proxyStarted) {
      torReady = true;
      proxyStarted = true;
      console.log('[✓] Tor is ready.');
      await startProxyAndSetSystemProxy();
    }
  });

  torProcess.stderr.on('data', (data) => process.stderr.write('[tor-error] ' + data.toString()));
  torProcess.on('close', () => {
    console.log('[tor] Process exited.');
    torProcess = null;
    torReady = false;
    proxyStarted = false;
  });

  res.send('⏳ Starting Tor...');
});

let proxyServerRunning = false;
let proxyServer = null;

async function startProxyAndSetSystemProxy() {
  if (proxyServerRunning) {
    console.log('⚠️ Proxy already running.');
    return;
  }

  proxyServer = http.createServer();

  proxyServer.on('connect', (req, clientSocket, head) => {
    const { port, hostname } = new URL(`http://${req.url}`);

    SocksClient.createConnection({
      proxy: { ipaddress: '127.0.0.1', port: TOR_SOCKS_PORT, type: 5 },
      command: 'connect',
      destination: { host: hostname, port: parseInt(port, 10) }
    }).then(info => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      info.socket.write(head);

      info.socket.pipe(clientSocket);
      clientSocket.pipe(info.socket);

      info.socket.on('error', err => {
        console.warn('[!] SOCKS socket error:', err.message);
        clientSocket.destroy();
      });

      clientSocket.on('error', err => {
        console.warn('[!] Client socket error:', err.message);
        info.socket.destroy();
      });
    }).catch(err => {
      console.error('❌ Proxy connection failed:', err.message);
      clientSocket.end('HTTP/1.1 500 Connection error\r\n');
    });
  });

  proxyServer.listen(LOCAL_PORT, async () => {
    proxyServerRunning = true;
    console.log(`✅ SOCKS5→HTTP proxy running at http://127.0.0.1:${LOCAL_PORT}`);

    try {
      // Set system proxy (WinHTTP + Internet Settings)
      execSync(`netsh winhttp set proxy 127.0.0.1:${LOCAL_PORT}`);
      execSync(`powershell -Command "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1"`);
      execSync(`powershell -Command "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value '127.0.0.1:${LOCAL_PORT}'"`);

      console.log('✅ System proxy set to 127.0.0.1:' + LOCAL_PORT);
    } catch (err) {
      console.error('❌ Proxy set failed:', err.message);
    }
  });

  proxyServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ Port ${LOCAL_PORT} is already in use. Restart or kill the process.`);
    } else {
      console.error('❌ Proxy Server Error:', err.message);
    }
  });
}


// === Rotate Tor IP ===
function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function sendNewTorIdentity(password) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(TOR_CONTROL_PORT, '127.0.0.1', () => {
      socket.write(`AUTHENTICATE "${password}"\r\n`);
    });

    let step = 0;
    let buffer = '';
    socket.on('data', data => {
      buffer += data.toString();
      if (step === 0 && buffer.includes('250 OK')) {
        step = 1;
        socket.write('SIGNAL NEWNYM\r\n');
      } else if (step === 1 && buffer.includes('250 OK')) {
        socket.end();
        console.log('[+] Tor identity rotated');
        resolve();
      } else if (buffer.includes('515')) {
        socket.end();
        reject('Tor AUTHENTICATE failed.');
      }
    });

    socket.on('error', err => reject('ControlPort error: ' + err.message));
  });
}

app.post('/tor-rotate', async (req, res) => {
  try {
    await sendNewTorIdentity(TOR_PASSWORD);
    await wait(5000);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Rotation failed' });
  }
});

// === Get Current Tor IP ===
app.get('/tor-ip', async (req, res) => {
  try {
    const direct = await axios.get('https://api.ipify.org?format=json');

    res.json({
      real_ip: direct.data.ip
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to detect IPs', message: err.message });
  }
});



// === Unset system proxy ===
app.get('/unset-system-proxy', (req, res) => {
  try {
    exec(`netsh winhttp reset proxy`);
    exec(`powershell -Command "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0"`);
    res.send('✅ System proxy disabled');
  } catch (err) {
    console.error('❌ Failed to disable proxy:', err.message);
    res.status(500).send('Failed to disable proxy');
  }
});

// === Check proxy status ===
app.get('/proxy-status', (req, res) => {
  exec(`powershell -Command "(Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings').ProxyEnable"`, (err, stdout) => {
    if (err) return res.status(500).json({ enabled: false });
    const isEnabled = stdout.trim() === '1';
    res.json({ enabled: isEnabled });
  });
});

// Stop tor.exe process from web
// ========== STOP TOR ==========
app.get('/stop-tor', (req, res) => {
  try {
    if (torProcess) {
      torProcess.kill();
      torProcess = null;
      torReady = false;

      if (proxyServer) {
        proxyServer.close(() => {
          console.log('🛑 Proxy server stopped.');
          proxyServerRunning = false;
        });
      }

      execSync(`netsh winhttp reset proxy`);
      execSync(`powershell -Command "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0"`);

      res.send('🛑 Tor stopped & system proxy disabled.');
    } else {
      res.send('⚠️ Tor is not running.');
    }
  } catch (err) {
    console.error('❌ Failed to stop tor:', err.message);
    res.status(500).send('Failed to stop Tor.');
  }
});


app.get('/set-system-proxy', (req, res) => {
  try {
    execSync(`netsh winhttp set proxy 127.0.0.1:9081`);
    execSync(`powershell -Command "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1"`);
    execSync(`powershell -Command "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value '127.0.0.1:9081'"`);
    res.send('✅ System proxy enabled');
  } catch (err) {
    console.error('❌ Failed to enable system proxy:', err.message);
    res.status(500).send('❌ Failed to enable system proxy');
  }
});


app.listen(PORT, () => {
  console.log(`🚀 Server running at: http://localhost:${PORT}`);
});
