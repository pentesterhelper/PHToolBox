const { spawn } = require('child_process');

const methods = ['GET', 'POST', 'HEAD']; // Safe methods
const pathVariants = ['', '/', '/.', '/..', '/...', '/test', '//'];
const spoofedHosts = [null, 'fintakeai.com'];

function extractServerInfo(headerStr) {
    const headers = {};
    const lines = headerStr.split('\r\n');
    for (const line of lines) {
        const [key, ...rest] = line.split(': ');
        if (!key || !rest.length) continue;
        headers[key.toLowerCase()] = rest.join(': ');
    }

    return {
        server: headers['server'] || null,
        'x-powered-by': headers['x-powered-by'] || null,
        'x-aspnet-version': headers['x-aspnet-version'] || null,
        'x-runtime': headers['x-runtime'] || null,
        'x-generator': headers['x-generator'] || null,
        'x-server': headers['x-server'] || null,
        'x-hostname': headers['x-hostname'] || null,
        via: headers['via'] || null,
        panel: headers['panel'] || null,
        platform: headers['platform'] || null
    };
}

function runCurlRequest(url, path, method, spoofedHost) {
    return new Promise((resolve) => {
        const fullUrl = url + path;

        const args = [
            '-X', method,
            fullUrl,
            '--noproxy', '*',
            '-i', // include headers
            '-s', '--max-time', '10',
            '-A', 'Mozilla/5.0',
            '--location' // follow redirects if any
        ];

        if (spoofedHost) {
            args.push('-H', `Host: ${spoofedHost}`);
        }

        const curl = spawn('curl', args);
        let output = '';
        let error = '';

        curl.stdout.on('data', (data) => {
            output += data.toString();
        });

        curl.stderr.on('data', (data) => {
            error += data.toString();
        });

        curl.on('close', () => {
            // Extract all header blocks (in case of redirects, multiple responses)
            const headerSections = output.split('\r\n\r\n');
            const lastHeaderIndex = headerSections.findLastIndex(section => section.startsWith('HTTP/'));
            const rawHeaders = headerSections[lastHeaderIndex] || '';
            const body = headerSections.slice(lastHeaderIndex + 1).join('\r\n\r\n');

            const statusLine = rawHeaders.split('\r\n')[0] || '';
            const statusMatch = statusLine.match(/HTTP\/.* (\d+)/);
            const status = statusMatch ? parseInt(statusMatch[1]) : null;

            const serverHeaders = extractServerInfo(rawHeaders);

            resolve({
                url: fullUrl,
                method,
                path,
                spoofedHost: spoofedHost || 'original',
                status,
                allHeaders: rawHeaders || null,
                serverHeaders,
                bodyPreview: body.slice(0, 200),
                error: error.trim() || null
            });
        });
    });
}

async function testServerHeaders(url) {
    const results = [];
    const headerSummary = {};

    for (const path of pathVariants) {
        for (const method of methods) {
            for (const spoofHost of spoofedHosts) {
                const result = await runCurlRequest(url, path, method, spoofHost);
                results.push(result);

                if (!result.error && result.serverHeaders) {
                    for (const [header, value] of Object.entries(result.serverHeaders)) {
                        if (value) {
                            if (!headerSummary[header]) {
                                headerSummary[header] = new Set();
                            }
                            headerSummary[header].add(value);
                        }
                    }
                }
            }
        }
    }

    const uniqueServerHeaders = {};
    for (const [key, values] of Object.entries(headerSummary)) {
        uniqueServerHeaders[key] = Array.from(values);
    }

    return {
        rawResults: results,
        uniqueServerHeaders
    };
}

module.exports = { testServerHeaders };
