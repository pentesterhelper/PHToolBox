// server/tester.js
const axios = require('axios');
const { URL } = require('url');

const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'HEAD'];

async function sendRequest(method, fullUrl) {
    let parsedUrl;
    try {
        parsedUrl = new URL(fullUrl);
    } catch {
        return {
            method,
            url: fullUrl,
            error: 'Invalid URL'
        };
    }

    const host = parsedUrl.host;

    const config = {
        method,
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
        data: method !== 'GET' && method !== 'HEAD' ? { test: 'data' } : undefined,
        proxy: false // 👈 disables proxy usage completely
    };

    try {
        const response = await axios(config);
        return {
            method,
            url: fullUrl,
            host,
            request: {
                headers: config.headers,
                body: config.data || null
            },
            response: {
                status: response.status,
                headers: response.headers,
                body: response.data
            }
        };
    } catch (err) {
        return {
            method,
            url: fullUrl,
            host,
            error: err.message
        };
    }
}

async function testAllMethods(url) {
    const results = [];
    for (const method of methods) {
        const result = await sendRequest(method, url);
        results.push(result);
    }
    return results;
}

module.exports = { testAllMethods };