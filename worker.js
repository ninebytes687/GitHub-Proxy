'use strict'
const ASSET_URL = 'https://hunshcn.github.io/gh-proxy/'
const PREFIX = '/'
const Config = {
    jsdelivr: 0
}
const whiteList = []
const PREFLIGHT_INIT = {
    status: 204,
    headers: new Headers({
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
        'access-control-max-age': '1728000',
    }),
}
const exp1 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive)\/.*$/i
const exp2 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i
const exp3 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:info|git-).*$/i
const exp4 = /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+?\/.+$/i
const exp5 = /^(?:https?:\/\/)?gist\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+$/i
const exp6 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/tags.*$/i

function makeRes(body, status = 200, headers = {}) {
    headers['access-control-allow-origin'] = '*'
    headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
    return new Response(body, { status, headers })
}

function newUrl(urlStr) {
    try { return new URL(urlStr) } catch (err) { return null }
}

function checkUrl(u) {
    for (let i of [exp1, exp2, exp3, exp4, exp5, exp6]) {
        if (u.search(i) === 0) return true
    }
    return false
}

function verifyPassword(inputCode, env) {
    const correctPassword = env && env.MY_TOTP_SECRET ? env.MY_TOTP_SECRET : 'NineBytes666';
    return inputCode.trim() === correctPassword.trim();
}

export default {
    async fetch(request, env, ctx) {
        try {
            return await fetchHandler(request, env);
        } catch (err) {
            return makeRes('cfworker error:\n' + err.stack, 502);
        }
    }
}

async function fetchHandler(req, env) {
    const urlStr = req.url
    const urlObj = new URL(urlStr)


    if (urlObj.pathname === '/robots.txt') {
        return new Response('User-agent: *\nDisallow: /', {
            status: 200, headers: { 'Content-Type': 'text/plain', 'X-Robots-Tag': 'noindex, nofollow' }
        })
    }


    if (urlObj.pathname === PREFIX || urlObj.pathname === '/index.html' || urlObj.pathname === '/') {
        if (!urlObj.searchParams.get('q')) {
            return new Response(HTML_TEMPLATE, {
                status: 200,
                headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                    'X-Robots-Tag': 'noindex, nofollow, noarchive'
                }
            })
        }
    }


    const inputCode = urlObj.searchParams.get('code')
    const isProxyRequest = urlObj.searchParams.get('q') || urlObj.href.slice(urlObj.origin.length + PREFIX.length).includes('github')
    
    if (isProxyRequest) {
        if (!inputCode || !verifyPassword(inputCode, env)) {
            return makeRes('403 Forbidden: 请提供正确的访问密码。', 403)
        }
    }

    let path = urlObj.searchParams.get('q')
    if (path) {
        return Response.redirect('https://' + urlObj.host + PREFIX + path + '?code=' + inputCode, 301)
    }

    let cleanHref = urlObj.href
    const cleanUrlObj = new URL(urlStr)
    cleanUrlObj.searchParams.delete('code')
    cleanHref = cleanUrlObj.href

    path = cleanHref.slice(urlObj.origin.length + PREFIX.length).replace(/^https?:\/+/, 'https://')
    
    if (path.search(exp1) === 0 || path.search(exp5) === 0 || path.search(exp6) === 0 || path.search(exp3) === 0) {
        return httpHandler(req, path)
    } else if (path.search(exp2) === 0) {
        if (Config.jsdelivr) {
            const newUrl = path.replace('/blob/', '@').replace(/^(?:https?:\/\/)?github\.com/, 'https://cdn.jsdelivr.net/gh')
            return Response.redirect(newUrl, 302)
        } else {
            path = path.replace('/blob/', '/raw/')
            return httpHandler(req, path)
        }
    } else if (path.search(exp4) === 0) {
        if (Config.jsdelivr) {
            const newUrl = path.replace(/(?<=com\/.+?\/.+?)\/(.+?\/)/, '@$1').replace(/^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com/, 'https://cdn.jsdelivr.net/gh')
            return Response.redirect(newUrl, 302)
        } else {
            return httpHandler(req, path)
        }
    } else {
        return fetch(ASSET_URL + path)
    }
}

function httpHandler(req, pathname) {
    const reqHdrRaw = req.headers

    if (req.method === 'OPTIONS' && reqHdrRaw.has('access-control-request-headers')) {
        return new Response(null, PREFLIGHT_INIT)
    }

    const reqHdrNew = new Headers(reqHdrRaw)
    let urlStr = pathname
    let flag = !Boolean(whiteList.length)
    for (let i of whiteList) {
        if (urlStr.includes(i)) { flag = true; break }
    }
    if (!flag) return new Response("blocked", { status: 403 })
    
    if (urlStr.search(/^https?:\/\//) !== 0) {
        urlStr = 'https://' + urlStr
    }
    const urlObj = newUrl(urlStr)
    
    const reqInit = {
        method: req.method,
        headers: reqHdrNew,
        redirect: 'manual',
        body: req.body
    }
    return proxy(urlObj, reqInit)
}

async function proxy(urlObj, reqInit) {
    const res = await fetch(urlObj.href, reqInit)
    const resHdrOld = res.headers
    const resHdrNew = new Headers(resHdrOld)
    const status = res.status

    if (resHdrNew.has('location')) {
        let _location = resHdrNew.get('location')
        if (checkUrl(_location))
            resHdrNew.set('location', PREFIX + _location)
        else {
            reqInit.redirect = 'follow'
            return proxy(newUrl(_location), reqInit)
        }
    }
    resHdrNew.set('access-control-expose-headers', '*')
    resHdrNew.set('access-control-allow-origin', '*')

    resHdrNew.delete('content-security-policy')
    resHdrNew.delete('content-security-policy-report-only')
    resHdrNew.delete('clear-site-data')
    
    resHdrNew.set('X-Robots-Tag', 'noindex, nofollow, noarchive')

    return new Response(res.body, { status, headers: resHdrNew })
}

const HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub 文件加速下载</title>
    <style>
        :root {
            --primary-color: #2da44e;
            --primary-disabled: #38433a;
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --text-color: #c9d1d9;
            --border-color: #30363d;
            --error-color: #f85149;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: var(--card-bg);
            padding: 30px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            width: 100%;
            max-width: 500px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
            position: relative;
        }
        h2 {
            margin-top: 0;
            font-size: 20px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 10px 12px;
            box-sizing: border-box;
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #58a6ff;
        }
        #totpCode {
            font-size: 14px;
            text-align: left;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
            margin-bottom: 10px;
        }
        button:hover { background-color: #2c974b; }
        button:disabled {
            background-color: var(--primary-disabled);
            cursor: not-allowed;
            color: rgba(255,255,255,0.4);
        }
        .error-toast {
            display: none;
            position: absolute;
            top: -50px;
            left: 50%;
            transform: translateX(-50%);
            background-color: var(--error-color);
            color: white;
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: fadeIn 0.3s;
            white-space: nowrap;
        }
        .footer-info {
            text-align: center;
            font-size: 11px;
            color: #8b949e;
            margin-top: 20px;
            border-top: 1px solid #21262d;
            padding-top: 15px;
            letter-spacing: 0.5px;
            line-height: 1.6;
        }
        .footer-info .project-link {
            margin-top: 4px;
            color: #79c0ff;
            text-decoration: none;
            transition: color 0.2s;
        }
        .footer-info .project-link:hover {
            color: #58a6ff;
            text-decoration: underline;
        }
        /* 新增：提示声明文字的小样式 */
        .footer-info .private-notice {
            margin-top: 4px;
            color: #f85149;
            opacity: 0.85;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translate(-50%, -10px); }
            to { opacity: 1; transform: translate(-50%, 0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div id="errorToast" class="error-toast">密码错误</div>
        <h2>GitHub 文件私有加速站</h2>
        
        <div class="form-group">
            <label for="githubUrl">GitHub 文件链接</label>
            <input type="text" id="githubUrl" placeholder="https://github.com/... /releases/download/...">
        </div>

        <div class="form-group">
            <label for="totpCode">下载密码</label>
            <input type="password" id="totpCode" placeholder="请输入下载密码">
        </div>

        <button id="downloadBtn" disabled>下载</button>

        <div class="footer-info">
            <div>&copy; 2026 NineBytes. All rights reserved.</div>
            <div style="margin-top: 4px;">
                项目基于 Cloudflare Workers，开源于 GitHub 
                <a class="project-link" href="https://github.com/hunshcn/gh-proxy" target="_blank" rel="noopener noreferrer">hunshcn/gh-proxy</a>
            </div>
            <div class="private-notice">本站为个人私有加速服务，不对公众开放</div>
        </div>
    </div>

    <script>
        const githubUrlInput = document.getElementById('githubUrl');
        const totpCodeInput = document.getElementById('totpCode');
        const downloadBtn = document.getElementById('downloadBtn');
        const errorToast = document.getElementById('errorToast');

        function checkInputs() {
            const urlValue = githubUrlInput.value.trim();
            const codeValue = totpCodeInput.value.trim();
            downloadBtn.disabled = !(urlValue.length > 0 && codeValue.length > 0);
        }

        githubUrlInput.addEventListener('input', checkInputs);
        totpCodeInput.addEventListener('input', checkInputs);

        downloadBtn.addEventListener('click', async () => {
            const targetUrl = githubUrlInput.value.trim();
            const code = totpCodeInput.value.trim();
            const workerDomain = window.location.origin; 
            const requestUrl = \`\${workerDomain}/\${targetUrl}?code=\${code}\`;

            try {
                downloadBtn.disabled = true;
                downloadBtn.innerText = '正在验证...';
                
                const response = await fetch(requestUrl, { method: 'HEAD' });
                
                if (response.status === 403) {
                    showError();
                } else {
                    window.open(requestUrl, '_blank');
                }
            } catch (err) {
                showError();
            } finally {
                downloadBtn.innerText = '下载';
                checkInputs();
            }
        });

        function showError() {
            errorToast.style.display = 'block';
            setTimeout(() => { errorToast.style.display = 'none'; }, 3000);
        }
    </script>
</body>
</html>
`
