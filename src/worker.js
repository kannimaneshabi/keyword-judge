const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const MAX_BYTES = 700000;
const TIMEOUT_MS = 15000;

function cors() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400'
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors() }
  });
}

function blockedHost(host) {
  const h = host.toLowerCase();
  if (!h) return '空主机名';
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') ||
      h.endsWith('.internal') || h === 'metadata.google.internal') return '内网主机名';
  if (h.includes(':')) return 'IPv6 与非常规主机名不允许';
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127) return '私有或回环地址';
    if (a === 169 && b === 254) return '链路本地地址';
    if (a === 172 && b >= 16 && b <= 31) return '私有地址';
    if (a === 192 && b === 168) return '私有地址';
    if (a === 100 && b >= 64 && b <= 127) return '运营商级 NAT 地址';
    if (a >= 224) return '组播或保留地址';
    return null;
  }
  return null;
}

async function handleProxy(url) {
  const target = url.searchParams.get('url');
  if (!target) return json({ ok: false, error: '缺少 url 参数' }, 400);

  let t;
  try {
    t = new URL(target);
  } catch (e) {
    return json({ ok: false, error: 'URL 格式无效' }, 400);
  }

  if (t.protocol !== 'http:' && t.protocol !== 'https:') {
    return json({ ok: false, error: '仅支持 http 与 https' }, 400);
  }
  const blocked = blockedHost(t.hostname);
  if (blocked) return json({ ok: false, error: '目标地址不允许访问：' + blocked }, 403);
  if (t.port && t.port !== '80' && t.port !== '443') {
    return json({ ok: false, error: '仅支持 80 / 443 端口' }, 403);
  }

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  const started = Date.now();
  try {
    const res = await fetch(t.toString(), {
      redirect: 'follow',
      signal: ctl.signal,
      headers: {
        'User-Agent': UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
      }
    });
    const ct = res.headers.get('content-type') || '';
    if (!/text\/html|application\/xhtml|text\/plain/i.test(ct)) {
      return json({ ok: false, error: '目标返回的不是 HTML（' + (ct || '未知类型') + '）', status: res.status });
    }
    const buf = await res.arrayBuffer();
    const bytes = buf.byteLength;
    const cut = buf.slice(0, MAX_BYTES);
    return json({
      ok: res.ok,
      requested: t.toString(),
      finalUrl: res.url || t.toString(),
      status: res.status,
      contentType: ct,
      bytes,
      truncated: bytes > MAX_BYTES,
      ms: Date.now() - started,
      html: new TextDecoder('utf-8').decode(cut)
    }, res.ok ? 200 : 502);
  } catch (e) {
    let reason = String(e.message || e);
    if (e.name === 'AbortError' || /timeout|aborted/i.test(reason)) reason = '超时（' + TIMEOUT_MS + 'ms）';
    else if (/internal error|dns|resolve|ENOTFOUND/i.test(reason)) reason = '域名无法解析或目标拒绝连接';
    else if (/certificate|tls|ssl/i.test(reason)) reason = 'HTTPS 证书错误';
    return json({ ok: false, error: '抓取失败：' + reason, ms: Date.now() - started }, 502);
  } finally {
    clearTimeout(timer);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/fetch-page') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });
      if (request.method !== 'GET') return json({ ok: false, error: '仅支持 GET' }, 405);

      // 按访问者 IP 限流。注意：本 binding 在实测中未触发（70 次连续请求仍全部放行），
      // 因此不能作为唯一防护；生产环境应在 Cloudflare 控制台为 /api/fetch-page* 另配 Rate Limiting 规则。
      // 本地 dev 无此 binding 时自动跳过。
      if (env.FETCH_LIMITER) {
        const ip = request.headers.get('CF-Connecting-IP') || 'anonymous';
        const { success } = await env.FETCH_LIMITER.limit({ key: ip });
        if (!success) {
          return json({ ok: false, error: '请求过于频繁，请稍后再试（每分钟最多 60 次）' }, 429);
        }
      }
      return handleProxy(url);
    }

    if (url.pathname === '/api/health') {
      return json({ ok: true, service: 'keyword-judge', time: new Date().toISOString() });
    }

    return env.ASSETS.fetch(request);
  }
};
