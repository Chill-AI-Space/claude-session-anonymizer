/**
 * Session Collector — Cloudflare Worker
 *
 * Public API for collecting anonymized Claude Code sessions.
 * Storage: R2 (files) + KV (metadata index + rate limiting)
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

// ── Rate Limiting (KV-based, per IP) ──────────────────────────────────────

async function checkRateLimit(kv, ip, maxPerHour) {
  const key = `rate:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - 3600;

  const raw = await kv.get(key, 'json');
  const timestamps = (raw || []).filter((t) => t > windowStart);

  if (timestamps.length >= maxPerHour) {
    return { allowed: false, remaining: 0 };
  }

  timestamps.push(now);
  await kv.put(key, JSON.stringify(timestamps), { expirationTtl: 3600 });

  return { allowed: true, remaining: maxPerHour - timestamps.length };
}

// ── SHA-256 hash ──────────────────────────────────────────────────────────

async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ── Routes ────────────────────────────────────────────────────────────────

async function handleSubmit(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const maxPerHour = parseInt(env.RATE_LIMIT_PER_HOUR) || 10;
  const maxFileSize = parseInt(env.MAX_FILE_SIZE) || 5 * 1024 * 1024;

  // Rate limit check
  const rateCheck = await checkRateLimit(env.META, ip, maxPerHour);
  if (!rateCheck.allowed) {
    return json({ error: 'Rate limit exceeded. Try again later.' }, 429);
  }

  // Read body
  const body = await request.arrayBuffer();
  if (body.byteLength === 0) {
    return json({ error: 'Empty body' }, 400);
  }
  if (body.byteLength > maxFileSize) {
    return json({ error: `File too large. Max ${maxFileSize / 1024 / 1024}MB` }, 413);
  }

  // Compute hash for dedup
  const hash = await sha256(body);

  // Check if already exists
  const existing = await env.SESSIONS.head(hash + '.jsonl');
  if (existing) {
    return json({
      status: 'duplicate',
      hash,
      message: 'This session was already submitted.',
    });
  }

  // Quick sanity check: should look like JSONL (first line is valid JSON)
  const text = new TextDecoder().decode(body.slice(0, 1000));
  const firstLine = text.split('\n')[0];
  try {
    JSON.parse(firstLine);
  } catch {
    return json({ error: 'Invalid format. Expected JSONL (anonymized session file).' }, 400);
  }

  // Store in R2
  const now = new Date().toISOString();
  await env.SESSIONS.put(hash + '.jsonl', body, {
    customMetadata: {
      submitted_at: now,
      size: String(body.byteLength),
      ip_hash: await sha256(new TextEncoder().encode(ip + 'salt:session-collector')),
    },
  });

  // Update index in KV
  const index = (await env.META.get('session-index', 'json')) || [];
  index.push({
    hash,
    submitted_at: now,
    size: body.byteLength,
  });
  await env.META.put('session-index', JSON.stringify(index));

  return json({
    status: 'ok',
    hash,
    message: 'Session submitted successfully.',
    remaining_submissions: rateCheck.remaining - 1,
  });
}

async function handleList(env, base = '') {
  const index = (await env.META.get('session-index', 'json')) || [];

  return json({
    count: index.length,
    sessions: index.map((s) => ({
      hash: s.hash,
      submitted_at: s.submitted_at,
      size: s.size,
      download: `${base}/sessions/${s.hash}`,
    })),
  });
}

async function handleGet(hash, env) {
  const object = await env.SESSIONS.get(hash + '.jsonl');
  if (!object) {
    return json({ error: 'Session not found' }, 404);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': 'application/x-ndjson',
      'Content-Disposition': `attachment; filename="${hash.slice(0, 12)}.jsonl"`,
      ...CORS_HEADERS,
    },
  });
}

async function handleStats(env) {
  const index = (await env.META.get('session-index', 'json')) || [];
  const totalSize = index.reduce((sum, s) => sum + (s.size || 0), 0);

  return json({
    total_sessions: index.length,
    total_size_bytes: totalSize,
    total_size_mb: (totalSize / 1024 / 1024).toFixed(2),
    oldest: index.length > 0 ? index[0].submitted_at : null,
    newest: index.length > 0 ? index[index.length - 1].submitted_at : null,
  });
}

// ── Main router ───────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const base = env.BASE_PATH || '/anonymised-claude-sessions';
    // Strip base path prefix to get the route
    let path = url.pathname;
    if (path.startsWith(base)) {
      path = path.slice(base.length) || '/';
    }

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // POST /submit
    if (request.method === 'POST' && path === '/submit') {
      return handleSubmit(request, env);
    }

    // GET /sessions
    if (request.method === 'GET' && path === '/sessions') {
      return handleList(env, base);
    }

    // GET /sessions/:hash
    const sessionMatch = path.match(/^\/sessions\/([a-f0-9]{64})$/);
    if (request.method === 'GET' && sessionMatch) {
      return handleGet(sessionMatch[1], env);
    }

    // GET /stats
    if (request.method === 'GET' && path === '/stats') {
      return handleStats(env);
    }

    // GET / — info page
    if (request.method === 'GET' && path === '/') {
      return json({
        name: 'Claude Session Collector',
        description: 'Public repository of anonymized Claude Code sessions',
        endpoints: {
          [`POST ${base}/submit`]: 'Submit an anonymized session (.jsonl body)',
          [`GET ${base}/sessions`]: 'List all submitted sessions',
          [`GET ${base}/sessions/:hash`]: 'Download a specific session',
          [`GET ${base}/stats`]: 'Collection statistics',
        },
        source: 'https://github.com/Chill-AI-Space/claude-session-anonymizer',
        rate_limit: `${env.RATE_LIMIT_PER_HOUR} submissions per hour per IP`,
      });
    }

    return json({ error: 'Not found' }, 404);
  },
};
