import { DurableObject } from 'cloudflare:workers'

const MIN = 60 * 1000
const HOUR = 60 * MIN
const DAY = 24 * HOUR

const num = (env, key, def) => {
  const n = Number(env[key])
  return Number.isFinite(n) && n > 0 ? n : def
}

function limits(env) {
  return {
    ipCooldownMs: num(env, 'IP_COOLDOWN_SEC', 30) * 1000,
    ipHourly: num(env, 'IP_HOURLY', 6),
    ipDaily: num(env, 'IP_DAILY', 20),
    uploadPer10Min: num(env, 'UPLOAD_PER_10MIN', 8),
    strikesToBan: num(env, 'STRIKES_TO_BAN', 5),
    banMs: num(env, 'BAN_MIN', 30) * MIN,
    phoneCooldownMs: num(env, 'PHONE_COOLDOWN_SEC', 60) * 1000,
    phoneDaily: num(env, 'PHONE_DAILY', 5),
  }
}

const deny = (status, waitMs, error) => ({ ok: false, status, retryAfter: Math.max(1, Math.ceil(waitMs / 1000)), error })

/**
 * Satu Durable Object per kunci ("ip:1.2.3.4" atau "phone:62812..."), jadi hitungan
 * konsisten walau Worker jalan di banyak lokasi. State dihapus 25 jam setelah aktivitas terakhir.
 */
export class Limiter extends DurableObject {
  async #load() {
    const s = (await this.ctx.storage.get('s')) || {}
    const now = Date.now()
    const keep = (a, ms) => (a || []).filter((t) => now - t < ms)
    return {
      creates: keep(s.creates, DAY),
      uploads: keep(s.uploads, 10 * MIN),
      strikes: keep(s.strikes, 10 * MIN),
      banUntil: s.banUntil || 0,
    }
  }

  async #save(s) {
    await this.ctx.storage.put('s', s)
    await this.ctx.storage.setAlarm(Date.now() + 25 * HOUR)
  }

  async alarm() {
    await this.ctx.storage.deleteAll()
  }

  // Catat pelanggaran; cukup banyak pelanggaran -> blokir sementara.
  #strike(s, L, now) {
    s.strikes.push(now)
    if (s.strikes.length >= L.strikesToBan) {
      s.banUntil = now + L.banMs
      s.strikes = []
    }
  }

  /** Cek + catat satu aksi dari sebuah IP. action: 'upload' | 'create' */
  async ipCheck(action, L) {
    const now = Date.now()
    const s = await this.#load()
    if (s.banUntil > now) {
      return deny(403, s.banUntil - now, 'Akses diblokir sementara karena terlalu banyak percobaan.')
    }

    let waitMs = 0
    let error = ''
    if (action === 'upload') {
      if (s.uploads.length >= L.uploadPer10Min) {
        waitMs = s.uploads[0] + 10 * MIN - now
        error = 'Terlalu banyak unggahan. Coba lagi nanti.'
      }
    } else {
      const last = s.creates[s.creates.length - 1]
      const hour = s.creates.filter((t) => now - t < HOUR)
      if (last && now - last < L.ipCooldownMs) {
        waitMs = last + L.ipCooldownMs - now
        error = `Tunggu ${Math.ceil(waitMs / 1000)} detik sebelum membuat sticker lagi.`
      } else if (hour.length >= L.ipHourly) {
        waitMs = hour[0] + HOUR - now
        error = 'Batas pembuatan per jam tercapai. Coba lagi nanti.'
      } else if (s.creates.length >= L.ipDaily) {
        waitMs = s.creates[0] + DAY - now
        error = 'Batas pembuatan harian tercapai. Coba lagi besok.'
      }
    }

    if (waitMs > 0) {
      this.#strike(s, L, now)
      await this.#save(s)
      if (s.banUntil > now) return deny(403, s.banUntil - now, 'Akses diblokir sementara karena terlalu banyak percobaan.')
      return deny(429, waitMs, error)
    }

    ;(action === 'upload' ? s.uploads : s.creates).push(now)
    await this.#save(s)
    return { ok: true }
  }

  /** Batalkan catatan create terakhir (permintaan gagal); strike=true juga dihitung pelanggaran. */
  async ipRefund(strike, L) {
    const s = await this.#load()
    s.creates.pop()
    if (strike) this.#strike(s, L, Date.now())
    await this.#save(s)
  }

  /** Cooldown + batas harian untuk nomor tujuan. */
  async phoneCheck(L) {
    const now = Date.now()
    const s = await this.#load()
    const last = s.creates[s.creates.length - 1]
    if (last && now - last < L.phoneCooldownMs) {
      const w = last + L.phoneCooldownMs - now
      return deny(429, w, `Nomor ini baru saja dikirimi sticker. Tunggu ${Math.ceil(w / 1000)} detik.`)
    }
    if (s.creates.length >= L.phoneDaily) {
      return deny(429, s.creates[0] + DAY - now, 'Nomor ini sudah mencapai batas sticker hari ini.')
    }
    s.creates.push(now)
    await this.#save(s)
    return { ok: true }
  }

  async phoneRefund() {
    const s = await this.#load()
    s.creates.pop()
    await this.#save(s)
  }
}

// ---------- Util ----------

function normalizePhone(raw) {
  let d = String(raw || '').replace(/\D/g, '')
  if (d.startsWith('62')) d = '62' + d.slice(2).replace(/^0+/, '')
  else if (d.startsWith('0')) d = '62' + d.slice(1)
  else if (d.startsWith('8')) d = '62' + d
  return /^628\d{8,11}$/.test(d) ? d : null
}

const json = (status, body, extra = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  })

const rejection = (r) => json(r.status, { error: r.error }, { 'Retry-After': String(r.retryAfter) })

function corsFor(origin, env) {
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean)
  const any = allowed.includes('*')
  if (!any && !allowed.includes(origin)) return null
  return {
    'Access-Control-Allow-Origin': any ? '*' : origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Expose-Headers': 'Retry-After',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  }
}

function toOrigin(env, request, url, ip, body) {
  const headers = new Headers({
    'Content-Type': request.headers.get('content-type') || 'application/octet-stream',
    'X-Worker-Secret': env.WORKER_SECRET,
    'X-Forwarded-For': ip,
  })
  const len = request.headers.get('content-length')
  if (len && typeof body !== 'string') headers.set('Content-Length', len)
  return fetch(env.ORIGIN_URL.replace(/\/$/, '') + url.pathname + url.search, { method: request.method, headers, body })
}

async function passthrough(res) {
  return new Response(res.body, {
    status: res.status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

const limiter = (env, key) => env.LIMITER.get(env.LIMITER.idFromName(key))

// ---------- Handler ----------

async function route(request, env, url, ip) {
  const L = limits(env)

  if (request.method === 'GET' && url.pathname === '/api/status') {
    try {
      return await passthrough(await toOrigin(env, request, url, ip))
    } catch (_) {
      return json(502, { ready: false })
    }
  }

  if (request.method === 'POST' && url.pathname === '/api/upload') {
    const r = await limiter(env, 'ip:' + ip).ipCheck('upload', L)
    if (!r.ok) return rejection(r)
    return passthrough(await toOrigin(env, request, url, ip, request.body))
  }

  if (request.method === 'POST' && url.pathname === '/api/create') {
    const text = await request.text()
    if (text.length > 4096) return json(413, { error: 'Data terlalu besar.' })
    let body
    try {
      body = JSON.parse(text)
    } catch (_) {
      return json(400, { error: 'Permintaan tidak valid.' })
    }
    const phone = normalizePhone(body?.phone)
    if (!phone) return json(400, { error: 'Nomor harus nomor WhatsApp Indonesia (+62 8xx).' })

    const ipBox = limiter(env, 'ip:' + ip)
    const phoneBox = limiter(env, 'phone:' + phone)

    const a = await ipBox.ipCheck('create', L)
    if (!a.ok) return rejection(a)
    const b = await phoneBox.phoneCheck(L)
    if (!b.ok) {
      await ipBox.ipRefund(true, L) // menembak nomor yang sama berulang dihitung pelanggaran
      return rejection(b)
    }

    let res
    try {
      res = await toOrigin(env, request, url, ip, text)
    } catch (_) {
      res = null
    }
    if (!res || !res.ok) {
      // Gagal (nomor salah, bot mati, dsb.): jangan hitung ke jatah/cooldown
      await Promise.all([ipBox.ipRefund(false, L), phoneBox.phoneRefund()])
      if (!res) return json(502, { error: 'Bot tidak bisa dihubungi. Coba lagi nanti.' })
    }
    return passthrough(res)
  }

  return json(404, { error: 'Tidak ditemukan.' })
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin')
    const cors = origin ? corsFor(origin, env) : {}
    if (origin && !cors) return json(403, { error: 'Origin tidak diizinkan.' })
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors })

    if (!env.ORIGIN_URL || !env.WORKER_SECRET) {
      console.log('ORIGIN_URL / WORKER_SECRET belum diatur')
      return json(500, { error: 'Server belum dikonfigurasi.' }, cors)
    }

    const url = new URL(request.url)
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown'
    let res
    try {
      res = await route(request, env, url, ip)
    } catch (err) {
      console.log('Worker error:', err)
      res = json(500, { error: 'Terjadi kesalahan. Coba lagi.' })
    }
    const out = new Response(res.body, res)
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v)
    return out
  },
}
