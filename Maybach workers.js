// 代码名称：GrainTCP+CM+XHTTP+jaclbax
// 版本号：v1.4.4 (Bugfix & Native Tuned)
// 生成时间：2026-10-06 10:45:00 (北京时间)
import { connect } from 'cloudflare:sockets';

const te = new TextEncoder();
const td = new TextDecoder();

const myID = '';

let PIP = 'ProxyIP.CMLiussss.net';  
let SUB = 'sub.xdu.qzz.io';  
let SUBAPI = 'https://subapi.cmliussss.net';  
let SUBINI = 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini'; 
const SBV12 = 'https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.12.x/sing-box.json'; 
const SBV11 = 'https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.11.x/sing-box.json'; 
const ST = "";  
const ECH = true;  
const ECH_DNS = 'https://dns.alidns.com/dns-query';  
const ECH_SNI = 'cloudflare-ech.com';  
const FP = ECH ? 'chrome' : 'randomized';
let TYPE = 'xhttp'; 

const RACE = 2; 

const padHeader = myID ? myID.slice(1, 7) : 'header';
const padKey = '_' + (myID ? myID.slice(25, 31) : 'padding');
const xhttpExtra = JSON.stringify({
    "extra": {
        "noGRPCHeader": true,
        "headers": {
            "Content-Type": "application/octet-stream"
        },
        "xPaddingBytes": "100-1000",
        "xPaddingObfsMode": true,
        "xPaddingMethod": "tokenish",
        "xPaddingPlacement": "queryInHeader",
        "xPaddingHeader": padHeader,
        "xPaddingKey": padKey
    }
});

const xhttpBase62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function genXhttpPadding(len) {
    let res = '';
    for (let i = 0; i < len; i++) {
        res += xhttpBase62[Math.floor(Math.random() * xhttpBase62.length)];
    }
    return res;
}

const v1 = PIP, v2 = myID; 
const CFG = { chunk: 131072, dnPack: 524288, dnMs: 10, upPack: 65536, upNMax: 256, maxED: 8192, hsMax: 16384, connMs: 4000, xhInit: 32768, xhNext: 8192 }; 
const c_map = new Map, c_run = new Map, c_max = 400, c_ttl = 18e4;
const p_map = new Map, p_ring = new Array(20); let p_idx = 0; 

let v3 = null, v4 = null;
const r_ip = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const r_ip6 = /^\[?([a-fA-F0-9:]+)\]?$/, v_b0 = new Uint8Array(0), dec = new TextDecoder, enc = new TextEncoder;
const v_v10 = new Uint8Array([33, 18, 164, 66]), v_z20 = new Uint8Array(20), v_ssinf = enc.encode("ss-subkey");
const hex = c => (c > 64 ? c + 9 : c) & 15, idB = new Uint8Array(16);
if (v2) {
    for (let i = 0, p = 0; i < 16; i++) {
        let c1 = v2.charCodeAt(p++); if (c1 === 45) c1 = v2.charCodeAt(p++);
        let c2 = v2.charCodeAt(p++); if (c2 === 45) c2 = v2.charCodeAt(p++);
        idB[i] = hex(c1) << 4 | hex(c2);
    }
}

// 修复点 1：精确匹配 VLESS 协议 UUID 的偏移量，从 c[1] 处起比较 16 字节
const matchID = c => { for (let i = 0; i < 16; i++) if (c[i + 1] !== idB[i]) return !1; return !0; };

const cat = (...xs) => { const r = new Uint8Array(xs.reduce((n, x) => n + x.length, 0)); let o = 0; for (const x of xs) r.set(x, o), o += x.length; return r; };
const f1 = s => enc.encode(s);
const f3 = (b, o) => b[o] << 8 | b[o + 1];
const f4 = (b, o) => (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
const f5 = n => crypto.getRandomValues(new Uint8Array(n));
const f6 = () => f3(f5(2), 0);
const f7 = () => f4(f5(4), 0);
const f8 = ip => new Uint8Array(ip.split(".").map(Number));
const f9 = (d, o, n) => { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += f3(d, i); n & 1 && (s += d[o + n - 1] << 8); while (s >> 16) s = (s & 65535) + (s >> 16); return ~s & 65535; };
const rotl = (v, a) => v >>> a | v << 32 - a;
const f_auth = t => { const d = f1(t), K = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298], H = [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428]; const ml = d.length, pl = Math.ceil((ml + 9) / 64) * 64, p = new Uint8Array(pl); p.set(d); p[ml] = 128; const v = new DataView(p.buffer); v.setUint32(pl - 4, ml * 8, !1); for (let c = 0; c < pl; c += 64) { const W = new Uint32Array(64); for (let i = 0; i < 16; i++) W[i] = v.getUint32(c + i * 4, !1); for (let i = 16; i < 64; i++) { const s0 = rotl(W[i - 15], 7) ^ rotl(W[i - 15], 18) ^ W[i - 15] >>> 3, s1 = rotl(W[i - 2], 17) ^ rotl(W[i - 2], 19) ^ W[i - 7] >>> 10; W[i] = W[i - 16] + s0 + W[i - 7] + s1 >>> 0; } let [a, b, x, y, e, f, g, h] = H; for (let i = 0; i < 64; i++) { const S1 = rotl(e, 6) ^ rotl(e, 11) ^ rotl(e, 25), ch = e & f ^ ~e & g, t1 = h + S1 + ch + K[i] + W[i] >>> 0, S0 = rotl(a, 2) ^ rotl(a, 13) ^ rotl(a, 22), maj = a & b ^ a & x ^ b & x, t2 = S0 + maj >>> 0; h = g; g = f; f = e; e = y + t1 >>> 0; y = x; x = b; b = a; a = t1 + t2 >>> 0; } H[0] = H[0] + a >>> 0; H[1] = H[1] + b >>> 0; H[2] = H[2] + x >>> 0; H[3] = H[3] + y >>> 0; H[4] = H[4] + e >>> 0; H[5] = H[5] + f >>> 0; H[6] = H[6] + g >>> 0; H[7] = H[7] + h >>> 0; } let r = ""; for (let i = 0; i < 7; i++) r += (H[i] >>> 24 & 255).toString(16).padStart(2, "0") + (H[i] >>> 16 & 255).toString(16).padStart(2, "0") + (H[i] >>> 8 & 255).toString(16).padStart(2, "0") + (H[i] & 255).toString(16).padStart(2, "0"); return r; };
const authHex = v2 ? f_auth(v2) : "", authBuf = new Uint8Array(56);
if (authHex) for (let i = 0; i < 56; i++) authBuf[i] = authHex.charCodeAt(i);
function f12(s) { try { s?.close?.(); } catch { } }
const rl = t => { try { t?.releaseLock(); } catch { } };
const I = t => t instanceof Uint8Array ? t : ArrayBuffer.isView(t) ? new Uint8Array(t.buffer, t.byteOffset, t.byteLength) : new Uint8Array(t);
const f_p16 = (d, o, v) => { d[o] = v >> 8 & 255; d[o + 1] = v & 255; };
const f_adr = (t, b) => 1 === t ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : 3 === t ? dec.decode(b) : `[${Array.from({ length: 8 }, (_, i) => (b[2 * i] << 8 | b[2 * i + 1]).toString(16)).join(":")}]`;
function f13(s) { if (!s) return null; const e = (e, n, r) => { try { const s = t.startsWith(e + "s://"), a = /!ip(?:$|&)/i.test(t), i = new URL(t.replace(/!ip(?:$|&)/i, "")); return { type: s ? e + "s" : e, host: i.hostname, port: parseInt(i.port) || (s ? r : n), username: i.username ? decodeURIComponent(i.username) : "", password: i.password ? decodeURIComponent(i.password) : "", isc: s && (a || r_ip.test(i.hostname) || r_ip6.test(i.hostname)) } } catch { return null; } }; if ((s = s.trim()).startsWith("turn://") || s.startsWith("turns://")) return e("turn", 3478, 5349); if (s.startsWith("sstp://")) { try { const e = new URL(s); return { type: "sstp", host: e.hostname, port: parseInt(e.port) || 443, username: e.username ? decodeURIComponent(e.username) : "vpn", password: e.password ? decodeURIComponent(e.password) : "vpn" } } catch { return null; } } if (s.startsWith("socks://") || s.startsWith("socks5://")) { try { const e = new URL(s.replace(/^socks:\/\//, "socks5://")); return { type: "socks5", host: e.hostname, port: parseInt(e.port) || 1080, username: e.username ? decodeURIComponent(e.username) : "", password: e.password ? decodeURIComponent(e.password) : "" } } catch { return null; } } if (s.startsWith("http://") || s.startsWith("https://")) { try { const h = s.startsWith("https://"), hasTag = /!ip(?:$|&)/i.test(s), u = new URL(s.replace(/!ip(?:$|&)/i, "")), c = hasTag || r_ip.test(u.hostname) || r_ip6.test(u.hostname); return { type: h ? "https" : "http", host: u.hostname, port: parseInt(u.port) || (h ? 443 : 80), username: u.username ? decodeURIComponent(u.username) : "", password: u.password ? decodeURIComponent(u.password) : "", isc: c }; } catch { return null; } } const m = s.match(/^\[([^\]]+)\](?::(\d+))?$/); if (m) { const p = parseInt(m[2], 10); return { type: "direct", host: m[1], port: !isNaN(p) && p > 0 ? p : 443 } } const i = s.lastIndexOf(":"); if (i > 0) { const h = s.substring(0, i), p = parseInt(s.substring(i + 1), 10); if (!isNaN(p) && p > 0 && p <= 65535) return { type: "direct", host: h, port: p } } return { type: "direct", host: s, port: 443 } }
async function f14(d, t) { const k = d + "_" + t, n = Date.now(), c = c_map.get(k); if (c) { if (n - c.time < c_ttl) return c.data; c_map.delete(k); } const old = c_run.get(k); if (old) return old; const j = (async () => { try { const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(d)}&type=${t}`, { headers: { Accept: "application/dns-json" } }); if (!r.ok) return []; const a = (await r.json()).Answer || []; if (a.length) { if (c_map.size >= c_max) c_map.delete(c_map.keys().next().value); c_map.set(k, { data: a, time: Date.now() }); } return a; } catch { return []; } })(); c_run.set(k, j); try { return await j; } finally { c_run.delete(k); } }
const f_evp = async (pw, kl) => { let k = v_b0, pv = v_b0; const p = enc.encode(pw); while (k.length < kl) { const d = new Uint8Array(pv.length + p.length); d.set(pv), d.set(p, pv.length), pv = new Uint8Array(await crypto.subtle.digest("MD5", d)); const nk = new Uint8Array(k.length + pv.length); nk.set(k), nk.set(pv, k.length), k = nk; } return k.slice(0, kl); };
const f_hkdf = async (ikm, salt, info, len) => { const k1 = await crypto.subtle.importKey("raw", salt.length ? salt : v_z20, { name: "HMAC", hash: "SHA-1" }, !1, ["sign"]), prk = new Uint8Array(await crypto.subtle.sign("HMAC", k1, ikm)); const k2 = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-1" }, !1, ["sign"]), okm = new Uint8Array(Math.ceil(len / 20) * 20); let pv = v_b0; for (let i = 0; i < Math.ceil(len / 20); i++) { pv = new Uint8Array(await crypto.subtle.sign("HMAC", k2, cat(pv, info, new Uint8Array([i + 1])))), okm.set(pv, i * 20); } return okm.slice(0, len); };
let v_mk = null;
const f_gmk = async () => v_mk ??= await f_evp(v2, 16);
class AEAD { 
    constructor(key) { this.key = key; this.nonce = new Uint8Array(12); this.ck = null; } 
    async init() { this.ck = await crypto.subtle.importKey("raw", this.key, { name: "AES-GCM" }, !1, ["encrypt", "decrypt"]); } 
    inc() { for (let i = 0; i < this.nonce.length; i++) { this.nonce[i]++; if (this.nonce[i]) break; } } 
    ivs() { const t = this.nonce.slice(); this.inc(); return t; }
    async encIv(d, iv) { return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv, tagLength: 128 }, this.ck, d)); }
    async dec(d) { try { const p = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.nonce, tagLength: 128 }, this.ck, d)); return this.inc(), p; } catch { return null; } } 
}
class SS { 
    constructor() { this.dec = null; this.enc = null; this.buf = v_b0; this.o = 0; this.e = 0; this.plen = -1; this.need = 0; } 
    async decData(t, cb) { 
        const n = t?.byteLength || 0; 
        if (n) { 
            if (this.buf.length) { 
                if (this.buf.length - this.e < n) {
                    if (this.o > 0 && this.buf.length - this.e + this.o >= n) {
                        this.buf.copyWithin(0, this.o, this.e); this.e -= this.o; this.o = 0; 
                    } else {
                        const nt = new Uint8Array(this.e - this.o + n); nt.set(this.buf.subarray(this.o, this.e)); this.buf = nt; this.e -= this.o; this.o = 0; 
                    }
                }
            } else { 
                this.buf = new Uint8Array(n); this.o = 0; this.e = 0; 
            } 
            this.buf.set(t.length === n ? t : t.subarray(0, n), this.e); this.e += n; 
        } 
        if (this.e - this.o > 262144) return "buf"; 
        if (!this.dec) { 
            if (this.e - this.o < 16) return; 
            const salt = this.buf.subarray(this.o, this.o + 16); this.o += 16; 
            this.dec = new AEAD(await f_hkdf(await f_gmk(), salt, v_ssinf, 16)); await this.dec.init(); 
        } 
        for (; ;) { 
            if (this.plen < 0) { 
                if (this.e - this.o < 18) break; 
                const lp = await this.dec.dec(this.buf.subarray(this.o, this.o + 18)); 
                if (!lp) return "len"; 
                this.plen = f3(lp, 0); this.need = this.plen + 16; this.o += 18; 
            } 
            if (this.e - this.o < this.need) break; 
            const pp = await this.dec.dec(this.buf.subarray(this.o, this.o + this.need)); 
            if (!pp) return "pay"; 
            cb(pp); 
            this.o += this.need; this.plen = -1; 
        } 
    } 
    async encData(t) { 
        let e = v_b0; 
        if (!this.enc) { 
            const salt = crypto.getRandomValues(new Uint8Array(16)); 
            this.enc = new AEAD(await f_hkdf(await f_gmk(), salt, v_ssinf, 16)); await this.enc.init(); e = salt; 
        } 
        if (!t || 0 === t.length) return e; 
        t = I(t);
        const n = new Uint8Array(e.length + t.length + 34 * Math.ceil(t.length / 16383)); 
        if (e.length) n.set(e); 
        let r = e.length; 
        for (let i = 0; i < t.length; i += 262128) { 
            const s = []; 
            for (let j = i; j < Math.min(i + 262128, t.length); j += 16383) { 
                const ck = t.subarray(j, Math.min(j + 16383, t.length)); 
                const lb = new Uint8Array(2); f_p16(lb, 0, ck.length); 
                const iv1 = this.enc.ivs(), iv2 = this.enc.ivs(); 
                s.push((async () => ({ l: ck.length, L: await this.enc.encIv(lb, iv1), M: await this.enc.encIv(ck, iv2) }))()); 
            } 
            for (const { l, L, M } of await Promise.all(s)) { 
                n.set(L, r); r += 18; n.set(M, r); r += l + 16; 
            } 
        } 
        return n.subarray(0, r); 
    } 
}
const millWs = async (ws, readable, sendFn, onClose) => { 
    let r, ib = !1; 
    try { r = readable.getReader({ mode: "byob" }); ib = !0; } catch { r = readable.getReader(); ib = !1; } 
    const h = CFG.dnPack, l = CFG.chunk; 
    let u = new Uint8Array(h), w = new ArrayBuffer(l), f = 0, tm = 0, p = !0; 
    const flush = () => { 
        if (tm) { clearTimeout(tm); tm = 0; } 
        if (!f) return; 
        const t = f; f = 0; sendFn(u.subarray(0, t)); 
    }; 
    const waitBP = async () => { 
        for (; ws.readyState === WebSocket.OPEN && ws.bufferedAmount > 262144;) { 
            await (globalThis.scheduler?.wait?.(ws.bufferedAmount > 524288 ? 8 : 2) ?? new Promise(res => setTimeout(res, 2))); 
            if (ws.bufferedAmount <= 65536) break; 
        } 
    }; 
    try { 
        for (; ws.readyState === WebSocket.OPEN;) { 
            await waitBP(); 
            const readSize = Math.min(l, h - f); 
            const { done, value } = await (ib ? r.read(new Uint8Array(w, 0, readSize)) : r.read()); 
            if (done) break; 
            const vLen = value?.byteLength || 0; 
            if (vLen) { 
                if (ib) { w = value.buffer; u.set(value, f); f += vLen; } 
                else if (f + vLen > h) { flush(); vLen >= h ? sendFn(value) : (u.set(value, 0), f = vLen); } 
                else { u.set(value, f); f += vLen; } 
            } 
            const isFirst = p && f < l; p = !1; 
            if (f + l > h || isFirst) flush(); 
            else tm ||= setTimeout(flush, CFG.dnMs); 
        } 
    } catch { } finally { 
        try { flush(); } catch { } 
        rl(r); onClose(); 
    } 
};
const mkUpBatcher = (w, errCb, max) => {
    const buf = new Uint8Array(max);
    let off = 0, tm = 0, bad = !1;
    const flush = () => {
        if (tm) { clearTimeout(tm); tm = 0; }
        if (!off || bad) return;
        const i = off; off = 0;
        try { w.write(buf.subarray(0, i)).catch(() => { bad = !0; errCb(); }); } 
        catch { bad = !0; errCb(); }
    };
    return d => {
        if (bad || !d?.byteLength) return;
        const len = d.byteLength;
        if (len >= max) {
            flush();
            try { w.write(d).catch(errCb); } catch { errCb(); }
        } else {
            if (off + len > max) flush();
            buf.set(d, off); off += len;
            if (off === max) flush();
            else tm ||= setTimeout(flush, 2);
        }
    };
};
const f_cd_single = (h, p, m) => new Promise((ok, no) => {
    h = String(h).trim(), h[0] == "[" && h[h.length - 1] == "]" && (h = h.slice(1, -1)); 
    const s = connect({ hostname: h, port: p }, { allowHalfOpen: true }); 
    let e = 0; 
    const t = setTimeout(() => { if (e) return; e = 1; try { s.close(); } catch { } no(0); }, m); 
    s.opened.then(() => { if (e) { try { s.close(); } catch { } return; } e = 1; clearTimeout(t); ok(s); }, x => { if (e) return; e = 1; clearTimeout(t); try { s.close(); } catch { } no(x); }); 
});
const f_cd = async (h, p, m = CFG.connMs) => {
    if (RACE < 2) return f_cd_single(h, p, m);
    let ok = 0;
    const c = [];
    for (let i = 0; i < RACE; i++) {
        c.push(f_cd_single(h, p, m).then(sock => {
            if (ok) {
                try { sock.close(); } catch {}
                return Promise.reject(0);
            }
            return ok = sock;
        }));
    }
    try { return await Promise.any(c); } catch { throw 0; }
};
async function f26_pool(h, p, pool) {
    try { const sock = await f_cd(h, p, CFG.connMs); return sock; } catch { }
    const via = async (q) => "socks5" === q.type ? f20(q, h, p) : ["http", "https"].includes(q.type) ? f21(q, h, p) : "sstp" === q.type ? f22(q, h, p) : ["turn", "turns"].includes(q.type) ? f38(q, h, p) : f_cd(q.host, q.port, CFG.connMs);
    for (const cf of pool) {
        try {
            let cv = cf.trim(), q = null;
            if (cv.toLowerCase().endsWith("!txt")) {
                const tg = cv.slice(0, -4).trim();
                let pv = null;
                try {
                    const tr = await f14(tg, "TXT"), td = tr.filter(x => 16 === x.type).map(x => x.data);
                    if (td.length) pv = td.map(x => x.replace(/"/g, "")).join(",").replace(/[\r\n\s]+/g, ",").split(",").map(x => x.trim()).filter(Boolean);
                } catch { }
                if (pv && pv.length) q = f13(pv[Math.floor(Math.random() * pv.length)]);
            }
            if (!q) q = f13(cv);
            if (q?.type === "direct" && cv) {
                try {
                    const a = await f16(cv, h, myID);
                    if (a?.length) [q.host, q.port] = a[Math.floor(Math.random() * a.length)];
                } catch { }
            }
            if (!q) q = { type: "direct", host: cv, port: 443 };
            const sock = await via(q);
            if (sock) return sock;
        } catch (e) { }
    }
    return null;
}
const dn_res = async t => { const n = I(t); for (let e = 0; e < 2; e++) { let r; try { r = await f_cd("1.1.1.1", 53); const s = r.writable.getWriter(), i = r.readable.getReader(); let o = v_b0; const c = async t => { for (; o.byteLength < t;) { const { done: n, value: e } = await i.read(); if (n) throw 0; const r = I(e); o = o.byteLength ? cat(o, r) : r; } const e = o.subarray(0, t); o = o.byteLength > t ? o.subarray(t) : new Uint8Array(0); return e; }; const l = n.byteLength >= 2 && f3(n, 0) === n.byteLength - 2; await s.write(l ? n : cat(new Uint8Array([n.byteLength >> 8, 255 & n.byteLength]), n)); const h = await c(2), u = await c(f3(h, 0)); return l ? cat(h, u) : u; } catch { if (1 === e) return null; } finally { f12(r); } } };
const f27_dns = async (uc, ws) => { try { const n = await dn_res(uc); if (n?.byteLength && ws.readyState === WebSocket.OPEN) ws.send(n); } catch { } };
const pt_dns = (outWriter, onError) => {
    let n = v_b0, pChain = Promise.resolve(), fin = !1;
    return {
        write: d => (pChain = pChain.then(() => (async dItem => {
            if (fin || !dItem?.byteLength) return;
            const r = I(dItem); n = n.byteLength ? cat(n, r) : r; let s = 0;
            for (; n.byteLength - s >= 2;) {
                const e = s + 2 + (n[s] << 8 | n[s + 1]);
                if (n.byteLength < e) break;
                const res = await dn_res(n.slice(s, e));
                if (res) await outWriter.write(res);
                s = e;
            }
            n = s < n.byteLength ? n.slice(s) : v_b0;
        })(d)), pChain.catch(onError), pChain),
        async finish() { if (await pChain, fin = !0, n.byteLength) throw 0; }
    };
};
const dt_read = async (st, len) => {
    if (st.byob) {
        const n = new ArrayBuffer(len), r = await st.reader.read(new Uint8Array(n));
        return { done: r.done, value: r.value ? I(r.value) : v_b0 };
    }
    const n = await st.reader.read();
    return { done: n.done, value: n.value ? I(n.value) : v_b0 };
};
const f_padr = (b, o, t) => { const l = 3 === t ? b[o++] : 1 === t ? 4 : 4 === t ? 16 : null; return null === l ? null : o + l > b.length ? null : { b: b.subarray(o, o + l), o: o + l }; };
const f_vmore = c => { if (c.byteLength < 24 || !matchID(c)) return null; let o = 19 + c[17]; if (o + 3 > c.byteLength) return null; let t = c[o + 2]; const p = c[o] << 8 | c[o + 1]; 1 !== t && (t += 1); const a = f_padr(c, o + 3, t); return a ? { t: t, b: a.b, p: p, u: 2 === c[18 + c[17]], v: c[0], o: a.o } : null; };
const f_trajon = c => { if (c.byteLength < 60) return null; for (let i = 0; i < 56; i++) if (c[i] !== authBuf[i]) return null; if (c[56] !== 13 || c[57] !== 10 || c[58] !== 1) return null; const t = c[59]; let o = 60, l = 1 === t ? 4 : 3 === t ? c[o++] : 4 === t ? 16 : null; if (null === l) return null; const n = o + l; if (n + 4 > c.byteLength || c[n + 2] !== 13 || c[n + 3] !== 10) return null; return { t: t, b: c.subarray(o, n), p: c[n] << 8 | c[n + 1], o: n + 4 }; };
const f43 = d => { if (d.length < 1) return null; const t = d[0]; let h, p, o; if (1 === t && d.length >= 7) { h = `${d[1]}.${d[2]}.${d[3]}.${d[4]}`; p = f3(d, 5); o = 7; } else if (3 === t && d.length >= 4 + d[1]) { h = dec.decode(d.subarray(2, 2 + d[1])); p = f3(d, 2 + d[1]); o = 4 + d[1]; } else if (4 === t && d.length >= 19) { h = `[${Array.from({ length: 8 }, (_, i) => (d[1 + 2 * i] << 8 | d[2 + 2 * i]).toString(16)).join(":")}]`; p = f3(d, 17); o = 19; } else return null; return { h: h, p: p, o: o }; };
const parseSession = (t, type) => {
    let n;
    if (1 === type) {
        n = f_vmore(t);
        return n ? { type: type, host: f_adr(n.t, n.b), port: n.p, payload: t.subarray(n.o), responsePrefix: new Uint8Array([n.v, 0]), udpDns: n.u } : null;
    } else if (2 === type) {
        n = f_trajon(t);
        return n ? { type: type, host: f_adr(n.t, n.b), port: n.p, payload: t.subarray(n.o), responsePrefix: v_b0, udpDns: !1 } : null;
    } else if (3 === type) {
        n = f43(t);
        return n ? { type: type, host: n.h, port: n.p, payload: t.subarray(n.o), responsePrefix: v_b0, udpDns: !1 } : null;
    }
    return null;
};
const sniffSession = t => {
    const e = t.byteLength;
    if (e > 0) {
        const n = Math.min(Math.max(0, e - 1), 16);
        let ok = !0;
        for (let i = 0; i < n; i++) if (t[i + 1] !== idB[i]) { ok = !1; break; }
        if (ok) {
            if (e < 17) return { more: 1 };
            if (matchID(t)) {
                const sess = parseSession(t, 1);
                return sess ? { type: 1, session: sess } : e < CFG.hsMax ? { more: 1 } : { error: 1 };
            }
        }
    }
    if (e > 0) {
        const n = Math.min(e, 56);
        let ok = !0;
        for (let i = 0; i < n; i++) if (t[i] !== authBuf[i]) { ok = !1; break; }
        if (ok) {
            if (e < 60) return { more: 1 };
            const sess = parseSession(t, 2);
            return sess ? { type: 2, session: sess } : e < CFG.hsMax ? { more: 1 } : { error: 1 };
        }
    }
    const sess = parseSession(t, 3);
    if (sess) return { type: 3, session: sess };
    return e < 17 ? { more: 1 } : { error: 1 };
};
function parsePathConfig(url) {
    const cacheKey = url.pathname + (url.search || "");
    const cached = p_map.get(cacheKey);
    if (cached) return cached;
    let path = url.pathname.slice(1);
    try { path = decodeURIComponent(path); } catch { }
    const q = path.indexOf("?");
    const pathPart = q < 0 ? path : path.slice(0, q);
    const i = pathPart.indexOf("=");
    let proxy = null;
    if (i > 0 && i < pathPart.length - 1) {
        const key = pathPart.slice(0, i).trim();
        const value = pathPart.slice(i + 1).trim();
        if (key && value) { proxy = value; }
    }
    const res = { proxy };
    if (p_ring[p_idx]) p_map.delete(p_ring[p_idx]);
    p_ring[p_idx] = cacheKey;
    p_map.set(cacheKey, res);
    p_idx = (p_idx + 1) % 20;
    return res;
}
async function handleXHTTP(req, proxyPool) {
    if (!req.body) return new Response(null, { status: 400 });
    
    // 修复点 2：在 Native 实现中直接安全的调用无参构造函数，避免参数抛出引发 XHTTP 管道断裂
    const trans = typeof IdentityTransformStream === "function" 
        ? new IdentityTransformStream() 
        : new TransformStream(void 0, { highWaterMark: 1048576 });

    const stReader = (() => {
        try { return { reader: req.body.getReader({ mode: "byob" }), byob: !0 }; } 
        catch { return { reader: req.body.getReader(), byob: !1 }; }
    })();

    const rd = stReader.reader, wr = trans.writable.getWriter();
    let upstream = null, rdDone = !1, wrDone = !1, isAbort = !1, ctlUp = null, ctlDn = null;

    const releaseRd = () => { 
        if (!rdDone) { 
            rdDone = !0; 
            try { rd.releaseLock(); } catch { } 
        } 
    };

    const abortSession = err => {
        if (!isAbort) {
            isAbort = !0;
            try { ctlUp?.abort(err); } catch { }
            try { ctlDn?.abort(err); } catch { }
            releaseRd();
            try { upstream?.close?.(); } catch { }
            f12(upstream);
            if (!wrDone) {
                wrDone = !0;
                try { wr.abort(err).catch(() => { }); } catch { }
                rl(wr);
            }
        }
    };

    (async () => {
        let sBuf = new Uint8Array(0), session = null;
        let hsTimeout = setTimeout(() => { 
            try { rd.cancel(); } catch { } 
            abortSession(); 
        }, 15000);

        while (!session) {
            const probe = sniffSession(sBuf);
            if (probe.session) { 
                session = probe.session; 
                clearTimeout(hsTimeout);
                break; 
            }
            if (probe.error || sBuf.byteLength >= CFG.hsMax) {
                clearTimeout(hsTimeout);
                throw 0;
            }
            const rem = CFG.hsMax - sBuf.byteLength, nextLen = Math.min(0 === sBuf.byteLength ? CFG.xhInit : CFG.xhNext, rem);
            if (nextLen <= 0) { clearTimeout(hsTimeout); throw 0; }
            const { done: dn, value: vl } = await dt_read(stReader, nextLen);
            if (dn) { clearTimeout(hsTimeout); throw 0; }
            if (vl.byteLength) sBuf = sBuf.byteLength ? cat(sBuf, vl) : new Uint8Array(vl);
        }

        if (session.responsePrefix.byteLength) await wr.write(session.responsePrefix);

        if (session.udpDns) {
            if (53 !== session.port) throw 0;
            const dnsHandler = pt_dns(wr, abortSession);
            if (session.payload.byteLength) await dnsHandler.write(session.payload);
            while (true) {
                const { done: dn, value: vl } = await dt_read(stReader, CFG.chunk);
                if (dn) break;
                if (vl.byteLength) await dnsHandler.write(vl);
            }
            await dnsHandler.finish();
            releaseRd();
            if (!wrDone) {
                wrDone = !0;
                try { await wr.close(); } finally { rl(wr); }
            }
            return void (isAbort = !0);
        }

        upstream = await f26_pool(session.host, session.port, proxyPool);
        if (!upstream) throw 0;

        if (!wrDone) {
            wrDone = !0;
            rl(wr);
        }

        ctlUp = new AbortController();
        ctlDn = new AbortController();

        const pDn = upstream.readable.pipeTo(trans.writable, { signal: ctlDn.signal });

        if (session.payload.byteLength) {
            const uWr = upstream.writable.getWriter();
            try { await uWr.write(session.payload); } finally { uWr.releaseLock(); }
        }

        releaseRd();
        const pUp = req.body.pipeTo(upstream.writable, { signal: ctlUp.signal });

        pUp.catch(e => { isAbort || abortSession(e); });
        pDn.then(() => {
            if (!isAbort) {
                isAbort = !0;
                try { ctlUp.abort(); } catch { }
                try { upstream?.close?.(); } catch { }
            }
        }, abortSession);
    })().catch(abortSession);

    const respHeaders = new Headers({
        'Content-Type': 'application/octet-stream',
        'grpc-status': '0',
        'X-Accel-Buffering': 'no',
        'Cache-Control': 'no-store, no-transform, private',
        'X-Content-Type-Options': 'nosniff'
    });

    try {
        const padUrl = new URL('https://x.invalid/');
        padUrl.searchParams.set(padKey, genXhttpPadding(100 + Math.floor(Math.random() * 901)));
        respHeaders.set(padHeader, padUrl.toString());
    } catch (e) { }

    return new Response(trans.readable, { status: 200, headers: respHeaders });
}
async function handleWS(req, proxyPool) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    server.binaryType = "arraybuffer";
    let rw = { socket: null, writer: null, bw: null };
    let isDNS = !1, closed = !1, u = !1, pT = 0, pendingPkt = 0;
    let dQueue = [];
    let flushPromise = Promise.resolve(), ssPromise = Promise.resolve();
    const ssEngine = new SS();
    let hsTimeout = setTimeout(() => { if (!pT) wither(1000); }, 15000);

    const wither = (code = 1000) => {
        if (!closed) {
            closed = !0; dQueue = [];
            if (hsTimeout) { clearTimeout(hsTimeout); hsTimeout = 0; }
            try { rw.writer?.close(); } catch { }
            rl(rw.writer); f12(rw.socket);
            try { server.close(code, ""); } catch { }
        }
    };

    const pushWsPkt = (data) => {
        if (!rw.bw) {
            if (server.readyState === WebSocket.OPEN) server.send(data);
            return;
        }
        const copy = data.slice();
        flushPromise = flushPromise.then(async () => {
            if (!closed) {
                try {
                    const enc = await ssEngine.encData(copy);
                    if (server.readyState === WebSocket.OPEN) server.send(enc);
                } catch { }
            }
        }).catch(() => {});
    };

    const flushClose = () => { flushPromise.then(() => { try { server.close(1000, ""); } catch { } }); };

    const processQueue = async () => {
        if (!u && !closed) {
            u = !0;
            try {
                for (; !closed ;) {
                    if (isDNS) {
                        let t = dQueue.shift();
                        if (!t) break;
                        if (t.byteLength < CFG.upPack && dQueue.length) {
                            const e = [t]; let n = t.byteLength;
                            while (dQueue.length && n + dQueue[0].byteLength <= CFG.upPack) {
                                const nxt = dQueue.shift(); e.push(nxt); n += nxt.byteLength;
                            }
                            if (e.length > 1) t = cat(...e);
                        }
                        await f27_dns(t, server);
                        continue;
                    }
                    if (!rw.socket) {
                        const t = dQueue.shift();
                        if (!t) break;
                        const sess = parseSession(t, pT);
                        if (!sess) throw 0;
                        if (sess.responsePrefix.byteLength && server.readyState === WebSocket.OPEN) server.send(sess.responsePrefix);
                        if (sess.udpDns) {
                            if (53 !== sess.port) throw 0;
                            isDNS = !0;
                            await f27_dns(sess.payload, server);
                            continue;
                        }
                        const sock = await f26_pool(sess.host, sess.port, proxyPool);
                        if (!sock) throw 0;
                        rw.socket = sock; rw.writer = sock.writable.getWriter();
                        rw.bw = mkUpBatcher(rw.writer, () => wither(1011), CFG.upPack);
                        
                        millWs(server, sock.readable, pushWsPkt, flushClose).catch(() => {});
                        if (sess.payload.byteLength) rw.bw(sess.payload);
                        continue;
                    }
                    const t = dQueue.shift();
                    if (!t) break;
                    rw.bw(t);
                }
            } catch { wither(1011); } finally { u = !1; if (!closed && dQueue.length) processQueue(); }
        }
    };

    let initBuffer = null;
    const onMessage = data => {
        if (closed) return;
        let chunk = I(data);
        if (!chunk.byteLength) return;

        if (!pT) {
            initBuffer = initBuffer?.byteLength ? cat(initBuffer, chunk) : chunk;
            const probe = sniffSession(initBuffer);
            if (probe.session) {
                pT = probe.type; chunk = initBuffer; initBuffer = null;
                if (hsTimeout) { clearTimeout(hsTimeout); hsTimeout = 0; }
            } else if (probe.error || initBuffer.byteLength >= CFG.hsMax) {
                wither(1011); return;
            } else {
                return;
            }
        }

        if (1 === pT || 2 === pT) {
            dQueue.push(chunk); processQueue();
        } else {
            if (++pendingPkt > CFG.upNMax) return wither(1011);
            ssPromise = ssPromise.then(async () => {
                try {
                    if (!closed) {
                        const err = await ssEngine.decData(chunk, p => { if (p.byteLength) dQueue.push(p); });
                        if (err) return wither(1011);
                        processQueue();
                    }
                } catch { wither(1011); } finally { pendingPkt--; }
            }).catch(() => { });
        }
    };

    const early = req.headers.get("sec-websocket-protocol");
    if (early) {
        try {
            let b64 = early.replace(/-/g, "+").replace(/_/g, "/").trim();
            b64 += "====".slice(0, (4 - b64.length % 4) % 4);
            const raw = typeof Uint8Array["fromBase64"] === "function" ? Uint8Array["fromBase64"](b64) : Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            if (raw.byteLength <= CFG.maxED) onMessage(raw);
        } catch { }
    }
    server.addEventListener("message", e => onMessage(e.data));
    server.addEventListener("close", () => wither(1000));
    server.addEventListener("error", () => wither(1011));
    return new Response(null, { status: 101, webSocket: client, headers: { "Sec-WebSocket-Extensions": "" } });
}
export default {
    async fetch(req, env) {
        const isWS = req.headers.get('Upgrade')?.toLowerCase() === 'websocket';
        const ct = (req.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
        const isXHTTP = req.method === 'POST' && (ct.startsWith('application/grpc') || ct === 'application/octet-stream');
        const u = new URL(req.url);
        if (!isWS && !isXHTTP && !req.body) {
            const UA = (req.headers.get("User-Agent") || "").toLowerCase();
            const isSub = (myID && u.pathname === `/${myID}`) || u.pathname === `/sub`;
            if (isSub) {
                if (u.pathname === `/sub` && u.searchParams.get('uuid') !== myID) return new Response("Invalid", { status: 403 });
                return await hSub(req, env, u, UA, u.hostname);
            }
            return new Response("OK", { status: 200 });
        }
        let cfg = parsePathConfig(u);
        let pParamInput = cfg.proxy || u.searchParams.get("proxyip");
        let proxyIPPool = [];
        if (pParamInput) proxyIPPool.push(pParamInput);
        if (PIP) proxyIPPool.push(PIP);
        const dynamicProxy = req.cf?.colo ? `${req.cf.colo}.PrOxYip.CmLiuSsSs.nEt:443` : null;
        if (dynamicProxy) proxyIPPool.push(dynamicProxy);
        if (isWS) return await handleWS(req, proxyIPPool);
        if (isXHTTP) return await handleXHTTP(req, proxyIPPool);
        return new Response(null, { status: 204 });
    }
};
async function _getECH(h) { try { const ps = h.split('.'), bs = []; for (const l of ps) { const e = new TextEncoder().encode(l); bs.push(e.length, ...e); } bs.push(0); const dn = new Uint8Array(bs); const pk = new Uint8Array(12 + dn.length + 4); const dv = new DataView(pk.buffer); dv.setUint16(0, Math.random() * 65535 | 0); dv.setUint16(2, 256); dv.setUint16(4, 1); pk.set(dn, 12); dv.setUint16(12 + dn.length, 65); dv.setUint16(14 + dn.length, 1); const rp = await fetch(ECH_DNS, { method: 'POST', headers: { 'Content-Type': 'application/' + 'dns' + '-message', Accept: 'application/' + 'dns' + '-message' }, body: pk }); if (!rp.ok) return null; const bf = new Uint8Array(await rp.arrayBuffer()); const rv = new DataView(bf.buffer); const qc = rv.getUint16(4), ac = rv.getUint16(6); const sn = p => { let c = p; while (c < bf.length) { const n = bf[c]; if (!n) return c + 1; if ((n & 0xC0) === 0xC0) return c + 2; c += n + 1; } return c + 1; }; let o = 12; for (let i = 0; i < qc; i++)o = sn(o) + 4; for (let i = 0; i < ac && o < bf.length; i++) { o = sn(o); const tp = rv.getUint16(o); o += 2; o += 6; const rl = rv.getUint16(o); o += 2; if (tp === 65) { const rd = bf.slice(o, o + rl); let p = 2; while (p < rd.length) { const n = rd[p]; if (!n) { p++; break; } p += n + 1; } while (p + 4 <= rd.length) { const k = (rd[p] << 8) | rd[p + 1], ln = (rd[p + 2] << 8) | rd[p + 3]; p += 4; if (k === 5) return '-----BEGIN ECH CONFIGS-----\n' + btoa(String.fromCharCode(...rd.slice(p, p + ln))) + '\n-----END ECH CONFIGS-----'; p += ln; } } o += rl; } return null; } catch { return null; } }
const fixVless = (link, h, tp, FP, ECH, ECH_SNI, ECH_DNS) => {
    if (!link.trim().toLowerCase().startsWith('vless://')) return link;
    try {
        let [base, hash] = link.split('#');
        const setParam = (url, key, value) => {
            const regex = new RegExp(`([?&])${key}=[^&]*`, 'i');
            if (regex.test(url)) return url.replace(regex, `$1${key}=${value}`);
            else return url + (url.includes('?') ? '&' : '?') + `${key}=${value}`;
        };
        base = setParam(base, 'sni', h);
        base = setParam(base, 'host', h);
        base = setParam(base, 'path', encodeURIComponent(tp));
        base = setParam(base, 'fp', FP);
        base = setParam(base, 'alpn', encodeURIComponent('h3,h2,http/1.1'));
        if (TYPE === 'xhttp') {
            base = setParam(base, 'type', 'xhttp');
            base = setParam(base, 'mode', 'stream-one');
            base = setParam(base, 'extra', encodeURIComponent(xhttpExtra));
        } else {
            base = setParam(base, 'type', 'ws');
            base = base.replace(/([?&])mode=[^&]*/gi, '$1').replace(/([?&])extra=[^&]*/gi, '$1');
        }
        if (ECH) {
            base = setParam(base, 'ech', encodeURIComponent(ECH_SNI + '+' + ECH_DNS));
        } else {
            base = base.replace(/([?&])ech=[^&]*/gi, '$1');
        }
        base = base.replace(/&&+/g, '&').replace(/\?&/g, '?').replace(/[?&]$/, '');
        return `${base}#${hash || 'Worker'}`;
    } catch { return link; }
};
function pSB(x, echCfg, h, FP, tp) {
    try {
        const j = JSON.parse(x), o = j['outbounds'] || [];
        for (const b of o) {
            if (b.type !== 'vless' && b.type !== 'vmess') continue;
            if (b.uuid !== myID && b.server_name !== myID) continue;
            if (!b.tls) b.tls = {};
            b.tls.server_name = h; 
            b.tls.utls = { enabled: true, fingerprint: FP };
            b.tls.alpn = ['h3', 'h2', 'http/1.1'];
            if (echCfg) { b.tls.ech = { enabled: true, config: [echCfg] }; }
            if (TYPE === 'xhttp') {
                if (!b.transport) b.transport = {};
                b.transport.type = 'xhttp';
                b.transport.host = h;
                b.transport.path = tp;
                b.transport.extra = JSON.parse(xhttpExtra);
            } else if (b.transport && (b.transport.type === 'ws' || b.transport.type === 'http')) {
                if (!b.transport.headers) b.transport.headers = {};
                b.transport.headers.Host = h;
                b.transport.path = tp;
            }
        }
        return JSON.stringify(j);
    } catch { return x; }
}
function pCL(x, h, FP, tp) {
    try {
        if (!ECH && TYPE !== 'xhttp') return x; 
        let y = x;
        if (!/^dns:\s*(?:\n|$)/m.test(y)) y = 'dns:\n  enable: true\n  default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n  use-hosts: true\n  nameserver:\n    - https://sm2.doh.pub/dns-query\n    - https://dns.alidns.com/dns-query\n  fallback:\n    - 8.8.4.4\n    - 208.67.220.220\n  fallback-filter:\n    geoip: true\n    geoip-code: CN\n    ipcidr:\n      - 240.0.0.0/4\n      - 0.0.0.0/32\n    domain:\n      - \'+.google.com\'\n      - \'+.youtube.com\'\n' + y;
        const ls = y.split('\n'); let di = -1, iD = false;
        for (let i = 0; i < ls.length; i++) { if (/^dns:\s*$/.test(ls[i])) { iD = true; continue; } if (iD && /^[a-zA-Z]/.test(ls[i])) { di = i; break; } }
        const ne = '    "' + h + '":\n      - ' + ECH_DNS + '\n    "' + ECH_SNI + '":\n      - ' + ECH_DNS;
        if (ECH) {
            if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(y)) { y = y.replace(/^(\s{2}nameserver-policy:\s*\n)/m, '$1' + ne + '\n'); }
            else if (di > 0) { ls.splice(di, 0, '  nameserver-policy:', ne); y = ls.join('\n'); }
        }
        const L = y.split('\n'), R = []; let i = 0;
        while (i < L.length) {
            const l = L[i], tl = l.trim();
            if (tl.startsWith('- {') && tl.includes('uuid:')) {
                let fn = l;
                const um = fn.match(/uuid:\s*([^,}\n]+)/);
                if (um && um[1].trim() === myID.trim()) {
                    fn = fn.replace(/client-fingerprint:\s*[^,}\s]+/, 'client-fingerprint: ' + FP);
                    if (ECH) fn = fn.replace(/\}(\s*)$/, `, ech-opts: {enable: true, query-server-name: ${ECH_SNI}}}$1`);
                    if (TYPE === 'xhttp') {
                        fn = fn.replace(/network:\s*ws/i, 'network: xhttp');
                        if (/ws-opts:/i.test(fn)) {
                            fn = fn.replace(/ws-opts:\s*\{([^}]*)\}/i, `xhttp-opts: {$1, extra: ${xhttpExtra}}`);
                        } else {
                            fn = fn.replace(/\}(\s*)$/, `, xhttp-opts: {extra: ${xhttpExtra}}}$1`);
                        }
                    }
                    fn = fn.replace(/alpn:\s*\[[^\]]+\]/i, `alpn: ['h3', 'h2', 'http/1.1']`);
                    fn = fn.replace(/path:\s*['"]?[^,}\s]+['"]?/i, `path: ${tp}`);
                }
                R.push(fn); i++;
            } else if (tl.startsWith('- name:')) {
                let nl = [l]; i++;
                while (i < L.length && L[i].search(/\S/) > (l.search(/\S/))) { nl.push(L[i]); i++; }
                const nodeText = nl.join('\n');
                const um = nodeText.match(/uuid:\s*([^\n]+)/);
                if (um && um[1].trim() === myID.trim()) {
                    for (let j = 0; j < nl.length; j++) {
                        if (/client-fingerprint:/.test(nl[j])) {
                            nl[j] = nl[j].replace(/client-fingerprint:\s*\S+/, 'client-fingerprint: ' + FP);
                        }
                        if (/^\s*path:/i.test(nl[j])) {
                            nl[j] = nl[j].replace(/(path:\s*)['"]?[^'"]+['"]?/i, `$1${tp}`);
                        }
                        if (/^\s*alpn:/i.test(nl[j])) {
                            nl[j] = nl[j].replace(/(alpn:\s*).*/i, `$1['h3', 'h2', 'http/1.1']`);
                        }
                        if (TYPE === 'xhttp') {
                            if (/^\s*network:\s*ws/i.test(nl[j])) {
                                nl[j] = nl[j].replace(/network:\s*ws/i, 'network: xhttp');
                            }
                            if (/^\s*ws-opts:/i.test(nl[j])) {
                                nl[j] = nl[j].replace(/ws-opts:/i, 'xhttp-opts:');
                            }
                        }
                    }
                    let ii = -1;
                    for (let j = nl.length - 1; j >= 0; j--) if (nl[j].trim()) { ii = j; break; }
                    if (ii >= 0) {
                        const ind = ' '.repeat(l.search(/\S/) + 2);
                        let appendLines = [];
                        if (ECH) {
                            appendLines.push(ind + 'ech-opts:', ind + '  enable: true', ind + '  query-server-name: ' + ECH_SNI);
                        }
                        if (TYPE === 'xhttp') {
                            if (!nodeText.includes('xhttp-opts:')) appendLines.push(ind + 'xhttp-opts:');
                            appendLines.push(
                                ind + '  extra:',
                                ind + '    noGRPCHeader: true',
                                ind + '    headers:',
                                ind + '      Content-Type: application/octet-stream',
                                ind + '    xPaddingBytes: "100-1000"',
                                ind + '    xPaddingObfsMode: true',
                                ind + '    xPaddingMethod: tokenish',
                                ind + '    xPaddingPlacement: queryInHeader',
                                ind + `    xPaddingHeader: "${padHeader}"`,
                                ind + `    xPaddingKey: "${padKey}"`
                            );
                        }
                        nl.splice(ii + 1, 0, ...appendLines);
                    }
                }
                R.push(...nl);
            } else { R.push(l); i++; }
        }
        return R.join('\n');
    } catch { return x; }
}
async function hSub(r, c, u, UA, h) {
    const now = Date.now();
    let up = SUB.trim() || h;
    let pip = u.searchParams.get("proxyip");
    let tp = (pip && pip.trim()) ? `/proxyip=${pip.trim()}` : "/proxyip=166.88.95.214:51294?ed=2560";
    const _gDU = () => {
        if (!ST) return null;
        try {
            const uu = new URL(`vless://${myID}@${up}:443`);
            uu.searchParams.set('encryption', 'none');
            uu.searchParams.set('security', 'tls');
            uu.searchParams.set('sni', h);
            uu.searchParams.set('fp', FP);
            uu.searchParams.set('alpn', 'h3,h2,http/1.1');
            uu.searchParams.set('type', TYPE);
            if (TYPE === 'xhttp') {
                uu.searchParams.set('mode', 'stream-one');
                uu.searchParams.set('extra', xhttpExtra);
            }
            uu.searchParams.set('host', h);
            uu.searchParams.set('path', tp);
            if (ECH) uu.searchParams.set('ech', ECH_SNI + '+' + ECH_DNS);
            uu.hash = 'Worker';
            return `https://${up}/sub?base=${encodeURIComponent(uu.toString())}&token=${encodeURIComponent(ST)}`;
        } catch { return null; }
    };
    if (UA.includes('box') || UA.includes('hiddify')) {
        const dU = _gDU();
        const bU = `${SUBAPI}/sub?target=singbox&url=${encodeURIComponent(dU || `https://${h}/${myID}?flag=true${pip ? `&proxyip=${encodeURIComponent(pip)}` : ''}`)}&config=${encodeURIComponent(SBV11)}&emoji=true&_t=${now}`;
        const o = await fetch(bU); if (!o.ok) return new Response("Err", { status: 500 });
        let echCfg = null; if (ECH) echCfg = await _getECH(ECH_SNI);
        return new Response(pSB(await o.text(), echCfg, h, FP, tp), { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } });
    }
    if (UA.includes('clash') || UA.includes('mihomo')) {
        const dU = _gDU();
        const a = `${SUBAPI}/sub?target=clash&url=${encodeURIComponent(dU || `https://${h}/${myID}?flag=true${pip ? `&proxyip=${encodeURIComponent(pip)}` : ''}`)}&config=${encodeURIComponent(SUBINI)}&emoji=true&_t=${now}`;
        const s = await fetch(a); if (!s.ok) return new Response("Err", { status: 500 });
        return new Response(pCL(await s.text(), h, FP, tp), { status: 200, headers: { "Content-Type": "text/yaml; charset=utf-8" } });
    }
    if (ST) {
        const _su = _gDU();
        try {
            const e = await fetch(_su, { headers: { "User-Agent": "Mozilla/5.0" } });
            if (e.ok) {
                let t = await e.text();
                try { t = atob(t); } catch { }
                t = t.split('\n').map(l => fixVless(l, h, tp, FP, ECH, ECH_SNI, ECH_DNS)).join('\n');
                return new Response(btoa(t), { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
            }
        } catch { }
        return new Response("Err", { status: 502, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }
    const p = new URLSearchParams();
    p.append('uuid', myID);
    p.append("host", up);
    p.append("sni", h);
    p.append("path", tp);
    p.append("type", TYPE);
    if (TYPE === 'xhttp') {
        p.append("mode", "stream-one");
        p.append("extra", xhttpExtra);
    }
    p.append('encryption', "none");
    p.append('security', 'tls');
    p.append('alpn', "h3,h2,http/1.1");
    p.append("fp", FP);
    if (ECH) p.append('ech', ECH_SNI + '+' + ECH_DNS);
    try {
        const e = await fetch(`https://${up}/sub?${p.toString()}`, { headers: { "User-Agent": "Mozilla/5.0" } });
        if (e.ok) {
            let t = await e.text();
            try { t = atob(t); } catch { }
            t = t.split('\n').map(l => fixVless(l, h, tp, FP, ECH, ECH_SNI, ECH_DNS)).join('\n');
            return new Response(btoa(t), { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
        }
    } catch { }
    return new Response("Err", { status: 502, headers: { "Content-Type": "text/plain; charset=utf-8" } });
}
