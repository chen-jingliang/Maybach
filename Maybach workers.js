// 代码名称：GrainTCP+CM+XHTTP+jaclbax
// 版本号：v1.4.9 (Pure Forwarding & Full Protocol & Zero-Error)
// 生成时间：2026-10-20 21:17:00 (北京时间)
import { connect } from 'cloudflare:sockets';

const te = new TextEncoder();
const td = new TextDecoder();

const myID = '';
let PIP = 'proxy.mia.xx.kg';

const RACE = 1;

const CFG = { chunk: 131072, dnPack: 262144, dnMs: 10, upPack: 32768, upNMax: 256, maxED: 8192, hsMax: 16384, connMs: 1800, xhInit: 32768, xhNext: 16384 };

const c_map = new Map, c_run = new Map, c_max = 400, c_ttl = 18e4;
const p_map = new Map, p_ring = new Array(20); let p_idx = 0;

const r_ip = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const r_ip6 = /^\[?([a-fA-F0-9:]+)\]?$/, v_b0 = new Uint8Array(0), dec = new TextDecoder, enc = new TextEncoder;
const v_v10 = new Uint8Array([33, 18, 164, 66]), v_z20 = new Uint8Array(20), v_ssinf = enc.encode("ss-subkey");
const hex = c => (c > 64 ? c + 9 : c) & 15, idB = new Uint8Array(16);
if (myID) {
    for (let i = 0, p = 0; i < 16; i++) {
        let c1 = myID.charCodeAt(p++); if (c1 === 45) c1 = myID.charCodeAt(p++);
        let c2 = myID.charCodeAt(p++); if (c2 === 45) c2 = myID.charCodeAt(p++);
        idB[i] = hex(c1) << 4 | hex(c2);
    }
}

const matchID = c => c[1] === idB[0] && c[2] === idB[1] && c[3] === idB[2] && c[4] === idB[3] && c[5] === idB[4] && c[6] === idB[5] && c[7] === idB[6] && c[8] === idB[7] && c[9] === idB[8] && c[10] === idB[9] && c[11] === idB[10] && c[12] === idB[11] && c[13] === idB[12] && c[14] === idB[13] && c[15] === idB[14] && c[16] === idB[15];

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
const authHex = myID ? f_auth(myID) : "", authBuf = new Uint8Array(56);
if (authHex) for (let i = 0; i < 56; i++) authBuf[i] = authHex.charCodeAt(i);

function f12(s) { try { if (s?.readyState === WebSocket.OPEN || s?.readyState === WebSocket.CLOSING) s.close(); const p = s?.close?.(); if(p && typeof p.catch === 'function') p.catch(()=>{}); } catch { } }
const rl = t => { try { t?.releaseLock(); } catch { } };
const I = t => t instanceof Uint8Array ? t : ArrayBuffer.isView(t) ? new Uint8Array(t.buffer, t.byteOffset, t.byteLength) : new Uint8Array(t);
const f_p16 = (d, o, v) => { d[o] = v >> 8 & 255; d[o + 1] = v & 255; };
const f_adr = (t, b) => 1 === t ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : 3 === t ? dec.decode(b) : `[${Array.from({ length: 8 }, (_, i) => (b[2 * i] << 8 | b[2 * i + 1]).toString(16)).join(":")}]`;

function f13(s) { if (!s) return null; const e = (e, n, r) => { try { const isS = s.startsWith(e + "s://"), a = /!ip(?:$\vert{}&)/i.test(s), i = new URL(s.replace(/!ip(?:$|&)/i, "")); return { type: isS ? e + "s" : e, host: i.hostname, port: parseInt(i.port) || (isS ? r : n), username: i.username ? decodeURIComponent(i.username) : "", password: i.password ? decodeURIComponent(i.password) : "", isc: isS && (a || r_ip.test(i.hostname) || r_ip6.test(i.hostname)) } } catch { return null; } }; if ((s = s.trim()).startsWith("turn://") || s.startsWith("turns://")) return e("turn", 3478, 5349); if (s.startsWith("sstp://")) { try { const e = new URL(s); return { type: "sstp", host: e.hostname, port: parseInt(e.port) || 443, username: e.username ? decodeURIComponent(e.username) : "vpn", password: e.password ? decodeURIComponent(e.password) : "vpn" } } catch { return null; } } if (s.startsWith("socks://") || s.startsWith("socks5://")) { try { const e = new URL(s.replace(/^socks:\/\//, "socks5://")); return { type: "socks5", host: e.hostname, port: parseInt(e.port) || 1080, username: e.username ? decodeURIComponent(e.username) : "", password: e.password ? decodeURIComponent(e.password) : "" } } catch { return null; } } if (s.startsWith("http://") || s.startsWith("https://")) { try { const h = s.startsWith("https://"), hasTag = /!ip(?:$\vert{}&)/i.test(s), u = new URL(s.replace(/!ip(?:$|&)/i, "")), c = hasTag || r_ip.test(u.hostname) || r_ip6.test(u.hostname); return { type: h ? "https" : "http", host: u.hostname, port: parseInt(u.port) || (h ? 443 : 80), username: u.username ? decodeURIComponent(u.username) : "", password: u.password ? decodeURIComponent(u.password) : "", isc: c }; } catch { return null; } } const m = s.match(/^\[([^\]]+)\](?::(\d+))?$/); if (m) { const p = parseInt(m[2], 10); return { type: "direct", host: m[1], port: !isNaN(p) && p > 0 ? p : 443 } } const i = s.lastIndexOf(":"); if (i > 0) { const h = s.substring(0, i), p = parseInt(s.substring(i + 1), 10); if (!isNaN(p) && p > 0 && p <= 65535) return { type: "direct", host: h, port: p } } return { type: "direct", host: s, port: 443 } }

async function f14(d, t) { const k = d + "_" + t, n = Date.now(), c = c_map.get(k); if (c) { if (n - c.time < c_ttl) return c.data; c_map.delete(k); } const old = c_run.get(k); if (old) return old; const j = (async () => { try { const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(d)}&type=${t}`, { headers: { Accept: "application/dns-json" } }); if (!r.ok) return []; const a = (await r.json()).Answer || []; if (a.length) { if (c_map.size >= c_max) c_map.delete(c_map.keys().next().value); c_map.set(k, { data: a, time: Date.now() }); } return a; } catch { return []; } })(); c_run.set(k, j); try { return await j; } finally { c_run.delete(k); } }

const resIPv4 = async d => {
    if (r_ip.test(d)) return d;
    const a = (await f14(d, "A")).filter(x => 1 === x.type).map(x => x.data);
    if (!a.length) throw 0;
    return a[0];
};

const f_hkdf = async (ikm, salt, info, len) => { const k1 = await crypto.subtle.importKey("raw", salt.length ? salt : v_z20, { name: "HMAC", hash: "SHA-1" }, !1, ["sign"]), prk = new Uint8Array(await crypto.subtle.sign("HMAC", k1, ikm)); const k2 = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-1" }, !1, ["sign"]), okm = new Uint8Array(Math.ceil(len / 20) * 20); let pv = v_b0; for (let i = 0; i < Math.ceil(len / 20); i++) { pv = new Uint8Array(await crypto.subtle.sign("HMAC", k2, cat(pv, info, new Uint8Array([i + 1])))), okm.set(pv, i * 20); } return okm.slice(0, len); };

let v_mk = null;
const f_gmk = async () => v_mk ??= new Uint8Array(await crypto.subtle.digest("MD5", f1(myID)));

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
                s.push(Promise.all([this.enc.encIv(lb, iv1), this.enc.encIv(ck, iv2)])); 
            } 
            for (const [L, M] of await Promise.all(s)) { 
                n.set(L, r); r += 18; n.set(M, r); r += M.length; 
            } 
        } 
        return n; 
    } 
}

const mkK = (cap, cpy = 0) => { let q = [], h = 0, b = 0, buf = null; const e = () => h >= q.length, trim = () => { h > 32 && h * 2 >= q.length && (q = q.slice(h), h = 0); }, clear = () => { q = [], h = 0, b = 0; }; const take = () => { if (e()) return null; const d = q[h]; return q[h++] = void 0, b -= d.byteLength, trim(), d; }; const sow = d => { const n = d?.byteLength || 0; return !!n && (q.push(d), b += n, 1); }; const pack = d => { let z = 0; if (!d) { d = take(); d && (z = 1); } if (!d || e()) return [d, 0, z]; let n = d.byteLength, j = h; while (j < q.length) { const x = q[j], nn = n + x.byteLength; if (nn > cap) break; n = nn; j++; } if (j === h) return [d, 0, z]; const out = buf ||= new Uint8Array(cap); out.set(d); for (let o = d.byteLength; h < j;) { const x = q[h]; q[h++] = void 0; b -= x.byteLength; out.set(x, o); o += x.byteLength; z++; } trim(); return [cpy ? out.slice(0, n) : out.subarray(0, n), 1, z]; }; return { e: e, get b() { return b; }, clear: clear, take: take, sow: sow, pack: pack }; };

const mkBt = (wr, onErr) => {
    const buf = new Uint8Array(32768);
    let cur = 0, tm = 0, dead = !1, p = Promise.resolve();
    const fail = () => { dead || (out.stop(), onErr()); };
    const writeOut = chunk => { try { p = wr.write(chunk).catch(fail); } catch { fail(); } return p; };
    const flush = () => {
        tm && (clearTimeout(tm), tm = 0);
        if (cur && !dead) { const c = buf.slice(0, cur); cur = 0; writeOut(c); }
        return p;
    };
    const out = chunk => {
        if (dead || !chunk?.byteLength) return p;
        const len = chunk.byteLength;
        if (len >= 32768) return flush(), writeOut(chunk);
        cur + len > 32768 && flush();
        buf.set(chunk, cur); cur += len;
        if (32768 === cur) return flush();
        tm ||= setTimeout(flush, 2);
        return p;
    };
    out.flush = flush;
    out.stop = () => { dead = !0; cur = 0; clearTimeout(tm); tm = 0; };
    return out;
};

let cachedTlsClient = null;
const F = () => cachedTlsClient ??= (() => {
    const t = new TextEncoder, e = new Uint8Array(0), n = new Map(Object.entries({TLS_AES_128_GCM_SHA256:{id:4865,keyLen:16,ivLen:12,hash:"SHA-256",tls13:!0},TLS_AES_256_GCM_SHA384:{id:4866,keyLen:32,ivLen:12,hash:"SHA-384",tls13:!0},TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:{id:49199,keyLen:16,ivLen:4,hash:"SHA-256",kex:"ECDHE"},TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:{id:49200,keyLen:32,ivLen:4,hash:"SHA-384",kex:"ECDHE"},TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:{id:49195,keyLen:16,ivLen:4,hash:"SHA-256",kex:"ECDHE"},TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:{id:49196,keyLen:32,ivLen:4,hash:"SHA-384",kex:"ECDHE"}}).map(([,t])=>[t.id,t])),r=new Map([[29,"X25519"],[23,"P-256"]]),s=[2052,2053,2054,1025,1281,1537,1027,1283,1539],a=(...t)=>{const e=t=>{const n=[];for(const r of t)r instanceof Uint8Array?n.push(...r):Array.isArray(r)?n.push(...e(r)):"number"==typeof r&&n.push(r);return n};return new Uint8Array(e(t))},i=t=>[t>>8&255,255&t],o=(t,e)=>t[e]<<8|t[e+1],c=(t,e)=>t[e]<<16|t[e+1]<<8|t[e+2],h=(...t)=>{const e=t.filter(t=>t&&t.length>0),n=e.reduce((t,e)=>t+e.length,0),r=new Uint8Array(n);let s=0;for(const t of e)r.set(t,s),s+=t.length;return r},l=t=>crypto.getRandomValues(new Uint8Array(t)),u=(t,e)=>{if(!t||!e||t.length!==e.length)return!1;let n=0;for(let r=0;r<t.length;r++)n|=t[r]^e[r];return 0===n},w=t=>"SHA-512"===t?64:"SHA-384"===t?48:32;
    async function f(t,e,n){const r=await crypto.subtle.importKey("raw",e,{name:"HMAC",hash:t},!1,["sign"]);return new Uint8Array(await crypto.subtle.sign("HMAC",r,n))}
    async function y(t,e){return new Uint8Array(await crypto.subtle.digest(t,e))}
    async function p(e,n,r,s,a="SHA-256"){const i=h(t.encode(n),r);let o=new Uint8Array(0),c=i;for(;o.length<s;){c=await f(a,e,c);const t=await f(a,e,h(c,i));o=h(o,t)}return o.slice(0,s)}
    async function d(t,e,n){return e&&e.length||(e=new Uint8Array(w(t))),f(t,e,n)}
    async function g(e,n,r,s,o){const c=t.encode("tls13 "+r);return async function(t,e,n,r){const s=w(t),a=Math.ceil(r/s);let i=new Uint8Array(0),o=new Uint8Array(0);for(let r=1;r<=a;r++)o=await f(t,e,h(o,n,[r])),i=h(i,o);return i.slice(0,r)}(e,n,a(i(o),c.length,c,s.length,s),o)}
    async function b(t="P-256"){
        if("X25519"===t){
            const kp=await crypto.subtle.generateKey({name:"X25519"},!0,["deriveBits"]);
            const pub=kp["publicKey"]||kp;
            const exp=await crypto.subtle.exportKey("raw",pub);
            const pk=new Uint8Array(exp instanceof ArrayBuffer?exp:new ArrayBuffer(0));
            return{kp,pk}
        }
        const kp=await crypto.subtle.generateKey({name:"ECDH",namedCurve:t},!0,["deriveBits"]);
        const pub=kp["publicKey"]||kp;
        const exp=await crypto.subtle.exportKey("raw",pub);
        const pk=new Uint8Array(exp instanceof ArrayBuffer?exp:new ArrayBuffer(0));
        return{kp,pk}
    }
    async function m(t,e,n="P-256"){
        if("X25519"===n){
            const pk=await crypto.subtle.importKey("raw",e,{name:"X25519"},!1,[]);
            return new Uint8Array(await crypto.subtle.deriveBits(Object.assign({name:"X25519"},{public:pk}),t,256))
        }
        const pk=await crypto.subtle.importKey("raw",e,{name:"ECDH",namedCurve:n},!1,[]);
        const s="P-384"===n?384:"P-521"===n?528:256;
        return new Uint8Array(await crypto.subtle.deriveBits(Object.assign({name:"ECDH"},{public:pk}),t,s))
    }
    async function A(t,e,n,r){const s=await crypto.subtle.importKey("raw",t,{name:"AES-GCM"},!1,["encrypt"]);return new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:e,additionalData:r,tagLength:128},s,n))}
    async function k(t,e,n,r){const s=await crypto.subtle.importKey("raw",t,{name:"AES-GCM"},!1,["decrypt"]);return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:e,additionalData:r,tagLength:128},s,n))}
    function U(t,e,n=771){return a(t,i(n),i(e.length),e)}
    function L(t,e){return a(t,[(n=e.length)>>16&255,n>>8&255,255&n],e);var n}
    class S{constructor(){this.b=new Uint8Array(0)}feed(t){this.b=h(this.b,t)}next(){if(this.b.length<5)return null;const t=this.b[0],e=o(this.b,1),n=o(this.b,3);if(this.b.length<5+n)return null;const r=this.b.slice(5,5+n);return this.b=this.b.slice(5+n),{type:t,version:e,length:n,fragment:r}}}
    class v{constructor(){this.b=new Uint8Array(0)}feed(t){this.b=h(this.b,t)}next(){if(this.b.length<4)return null;const t=this.b[0],e=c(this.b,1);if(this.b.length<4+e)return null;const n=this.b.slice(4,4+e),r=this.b.slice(0,4+e);return this.b=this.b.slice(4+e),{type:t,length:e,body:n,raw:r}}}
    function C(t){let e=0;const n=o(t,e);e+=2;const r=t.slice(e,e+32);e+=32;const s=t[e++],a=t.slice(e,e+s);e+=s;const i=o(t,e);e+=2;const c=t[e++];let h=n,l=null;if(e<t.length){const n=o(t,e);e+=2;const r=e+n;for(;e+4<=r;){const n=o(t,e);e+=2;const r=o(t,e);e+=2;const s=t.slice(e,e+r);if(e+=r,43===n&&r>=2)h=o(s,0);else if(51===n&&r>=4){const t=o(s,0),e=o(s,2);l={group:t,key:s.slice(4,4+e)}}}}const w=new Uint8Array([207,33,173,116,229,154,97,17,190,29,140,2,30,101,184,145,194,162,17,22,122,187,140,94,7,158,9,226,200,168,51,156]);return{version:n,sr:r,sid:a,cs:i,comp:c,sv:h,ks:l,isHRR:u(r,w),isTls13:772===h}}
    const T=(t,e=0)=>{let n=0;if(e){const e=t[n++];n+=e}if(n+3>t.length)return null;const r=c(t,n);if(n+=3,!r||n+3>t.length)return null;const s=c(t,n);return n+=3,s?t.slice(n,n+s):null};
    const x=t=>t&&1===t[0]&&112===t[1];
    const P=t=>{const e=new Uint8Array(8);return new DataView(e.buffer).setBigUint64(0,t,!1),e};
    const M=(t,e)=>{const n=t.slice(),r=P(e);for(let t=0;t<8;t++)n[n.length-8+t]^=r[t];return n};
    const E=(t,n,r,s)=>Promise.all([g(t,n,"key",e,r),g(t,n,"iv",e,s)]);
    return class {
        constructor(t,opts){let e=opts||{};if(this.sk=t,this.sn=e.serverName||"",this.s13=!1!==e.tls13,this.s12=!1!==e.tls12,!this.s13&&!this.s12)throw 0;this.to=e.timeout??3e4,this.cr=l(32),this.sr=null,this.hk=[],this.hc=!1,this.cs=null,this.cc=null,this.is13=!1,this.ms=null,this.hs=null,this.cwk=null,this.swk=null,this.cwi=null,this.swi=null,this.chk=null,this.shk=null,this.chi=null,this.shi=null,this.cak=null,this.sak=null,this.cai=null,this.sai=null,this.csn=0n,this.ssn=0n,this.rp=new S,this.hp=new v,this.kps=new Map,this.ekp=null,this.sc=!1}
        rh(t){this.hk.push(t)}
        ts(){return 1===this.hk.length?this.hk[0]:h(...this.hk)}
        gfc(t){return n.get(t)||null}
        async rc(t){if(!this.to)return t.read();let e;const n=t.read(),r=await Promise.race([n,new Promise(t=>e=setTimeout(()=>t(0),this.to))]).finally(()=>clearTimeout(e));if(r)return r;try{await t.cancel("err")}catch{}try{await n}catch{}throw 0}
        async pr(t,e){for(;;){let n;for(;n=this.rp.next();)if(await e(n))return;const{value:r,done:s}=await this.rc(t);if(s)throw 0;this.rp.feed(r)}}
        async ph(t,e){for(let t;t=this.hp.next();)if(await e(t))return;return this.pr(t,async t=>{if(21===t.type){if(x(t.fragment))return;throw 0}if(22===t.type){this.hp.feed(t.fragment);for(let t;t=this.hp.next();)if(await e(t))return 1}})}
        async ac(t){if(!t?.length)throw 0;this.sc=!0}
        async handshake(){const[e,n]=await Promise.all([b("P-256"),b("X25519")]);this.kps=new Map([[23,e],[29,n]]),this.ekp=e.kp;const r=this.sk.readable.getReader(),o=this.sk.writable.getWriter();try{const c=function(e,n,r,opts){let o=!opts||opts.tls13!==!1,c=!opts||opts.tls12!==!1;n=(t=>{if("["===(t=String(t??"").trim())[0]&&"]"===t[t.length-1]&&(t=t.slice(1,-1)),!t||t.includes(":"))return"";const e=t.split(".");if(4!==e.length)return t;for(const n of e){if(""===n||n.length>3)return t;let e=0;for(let r=0;r<n.length;r++){const s=n.charCodeAt(r)-48;if(s<0||s>9)return t;e=10*e+s}if(e>255)return t}return""})(n);const l=[];o&&l.push(4865,4866),c&&l.push(49199,49200,49195,49196);const u=a(...l.flatMap(i)),w=[a(255,1,0,1,0)];if(n){const e=t.encode(n),r=a(0,i(e.length),e);w.push(a(i(0),i(r.length+2),i(r.length),r))}w.push(a(i(11),0,2,1,0)),w.push(a(i(10),0,6,0,4,0,29,0,23));const f=a(...s.flatMap(i));if(w.push(a(i(13),i(f.length+2),i(f.length),f)),o&&r){let t;if(w.push(c?a(i(43),0,5,4,3,4,3,3):a(i(43),0,3,2,3,4)),w.push(a(i(45),0,2,1,1)),r?.x25519&&r?.p256)t=h(a(0,29,i(r.x25519.length),r.x25519),a(0,23,i(r.p256.length),r.p256));else if(r?.x25519)t=a(0,29,i(r.x25519.length),r.x25519);else if(r?.p256)t=a(0,23,i(r.p256.length),r.p256);else{if(!(r instanceof Uint8Array))throw 0;t=a(0,23,i(r.length),r)}w.push(a(i(51),i(t.length+2),i(t.length),t))}const y=h(...w);return L(1,a(i(771),e,0,i(u.length),u,1,0,i(y.length),y))}(this.cr,this.sn,{x25519:n.pk,p256:e.pk},{tls13:this.s13,tls12:this.s12});this.rh(c),await o.write(U(22,c,769));const l=await this.rsh(r);if(l.isHRR)throw 0;if(l.ks?.group&&this.kps.has(l.ks.group)){const t=this.kps.get(l.ks.group);this.ekp=t.kp}l.isTls13?await this.h13(r,o,l):await this.h12(r,o),this.hc=!0}finally{r.releaseLock(),o.releaseLock()}}
        async rsh(t){for(;;){const{value:e,done:n}=await this.rc(t);if(n)throw 0;let r;for(this.rp.feed(e);r=this.rp.next();){if(21===r.type){if(x(r.fragment))continue;throw 0}if(22!==r.type)continue;let t;for(this.hp.feed(r.fragment);t=this.hp.next();){if(2!==t.type)continue;this.rh(t.raw);const e=C(t.body);if(this.sr=e.sr,this.cs=e.cs,this.cc=this.gfc(e.cs),this.is13=e.isTls13,!this.cc)throw 0;return e}}}}
        async h12(t,e){let nc=0,spk=v_b0;if(await this.ph(t,async t=>{switch(t.type){case 11:{this.rh(t.raw);const e=T(t.body);if(!e)throw 0;await this.ac(e);break}case 12:{this.rh(t.raw);let ptr=1;nc=o(t.body,ptr);ptr+=2;const len=t.body[ptr++];spk=t.body.slice(ptr,ptr+len);break}case 14:return this.rh(t.raw),1;case 13:throw 0;default:this.rh(t.raw)}}),!this.sc||!nc)throw 0;const i=r.get(nc);if(!i)throw 0;const l=this.kps.get(nc);if(!l)throw 0;const w=await m(l.kp.privateKey,spk,i),f=L(16,a(l.pk.length,l.pk));this.rh(f);const d=this.cc.hash;this.ms=await p(w,"master secret",h(this.cr,this.sr),48,d);const g=this.cc.keyLen,b=this.cc.ivLen,A=await p(this.ms,"key expansion",h(this.sr,this.cr),2*g+2*b,d);this.cwk=A.slice(0,g),this.swk=A.slice(g,2*g),this.cwi=A.slice(2*g,2*g+b),this.swi=A.slice(2*g+b,2*g+2*b),await e.write(U(22,f)),await e.write(U(20,a(1)));const k=L(20,await p(this.ms,"client finished",await y(d,this.ts()),12,d));this.rh(k),await e.write(U(22,await this.e12(k,22)));let S=!1;await this.pr(t,async t=>{if(21===t.type){if(x(t.fragment))return;throw 0}if(20===t.type)return void(S=!0);if(22!==t.type||!S)return;const e=await this.d12(t.fragment,22);if(20!==e[0])return;const n=c(e,1),r=e.slice(4,4+n),s=await p(this.ms,"server finished",await y(d,this.ts()),12,d);if(!u(r,s))throw 0;return 1})}
        async h13(t,n,s){const a=r.get(s.ks?.group);if(!a||!s.ks?.key?.length)throw 0;const i=this.cc.hash,o=w(i),c=this.cc.keyLen,l=this.cc.ivLen,p=await m(this.ekp.privateKey,s.ks.key,a),b=await d(i,null,new Uint8Array(o)),A=await g(i,b,"derived",await y(i,e),o);this.hs=await d(i,A,p);const k=await y(i,this.ts()),S=await g(i,this.hs,"c hs traffic",k,o),v=await g(i,this.hs,"s hs traffic",k,o);[this.chk,this.chi]=await E(i,S,c,l),[this.shk,this.shi]=await E(i,v,c,l);const C=await g(i,v,"finished",e,o);let P=!1;const M=async t=>{switch(t.type){case 8:case 15:default:this.rh(t.raw);break;case 11:{const e=T(t.body,1);if(!e)throw 0;await this.ac(e),this.rh(t.raw);break}case 13:throw 0;case 20:{const e=await f(i,C,await y(i,this.ts()));if(!u(e,t.body))throw 0;this.rh(t.raw),P=!0;break}}};await this.pr(t,async t=>{if(20===t.type||22===t.type)return;if(21===t.type){if(x(t.fragment))return;throw 0}if(23!==t.type)return;const e=await this.d13h(t.fragment),n=e[e.length-1],r=e.slice(0,-1);if(22===n){this.hp.feed(r);for(let t;t=this.hp.next();)if(await M(t),P)return 1}});const H=await y(i,this.ts()),D=await g(i,this.hs,"derived",await y(i,e),o),R=await d(i,D,new Uint8Array(o)),_=await g(i,R,"c ap traffic",H,o),W=await g(i,R,"s ap traffic",H,o);[this.cak,this.cai]=await E(i,_,c,l),[this.sak,this.sai]=await E(i,W,c,l);const I=await g(i,S,"finished",e,o),$=L(20,await f(i,I,await y(i,this.ts())));this.rh($),await n.write(U(23,await this.e13h(h($,[22])))),this.csn=0n,this.ssn=0n}
        async e12(t,e){const n=this.csn++,r=P(n),s=h(r,[e],i(771),i(t.length)),a=l(8);return h(a,await A(this.cwk,h(this.cwi,a),t,s))}
        async d12(t,e){const n=this.ssn++,r=P(n),s=t.slice(0,8),a=t.slice(8);return k(this.swk,h(this.swi,s),a,h(r,[e],i(771),i(a.length-16)))}
        async e13h(t){const e=M(this.chi,this.csn++),n=a(23,3,3,i(t.length+16));return A(this.chk,e,t,n)}
        async d13h(t){const e=M(this.shi,this.ssn++),n=a(23,3,3,i(t.length));return k(this.shk,e,t,n)}
        async e13(t){const e=h(t,[23]),n=M(this.cai,this.csn++),r=a(23,3,3,i(e.length+16));return A(this.cak,n,e,r)}
        async d13(t){const e=M(this.sai,this.ssn++),n=a(23,3,3,i(t.length)),r=await k(this.sak,e,t,n);return{data:r.slice(0,-1),type:r[r.length-1]}}
        async write(t){if(!this.hc)throw 0;const e=this.sk.writable.getWriter();try{this.is13?await e.write(U(23,await this.e13(t))):await e.write(U(23,await this.e12(t,23)))}finally{e.releaseLock()}}
        async read(){for(;;){let t;for(;t=this.rp.next();){if(21===t.type){if(0===t.fragment[1])return null;throw 0}if(23!==t.type)continue;if(!this.is13)return this.d12(t.fragment,23);const{data:e,type:n}=await this.d13(t.fragment);if(23===n)return e;if(22!==n)continue;let r;for(this.hp.feed(e);r=this.hp.next();)if(4!==r.type&&24===r.type)throw 0}const e=this.sk.readable.getReader();try{const{value:t,done:n}=await this.rc(e);if(n)return null;this.rp.feed(t)}finally{e.releaseLock()}}}
        close(){this.sk.close()}
    };
})();

const J = (t, e, n) => new ReadableStream({start: e=>t?.length&&e.enqueue(t),pull: e,cancel: n});
const Y = (t, e, n) => ({readable: J(e, async e=>{try{const n=await t.read();n?e.enqueue(n):e.close()}catch(t){e.error(t)}},()=>t.close()),writable: new WritableStream({write: e=>t.write(e),close(){t.close()},abort(){t.close()}}),close: n});

function Z(username, password) {
    let sock, reader, writer, remoteHost, buf = v_b0, seq = 1, hBuf = new ArrayBuffer(16384);
    async function readBytes(len) {
        if (buf.length >= len) { const chunk = buf.subarray(0, len); buf = buf.subarray(len); return chunk; }
        const prev = buf.length > 0 ? new Uint8Array(buf) : null;
        const res = await reader.readAtLeast(len - buf.length, new Uint8Array(hBuf));
        if (res.done) throw 0; hBuf = res.value.buffer;
        const combined = prev ? cat(prev, res.value) : res.value;
        buf = combined.subarray(len); return combined.subarray(0, len);
    }
    async function readLine() {
        for (;;) {
            const idx = buf.indexOf(10);
            if (idx >= 0) {
                const line = dec.decode(buf.subarray(0, idx)); buf = buf.subarray(idx + 1);
                return line.replace(/\r$/, "");
            }
            const res = await reader.readAtLeast(1, new Uint8Array(hBuf));
            if (res.done) throw 0; hBuf = res.value.buffer;
            buf = buf.length > 0 ? cat(buf, res.value) : res.value;
        }
    }
    async function readPkt(timeoutMs = 1e4) {
        let timer;
        const timeoutPromise = new Promise((_, reject) => { timer = setTimeout(() => reject(0), timeoutMs); });
        try {
            const pktHeader = await Promise.race([readBytes(4), timeoutPromise]);
            clearTimeout(timer);
            const bodyLen = 4095 & f3(pktHeader, 2);
            return { ctrl: !(1 & ~pktHeader[1]), body: bodyLen > 4 ? await readBytes(bodyLen - 4) : v_b0 };
        } catch (err) { clearTimeout(timer); throw err; }
    }
    function makeDataPkt(payload) {
        const totalLen = 6 + payload.length, pkt = new Uint8Array(totalLen);
        pkt.set([16, 0, (totalLen >> 8 & 15) | 128, 255 & totalLen, 255, 3]); pkt.set(payload, 6); return pkt;
    }
    function makeCtrlPkt(msgId, attrType, msgSeq, attrs = []) {
        const attrLen = attrs.reduce((acc, item) => acc + 2 + item.data.length, 0), pkt = new Uint8Array(6 + attrLen), view = new DataView(pkt.buffer);
        view.setUint16(0, msgId); pkt[2] = attrType; pkt[3] = msgSeq; view.setUint16(4, 4 + attrLen);
        let offset = 6;
        for (const item of attrs) { pkt[offset] = item.type; pkt[offset + 1] = 2 + item.data.length; pkt.set(item.data, offset + 2); offset += 2 + item.data.length; }
        return pkt;
    }
    function makeConnectPkt(msgSeq) {
        const uUser = f1(username), uPass = f1(password), uLen = uUser.length, pLen = uPass.length, bodyLen = 6 + uLen + pLen, pkt = new Uint8Array(2 + bodyLen), view = new DataView(pkt.buffer);
        view.setUint16(0, 49187); pkt[2] = 1; pkt[3] = msgSeq; view.setUint16(4, bodyLen); pkt[6] = uLen; pkt.set(uUser, 7); pkt[7 + uLen] = pLen; pkt.set(uPass, 8 + uLen); return pkt;
    }
    function parsePPP(body) {
        let skip = (body.length >= 2 && 255 === body[0] && 3 === body[1]) ? 2 : 0;
        if (body.length - skip < 4) return null;
        const proto = f3(body, skip);
        if (33 === proto) return { protocol: proto, ip: body.subarray(skip + 2) };
        if (body.length - skip >= 6) return { protocol: proto, code: body[skip + 2], id: body[skip + 3], payload: body.subarray(skip + 6), raw: body.subarray(skip) };
        return null;
    }
    function getAttrs(payload) {
        const list = []; let idx = 0;
        while (idx + 2 <= payload.length) {
            const type = payload[idx], len = payload[idx + 1];
            if (len < 2 || idx + len > payload.length) break;
            list.push({ type: type, data: payload.subarray(idx + 2, idx + len) }); idx += len;
        }
        return list;
    }
    return {
        connect: async (host, port) => { sock = connect({ hostname: host, port: port }, { allowHalfOpen: true, secureTransport: "on" }); await sock.opened; reader = sock.readable.getReader({ mode: "byob" }); writer = sock.writable.getWriter(); remoteHost = host; },
        establish: async () => {
            const reqLine = f1(`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: ${remoteHost}\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`), attr1Data = new Uint8Array(2); new DataView(attr1Data.buffer).setUint16(0, 1); const attr2Data = new Uint8Array(2); new DataView(attr2Data.buffer).setUint16(0, 1500);
            const initPayload = cat((function(type, list = []) { const n = list.reduce((acc, item) => acc + 4 + item.data.length, 0), r = new Uint8Array(8 + n), s = new DataView(r.buffer); r[0] = 16; r[1] = 1; s.setUint16(2, 8 + n | 32768); s.setUint16(4, type); s.setUint16(6, list.length); let off = 8; for (const item of list) { r[off + 1] = item.id; s.setUint16(off + 2, 4 + item.data.length); r.set(item.data, off + 4); off += 4 + item.data.length; } return r; })(1, [{ id: 1, data: attr2Data }]), makeDataPkt(makeCtrlPkt(49185, 1, seq++, [{ type: 1, data: attr1Data }])));
            await writer.write(cat(reqLine, initPayload));
            const resp = await readLine();
            for (;;) { const headerLine = await readLine(); if ("" === headerLine) break; }
            if (!resp.includes("200")) throw 0;
            let gotConnectAck = false, gotConnected = false, sentAck = false, completed = false, clientIp = null;
            for (let t = 0; t < 25 && !completed; t++) {
                const pkt = await readPkt();
                if (pkt.ctrl) { if (!gotConnectAck && pkt.body.length >= 2 && 2 === f3(pkt.body, 0)) gotConnectAck = true; } else {
                    const ppp = parsePPP(pkt.body);
                    if (ppp) {
                        if (49185 === ppp.protocol) {
                            if (1 === ppp.code) {
                                const rawCopy = new Uint8Array(ppp.raw); rawCopy[2] = 2;
                                const reply = gotConnected && !sentAck ? cat(makeDataPkt(rawCopy), makeDataPkt(makeConnectPkt(seq++))) : makeDataPkt(rawCopy);
                                await writer.write(reply); if (gotConnected) sentAck = true;
                            } else if (2 === ppp.code) { gotConnected = true; if (!sentAck) { await writer.write(makeDataPkt(makeConnectPkt(seq++))); sentAck = true; } }
                        } else if (49187 === ppp.protocol && 2 === ppp.code) { await writer.write(makeDataPkt(makeCtrlPkt(32801, 1, seq++, [{ type: 3, data: new Uint8Array(4) }]))); } else if (32801 === ppp.protocol) {
                            if (1 === ppp.code) { const rawCopy = new Uint8Array(ppp.raw); rawCopy[2] = 2; await writer.write(makeDataPkt(rawCopy)); } else if (3 === ppp.code) { const attr = getAttrs(ppp.payload).find(x => 3 === x.type); if (attr) { clientIp = [...attr.data].join("."); await writer.write(makeDataPkt(makeCtrlPkt(32801, 1, seq++, [{ type: 3, data: attr.data }]))); } } else if (2 === ppp.code) { const attr = getAttrs(ppp.payload).find(x => 3 === x.type); if (attr) clientIp = [...attr.data].join("."); completed = true; }
                        }
                    }
                }
            }
            if (!clientIp) throw 0; return clientIp;
        },
        readPkt: readPkt, parsePPP: parsePPP, get buf() { return buf; }, get wr() { return writer; },
        close: () => { try { reader?.cancel(); } catch {} try { writer?.close(); } catch {} try { sock?.close(); } catch {} }
    };
}

const et=(t,e)=>{const n=e.length,r=new Uint8Array(4+n+(3&-n)),s=new DataView(r.buffer);return s.setUint16(0,t),s.setUint16(2,n),r.set(e,4),r},
nt=(t,e,n)=>{const r=cat(...n),s=new Uint8Array(20),a=new DataView(s.buffer);return a.setUint16(0,t),a.setUint16(2,r.length),s.set(v_v10,4),s.set(e,8),cat(s,r)},
rt=t=>{if(t.length<20||v_v10.some((e,n)=>t[4+n]!==e))return null;const e=new DataView(t.buffer,t.byteOffset,t.byteLength),n=e.getUint16(2),r={};for(let s=20;s+4<=20+n;){const n=e.getUint16(s),a=e.getUint16(s+2);if(s+4+a>t.length)break;r[n]=t.slice(s+4,s+4+a),s+=4+a+(3&-a)}return{type:e.getUint16(0),attrs:r}},
st=async(t,e)=>{const n=new Uint8Array(t),r=new DataView(n.buffer);r.setUint16(2,r.getUint16(2)+24);const s=await crypto.subtle.importKey("raw",e,{name:"HMAC",hash:"SHA-1"},!1,["sign"]);return cat(n,et(8,new Uint8Array(await crypto.subtle.sign("HMAC",s,n))))},
at=async(t,e)=>{let n=e??v_b0;const r=async()=>{const{done:e,value:r}=await t.read();if(e)throw 0;n=cat(n,new Uint8Array(r))};try{for(;n.length<20;)await r();const t=20+f3(n,2);for(;n.length<t;)await r();return[rt(n.subarray(0,t)),n.length>t?n.subarray(t):null]}catch{return[null,null]}},
it=async e=>{
    if(e.isc){
        const n=connect({hostname:e.host,port:e.port},{allowHalfOpen:true});
        await n.opened;
        const r=new(F())(n,{serverName:e.host});
        await r.handshake();
        return {s:n,c:r,h:{write:async t=>await r.write(t),releaseLock:()=>{}},u:{read:async()=>{const t=await r.read();return{done:!t,value:t}},releaseLock:()=>{},cancel:async()=>{}}};
    }
    const nOpts="turns"===e.type?{secureTransport:"on",allowHalfOpen:true}:{allowHalfOpen:true};
    const r=connect({hostname:e.host,port:e.port},nOpts);
    await r.opened;
    return {s:r,c:null,h:r.writable.getWriter(),u:r.readable.getReader()};
};

const f_cd_single = (h, p, m) => new Promise((ok, no) => {
    h = String(h).trim(); if (h[0] === "[" && h[h.length - 1] === "]") h = h.slice(1, -1);
    const s = connect({ hostname: h, port: p }, { allowHalfOpen: true });
    let e = 0;
    const t = setTimeout(() => { if (e) return; e = 1; f12(s); no(0); }, m);
    s.opened.then(() => { if (e) { f12(s); return; } e = 1; clearTimeout(t); ok(s); }, x => { if (e) return; e = 1; clearTimeout(t); f12(s); no(x); });
});

const f_cd = async (h, p, m = CFG.connMs) => {
    if (RACE < 2) return f_cd_single(h, p, m);
    let ok = null;
    const c = [];
    for (let i = 0; i < RACE; i++) {
        c.push(f_cd_single(h, p, m).then(sock => {
            if (ok) { f12(sock); return Promise.reject(0); }
            return ok = sock;
        }));
    }
    try { return await Promise.any(c); } catch { throw 0; }
};

async function f20({ host, port, username, password }, targetHost, targetPort) {
    let sock;
    try {
        sock = await f_cd(host, port, CFG.connMs);
        const c = sock.writable.getWriter(), h = sock.readable.getReader();
        const l = username && password ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]);
        await c.write(l);
        const u = await h.read();
        if (u.done || u.value.byteLength < 2) throw 0;
        const w = new Uint8Array(u.value)[1];
        if (2 === w) {
            const t = f1(username), e = f1(password), n = new Uint8Array(3 + t.length + e.length);
            n[0] = 1; n[1] = t.length; n.set(t, 2); n[2 + t.length] = e.length; n.set(e, 3 + t.length);
            await c.write(n);
            const a = await h.read();
            if (a.done || 0 !== new Uint8Array(a.value)[1]) throw 0;
        } else if (0 !== w) throw 0;
        const f = f1(targetHost), y = new Uint8Array(7 + f.length);
        y.set([5, 1, 0, 3, f.length]); y.set(f, 5);
        new DataView(y.buffer).setUint16(5 + f.length, targetPort, !1);
        await c.write(y);
        const p = await h.read();
        if (p.done || 0 !== new Uint8Array(p.value)[1]) throw 0;
        rl(c); rl(h);
        return sock;
    } catch (t) { f12(sock); throw t; }
}

async function f21(e, targetHost, targetPort) {
    let sock, a = null;
    try {
        sock = connect({ hostname: e.host, port: e.port }, e.isc ? { allowHalfOpen: true } : { secureTransport: "https" === e.type ? "on" : "off", allowHalfOpen: true });
        await sock.opened;
        let i = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
        if (e.username) i += `Proxy-Authorization: Basic ${btoa(`${e.username}:${e.password || ""}`)}\r\n`;
        i += "User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n";
        if (e.isc) {
            a = new (F())(sock, { serverName: e.host });
            await a.handshake();
            await a.write(f1(i));
        } else {
            const t = sock.writable.getWriter();
            await t.write(f1(i));
            t.releaseLock();
        }
        let o = e.isc ? null : sock.readable.getReader(), c = v_b0;
        for (;;) {
            let t, n;
            if (e.isc) { t = await a.read(); n = !t; } else { const res = await o.read(); t = res.value; n = res.done; }
            if (n || !t || (c = cat(c, t), c.length >= 12 && 50 !== c[9])) throw 0;
            let r = -1;
            for (let idx = 0; idx <= c.length - 4; idx++) {
                if (13 === c[idx] && 10 === c[idx+1] && 13 === c[idx+2] && 10 === c[idx+3]) { r = idx + 4; break; }
            }
            if (-1 !== r) {
                o?.releaseLock();
                let tail = c.subarray(r);
                if (e.isc) return Y(a, tail, () => a.close());
                if (tail.length > 0) {
                    let { readable, writable } = new TransformStream, writer = writable.getWriter();
                    writer.write(tail); writer.releaseLock();
                    sock.readable.pipeTo(writable).catch(() => {});
                    return { readable, writable: sock.writable, close: () => f12(sock) };
                }
                return sock;
            }
            if (c.length > 8192) throw 0;
        }
    } catch (t) { a?.close(); f12(sock); throw t; }
}

async function f22(t, e, n) {
    const r = await resIPv4(e);
    const s = Z(t.username, t.password), a = () => s.close();
    try {
        await s.connect(t.host, t.port);
        const clientIp = await s.establish();
        const i = ((t, e, n, r) => {
            const s = 1e4 + f6() % 5e4, a = f8(e), i = f8(n);
            let o = f7(), c = 0;
            const h = new Uint8Array(20);
            h.set([69, 0, 0, 0, 0, 0, 64, 0, 64, 6]);
            h.set(a, 12); h.set(i, 16);
            const l = new Uint8Array(1432);
            l.set(a); l.set(i, 4); l[9] = 6;
            const u = (t, e = v_b0) => {
                const n = e.length, a = 20 + n, i = 20 + a, u = 8 + i, w = new Uint8Array(u), f = new DataView(w.buffer);
                w.set([16, 0, (u >> 8 & 15) | 128, 255 & u, 255, 3, 0, 33]);
                w.set(h, 8); f.setUint16(10, i); f.setUint16(12, f6()); f.setUint16(18, f9(w, 8, 20));
                f.setUint16(28, s); f.setUint16(30, r); f.setUint32(32, o); f.setUint32(36, c);
                w[40] = 80; w[41] = t; f.setUint16(42, 65535);
                if (n) w.set(e, 48);
                l[10] = a >> 8; l[11] = 255 & a;
                l.set(w.subarray(28, 28 + a), 12);
                f.setUint16(44, f9(l, 0, 12 + a));
                return w;
            };
            const w = t => {
                if (t.length < 40 || 6 !== t[9]) return null;
                const e = 4 * (15 & t[0]);
                return f3(t, e) !== r || f3(t, e + 2) !== s ? null : { flags: t[e + 13], seq: f4(t, e + 4), off: e + 4 * (t[e + 12] >> 4 & 15) };
            };
            return {
                frame: u, match: w,
                handshake: async () => {
                    await t.wr.write(u(2)); o++;
                    for (let e = 0; e < 30; e++) {
                        const pkt = await t.readPkt();
                        if (!pkt.ctrl) {
                            const ppp = t.parsePPP(pkt.body);
                            if (ppp && 33 === ppp.protocol) {
                                const m = w(ppp.ip);
                                if (m && !(18 & ~m.flags)) { c = m.seq + 1 >>> 0; await t.wr.write(u(16)); return !0; }
                            }
                        }
                    }
                    throw 0;
                },
                get seq() { return o; }, set seq(v) { o = v; },
                get ack() { return c; }, set ack(v) { c = v; }
            };
        })(s, clientIp, r, n);
        await i.handshake();
        let sockOut = { enqueue: (v) => {}, close: () => {} };
        const readable = new ReadableStream({ start: st => { sockOut = st; }, cancel: a });
        return (async () => {
            try {
                let t = [], e = 0;
                const flushOut = () => {
                    if (e) {
                        sockOut.enqueue(1 === t.length ? t[0] : cat(...t));
                        t = []; e = 0;
                        s.wr.write(i.frame(16)).catch(() => {});
                    }
                };
                for (;;) {
                    const r = await s.readPkt(6e4);
                    if (!r.ctrl) {
                        const ppp = s.parsePPP(r.body);
                        if (ppp && 33 === ppp.protocol) {
                            const m = i.match(ppp.ip);
                            if (m) {
                                if (m.off < ppp.ip.length) {
                                    const chunk = ppp.ip.subarray(m.off);
                                    if (chunk.length) {
                                        i.ack = m.seq + chunk.length >>> 0;
                                        t.push(new Uint8Array(chunk));
                                        e += chunk.length;
                                    }
                                }
                                if (1 & m.flags) {
                                    flushOut();
                                    i.ack = i.ack + 1 >>> 0;
                                    s.wr.write(i.frame(17)).catch(() => {});
                                    sockOut.close();
                                    return;
                                }
                                if (s.buf.length < 4 || e >= 32768) flushOut();
                            }
                        }
                    }
                }
            } catch { try { sockOut.close(); } catch {} }
        })(), {
            readable,
            writable: new WritableStream({
                async write(chunk) {
                    const u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
                    if (u8.length <= 1400) {
                        await s.wr.write(i.frame(24, u8));
                        i.seq = i.seq + u8.length >>> 0;
                        return;
                    }
                    const list = [];
                    for (let idx = 0; idx < u8.length; idx += 1400) {
                        const part = u8.subarray(idx, Math.min(idx + 1400, u8.length));
                        list.push(i.frame(24, part));
                        i.seq = i.seq + part.length >>> 0;
                    }
                    await s.wr.write(cat(...list));
                },
                close: () => s.wr.write(i.frame(17)).catch(() => {}),
                abort: a
            }),
            close: a
        };
    } catch { a(); return null; }
}

async function f38(t, e, n) {
    let r = null, s = null, a = null, i = null;
    const o = () => { a?.close(); i?.close(); f12(r); f12(s); };
    try {
        const peerIp = await resIPv4(e);
        const c = await it(t);
        r = c.s; a = c.c;
        const { h: hWriter, u: uReader } = c, u = et(18, ((t, e) => {
            const n = new Uint8Array(8); n[1] = 1; new DataView(n.buffer).setUint16(2, 8466 ^ e);
            t.split(".").forEach((val, idx) => n[4 + idx] = +val ^ v_v10[idx]);
            return n;
        })(peerIp, n));
        const w = await (async(t, e, n, r, s) => {
            const a = new Uint8Array([n, 0, 0, 0]);
            await t.write(nt(3, f5(12), [et(25, a)]));
            let [i, o] = await at(e);
            if (!i) return null;
            let c = null, h = [];
            const l = t => c ? st(t, c) : Promise.resolve(t);
            if (275 === i.type && r.username && 401 === (i.attrs[9]?.length >= 4 ? 100 * (7 & i.attrs[9][2]) + i.attrs[9][3] : 0)) {
                const realm = dec.decode(i.attrs[20] ?? v_b0), nonce = i.attrs[21] ?? v_b0;
                c = new Uint8Array(await crypto.subtle.digest("MD5", f1(`${r.username}:${realm}:${r.password}`)));
                h = [et(6, f1(r.username)), et(20, f1(realm)), et(21, nonce)];
                const reqW = await st(nt(3, f5(12), [et(25, a), ...h]), c);
                const finArr = s ? await Promise.all(s(h, l)) : [];
                await t.write(finArr.length ? cat(reqW, ...finArr) : reqW);
                [i, o] = await at(e, o);
                if (!i) return null;
            } else if (s && 259 === i.type) {
                const arr = await Promise.all(s(h, l));
                arr.length && await t.write(cat(...arr));
            }
            return 259 === i.type ? { ky: c, aa: h, ex: o, sn: l } : null;
        })(hWriter, uReader, 6, t, (t, e) => [e(nt(8, f5(12), [u, ...t])), e(nt(10, f5(12), [u, ...t]))]);
        if (!w) throw 0;
        const { aa: fArr, sn: yFunc } = w;
        let p, d = w.ex;
        if ([p, d] = await at(uReader, d), 264 !== p?.type || ([p, d] = await at(uReader, d), 266 !== p?.type || !p.attrs[42])) throw 0;
        const g = await it(t);
        s = g.s; i = g.c;
        const { h: bWriter, u: mReader } = g;
        let A;
        await bWriter.write(await yFunc(nt(11, f5(12), [et(42, p.attrs[42]), ...fArr])));
        [p, A] = await at(mReader);
        if (267 !== p?.type) throw 0;
        return t.isc ? (rl(uReader), Y(i, A, o)) : ((t, e, n, r, s) => n?.length ? (e.releaseLock(), { readable: J(n, e => t.read().then(({done, value}) => done ? e.close() : e.enqueue(new Uint8Array(value))), () => t.cancel()), writable: s.writable, close: r }) : (t.releaseLock(), e.releaseLock(), { readable: s.readable, writable: s.writable, close: r }))(mReader, bWriter, A, o, s);
    } catch { o(); throw 0; }
}

async function f26_pool(h, p, pool) {
    try { return await f_cd(h, p, CFG.connMs); } catch { }
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
            if (!q) q = { type: "direct", host: cv, port: 443 };
            const sock = await via(q);
            if (sock) return sock;
        } catch (e) { }
    }
    return null;
}

const dn_res = async t => { const n = I(t); for (let e = 0; e < 2; e++) { let r; try { r = await f_cd("1.1.1.1", 53, CFG.connMs); const s = r.writable.getWriter(), i = r.readable.getReader(); let o = v_b0; const c = async t => { for (; o.byteLength < t;) { const { done: n, value: e } = await i.read(); if (n) throw 0; const r = I(e); o = o.byteLength ? cat(o, r) : r; } const e = o.subarray(0, t); o = o.byteLength > t ? o.subarray(t) : new Uint8Array(0); return e; }; const l = n.byteLength >= 2 && f3(n, 0) === n.byteLength - 2; await s.write(l ? n : cat(new Uint8Array([n.byteLength >> 8, 255 & n.byteLength]), n)); const h = await c(2), u = await c(f3(h, 0)); return l ? cat(h, u) : u; } catch { if (1 === e) return null; } finally { f12(r); } } };
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
        const m = Math.min(e, 56);
        let ok2 = !0;
        for (let i = 0; i < m; i++) if (t[i] !== authBuf[i]) { ok2 = !1; break; }
        if (ok2) {
            if (e < 60) return { more: 1 };
            const sess = parseSession(t, 2);
            return sess ? { type: 2, session: sess } : e < CFG.hsMax ? { more: 1 } : { error: 1 };
        }
    }
    return e < 17 ? { more: 1 } : { error: 1 };
};

const sniffWS = t => {
    const e = t.byteLength;
    let isV = e < 2;
    if (!isV) {
        isV = !0;
        const n = Math.min(e - 1, 16);
        for (let i = 0; i < n; i++) if (t[i + 1] !== idB[i]) { isV = !1; break; }
    }
    let isT = !0;
    const m = Math.min(e, 56);
    for (let i = 0; i < m; i++) if (t[i] !== authBuf[i]) { isT = !1; break; }
    if (!isV && !isT) return 3;
    if (isT) {
        if (e < 60) return 0;
        if (f_trajon(t)) return 2;
        if (!isV) return 3;
    }
    if (isV) {
        if (f_vmore(t)) return 1;
        if (e < CFG.hsMax) return 0;
    }
    return 3;
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
    
    const trans = typeof IdentityTransformStream === "function" 
        ? new IdentityTransformStream() 
        : new TransformStream(void 0, { highWaterMark: 1048576 });

    const stReader = (() => {
        try { return { reader: req.body.getReader({ mode: "byob" }), byob: !0 }; } 
        catch { return { reader: req.body.getReader(), byob: !1 }; }
    })();

    const rd = stReader.reader, wr = trans.writable.getWriter();
    let upstream = null, y = !1, p = !1, d = !1, ctlUp = null, ctlDn = null, bw = null;

    const releaseRd = () => { y || (y = !0, rl(rd)); };

    let hsTimeout = setTimeout(() => { try { rd.cancel().catch(()=>{}); } catch { } abortSession(); }, 15000);

    const abortSession = err => {
        if (!d) {
            d = !0; hsTimeout && (clearTimeout(hsTimeout), hsTimeout = 0);
            try { ctlUp?.abort(err); } catch { }
            try { bw?.stop(); } catch { }
            try { ctlDn?.abort(err); } catch { }
            if (!y) rd.cancel(err).catch(() => { });
            releaseRd();
            try { upstream?.close?.(); } catch { }
            f12(upstream);
            if (!p) {
                p = !0;
                try { wr.abort(err).catch(() => { }); } catch { }
                rl(wr);
            }
        }
    };

    (async () => {
        let sBuf = new Uint8Array(0), session = null;

        while (!session) {
            const probe = sniffSession(sBuf);
            if (probe.session) { 
                session = probe.session; 
                hsTimeout && (clearTimeout(hsTimeout), hsTimeout = 0);
                break; 
            }
            if (probe.error || sBuf.byteLength >= CFG.hsMax) throw 0;
            const rem = CFG.hsMax - sBuf.byteLength, nextLen = Math.min(0 === sBuf.byteLength ? CFG.xhInit : CFG.xhNext, rem);
            if (nextLen <= 0) throw 0;
            const { done: dn, value: vl } = await dt_read(stReader, nextLen);
            if (dn) throw 0;
            if (vl.byteLength) sBuf = sBuf.byteLength ? cat(sBuf, vl) : new Uint8Array(vl);
        }

        if (session.responsePrefix.byteLength) wr.write(session.responsePrefix).catch(abortSession);

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
            if (!p) {
                p = !0;
                try { await wr.close(); } finally { rl(wr); }
            }
            return void (d = !0);
        }

        upstream = await f26_pool(session.host, session.port, proxyPool);
        if (!upstream) throw 0;
        
        if (d) return f12(upstream);

        p || (p = !0, rl(wr));

        ctlUp = new AbortController();
        ctlDn = new AbortController();

        upstream.readable.pipeTo(trans.writable, { signal: ctlDn.signal }).catch(abortSession);

        const uWr = upstream.writable.getWriter();
        bw = mkBt(uWr, () => abortSession(0));
        if (session.payload.byteLength) {
            bw(session.payload);
            bw.flush();
        }
        releaseRd();
        (async () => {
            try {
                const upRd = req.body.getReader();
                let n = 0;
                for (; ;) {
                    const { done: dn, value: vl } = await upRd.read();
                    if (dn) break;
                    if (n += vl.byteLength, await bw(vl), n >= 32768) {
                        await bw.flush();
                        bw.stop();
                        rl(upRd);
                        rl(uWr);
                        req.body.pipeTo(upstream.writable, { signal: ctlUp.signal }).catch(err => { d || abortSession(err); });
                        return;
                    }
                }
                await bw.flush();
                await uWr.close().catch(() => { });
            } catch (err) {
                d || abortSession(err);
            }
        })();
    })().catch(abortSession);

    const respHeaders = new Headers({
        'Content-Type': 'application/octet-stream',
        'grpc-status': '0',
        'X-Accel-Buffering': 'no',
        'Cache-Control': 'no-store, no-transform, private',
        'X-Content-Type-Options': 'nosniff'
    });

    return new Response(trans.readable, { status: 200, headers: respHeaders });
}

async function handleWS(req, proxyPool) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    server.binaryType = "arraybuffer";
    let rw = { socket: null, writer: null, bw: null };
    let isDNS = !1, closed = !1, busy = !1, pT = 0, pendingPkt = 0;
    let ssPromise = Promise.resolve();
    const ssEngine = new SS();
    
    const uq = ((cap, mx = 4194304, nx = CFG.upNMax) => {
        const k = mkK(cap);
        let n = 0;
        return {
            get empty() { return k.e(); },
            get b() { return k.b; },
            clear() { k.clear(); n = 0; },
            sow: d => {
                const z = d?.byteLength || 0;
                if (!z || k.b + z > mx || n >= nx) return 0;
                n++; return k.sow(d);
            },
            bundle: d => {
                const r = k.pack(d);
                n = Math.max(0, n - r[2]);
                return r;
            }
        };
    })(CFG.upPack, 4194304);

    let hsTimeout = setTimeout(() => { if (!pT) wither(1000); }, 15e3);

    const wither = (code = 1000) => {
        if (!closed) {
            closed = !0; uq.clear();
            if (hsTimeout) { clearTimeout(hsTimeout); hsTimeout = 0; }
            try { rw.writer?.close(); } catch { }
            rl(rw.writer); f12(rw.socket);
            try { server.close(code, ""); } catch { }
        }
    };

    const sow = d => {
        const u = I(d);
        if (u.byteLength) {
            if (!uq.sow(u)) wither(1011);
            thresh();
        }
    };

    async function thresh() {
        if (!busy && !closed) {
            busy = !0;
            try {
                while (!closed) {
                    if (isDNS) {
                        const [d] = uq.bundle();
                        if (!d) break;
                        await f27_dns(d, server);
                        continue;
                    }
                    if (!rw.socket) {
                        const [d] = uq.bundle();
                        if (!d) break;
                        const sess = parseSession(d, pT);
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
                        
                        if (closed) { f12(sock); return; }

                        rw.socket = sock;
                        rw.writer = sock.writable.getWriter();
                        
                        mill(sock.readable, server, ssEngine, 3 !== pT).catch(() => { });
                        
                        const [first] = uq.bundle(sess.payload);
                        if (first?.byteLength) await rw.writer.write(first);
                        continue;
                    }
                    const [d] = uq.bundle();
                    if (!d) break;
                    await rw.writer.write(d);
                }
            } catch { wither(1011); } finally { busy = !1; !uq.empty && !closed && thresh(); }
        }
    }

    let initBuffer = null;
    const onMessage = data => {
        if (closed) return;
        let u = I(data);
        if (!u.byteLength) return;

        if (!pT) {
            initBuffer = initBuffer?.byteLength ? cat(initBuffer, u) : u;
            const t = sniffWS(initBuffer);
            if (!t) return;
            pT = t; u = initBuffer; initBuffer = null;
            if (hsTimeout) { clearTimeout(hsTimeout); hsTimeout = 0; }
        }

        if (1 === pT || 2 === pT) {
            sow(u);
        } else {
            if (++pendingPkt > CFG.upNMax) return wither(1011);
            ssPromise = ssPromise.then(async () => {
                if (!closed) {
                    try {
                        if (await ssEngine.decData(u, chunk => {
                            if (chunk.byteLength) if(!uq.sow(chunk)) wither(1011);
                        })) return void wither(1011);
                        thresh();
                    } catch { wither(1011); } finally { pendingPkt--; }
                }
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
            return new Response("OK", { status: 200 });
        }
        let cfg = parsePathConfig(u);
        let pParamInput = cfg.proxy || u.searchParams.get("proxyip");
        let proxyIPPool = [];
        if (pParamInput) proxyIPPool.push(pParamInput);
        if (PIP) proxyIPPool.push(PIP);
        const dynamicProxy = req.cf?.colo ? `${req.cf.colo}.proxy.example.net:443` : null;
        if (dynamicProxy) proxyIPPool.push(dynamicProxy);
        if (isWS) return await handleWS(req, proxyIPPool);
        if (isXHTTP) return await handleXHTTP(req, proxyIPPool);
        return new Response(null, { status: 204 });
    }
};

const mill = async (rd, ws, ss, isRaw) => { let r, ib = !1; try { r = rd.getReader({ mode: "byob" }), ib = !0; } catch { r = rd.getReader(); } if (!isRaw) { const tx = mkDn(ws, ss); let buf = new ArrayBuffer(CFG.chunk); try { if (ib) for (; ;) { const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk)); if (done) break; v?.byteLength && (v.byteLength >= CFG.chunk >> 1 ? (tx.reap(), tx.fastSend(v), buf = new ArrayBuffer(CFG.chunk)) : (tx.send(v.slice()), buf = v.buffer)); } else for (; ;) { const { done, value: v } = await r.read(); if (done) break; v?.byteLength && (v.byteLength >= CFG.chunk >> 1 ? (tx.reap(), tx.fastSend(v)) : tx.send(v)); } tx.reap(); } catch { } finally { try { tx.reap(); } catch { } try { r.releaseLock(); } catch { } } return; } const cap = CFG.dnPack, chk = CFG.chunk, tiny = 4096, d2 = chk << 1, dMax = cap - chk; let vBuf = new Uint8Array(cap), xBuf = new ArrayBuffer(chk), cur = 0, tm = null, lk = !1, fl = !1, sh = !1, low = !0; const reapRaw = () => { if (lk) return void (fl = !0); if (low = cur < d2, cur && ws.readyState === WebSocket.OPEN) { ws.send(vBuf.subarray(0, cur)); cur = 0; } fl = !1, sh = !1, tm && (clearTimeout(tm), tm = null); }; try { if (ib) for (; ;) { const d = cur > 0 && sh; lk = cur > 0 && !d; const { done: dn, value: q } = await r.read(new Uint8Array(d ? xBuf : vBuf.buffer, d ? 0 : cur, chk)); if (lk = !1, dn) break; if (d) vBuf.set(q, cur), xBuf = q.buffer; else { if (!cur && q.byteLength >= chk >> 1) { ws.readyState === WebSocket.OPEN && ws.send(q), vBuf = new Uint8Array(cap); continue; } vBuf = new Uint8Array(q.buffer); } const len = q.byteLength; if (!len) { fl && reapRaw(); continue; } cur += len, fl || len < tiny ? reapRaw() : (tm ||= setTimeout(reapRaw, low || len < 28672 ? CFG.dnMs : CFG.dnMs << 1), sh = len < chk, cur > dMax && reapRaw()); } else for (; ;) { const { done: dn, value: q } = await r.read(); if (dn) break; const b = q ? I(q) : v_b0; if (!b.byteLength) continue; if (!cur && b.byteLength >= chk >> 1) { ws.readyState === WebSocket.OPEN && ws.send(b); continue; } if (cur + b.byteLength > cap && reapRaw(), cur + b.byteLength > cap) { ws.readyState === WebSocket.OPEN && ws.send(b); continue; } vBuf.set(b, cur), cur += b.byteLength, b.byteLength < tiny ? reapRaw() : (tm ||= setTimeout(reapRaw, CFG.dnMs), cur > dMax && reapRaw()); } } catch { } finally { try { reapRaw(); } catch { } try { r.releaseLock(); } catch { } } };
const mkDn = (ws, ss) => { const cap = CFG.dnPack, tail = 28672, k = mkK(cap, 1); let tp = 0, q = [], busy = !1; const pushTx = r => { q.push(r); (async () => { if (!busy) { busy = !0; try { while (q.length > 0) { const item = q.shift(), encData = await ss.encData(item); if (ws.readyState === WebSocket.OPEN) ws.send(encData); } } catch { } finally { busy = !1; } } })(); }; const reap = () => { tp && clearTimeout(tp), tp = 0; for (; ;) { const [u] = k.pack(); if (!u) break; pushTx(u); } }; return { send(u) { let o = 0, n = u?.byteLength || 0; if (n) while (o < n) { const m = Math.min(cap - k.b, n - o); m ? (k.sow(o || m !== n ? u.subarray(o, o + m) : u), o += m, k.b >= cap || cap - k.b < tail ? reap() : tp ||= setTimeout(reap, CFG.dnMs)) : reap(); } }, fastSend(u) { u?.byteLength && pushTx(u); }, reap: reap }; };
