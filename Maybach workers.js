// ==========================================
// 代码名称：GrainTCP+CM+XHTTP+jaclbax
// 版本号：v1.3.4
// 生成时间：2026-08-21 15:50:12 (北京时间)
// 简要说明：同步 ToiCF/GrainTCP 最新主线架构，深度融合 jacobax 核心，重构 XHTTP extra 复合结构与默认路径
// ==========================================
import { connect } from 'cloudflare:sockets';

const te = new TextEncoder();
const td = new TextDecoder();

const myID = '00000000-0000-4000-b000-000000000000';

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

// XHTTP 混淆配置
const padHeader = myID.slice(1, 7);
const padKey = '_' + myID.slice(25, 31);
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

// ================= jacobax 最新优化核心引擎与密码学模块 =================
const v1 = PIP, v2 = myID; 
const CFG = { chunk: 131072, dnPack: 262144, dnTail: 2048, dnMs: 2, dnQr: 0, upPack: 65536, upQMax: 2097152, upNMax: 256, maxED: 8192, hsMax: 16384, connMs: 2000, xhInit: 8192, xhNext: 4096 }; 
const c_map = new Map, c_run = new Map, c_max = 400, c_ttl = 18e4;
let v3 = null, v4 = null, v_pk = null, v_pv = null, v_mk = null;
const r_ip = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const r_ip6 = /^\[?([a-fA-F0-9:]+)\]?$/, v_b0 = new Uint8Array(0), dec = new TextDecoder, enc = new TextEncoder;
const v_v10 = new Uint8Array([33, 18, 164, 66]), v_z20 = new Uint8Array(20), v_ssinf = enc.encode("ss-subkey");
const hex = c => (c > 64 ? c + 9 : c) & 15, idB = new Uint8Array(16); for (let i = 0, p = 0; i < 16; i++) { let c1 = v2.charCodeAt(p++); if (c1 === 45) c1 = v2.charCodeAt(p++); let c2 = v2.charCodeAt(p++); if (c2 === 45) c2 = v2.charCodeAt(p++); idB[i] = hex(c1) << 4 | hex(c2) }
const matchID = c => c[1] === idB[0] && c[2] === idB[1] && c[3] === idB[2] && c[4] === idB[3] && c[5] === idB[4] && c[6] === idB[5] && c[7] === idB[6] && c[8] === idB[7] && c[9] === idB[8] && c[10] === idB[9] && c[11] === idB[10] && c[12] === idB[11] && c[13] === idB[12] && c[14] === idB[13] && c[15] === idB[14] && c[16] === idB[15];
const cat = (...xs) => { const r = new Uint8Array(xs.reduce((n, x) => n + x.length, 0)); let o = 0; for (const x of xs) r.set(x, o), o += x.length; return r };
const f1 = s => enc.encode(s);
const f3 = (b, o) => b[o] << 8 | b[o + 1];
const f4 = (b, o) => (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
const f5 = n => crypto.getRandomValues(new Uint8Array(n));
const f6 = () => f3(f5(2), 0);
const f7 = () => f4(f5(4), 0);
const f8 = ip => new Uint8Array(ip.split(".").map(Number));
const f9 = (d, o, n) => { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += f3(d, i); n & 1 && (s += d[o + n - 1] << 8); while (s >> 16) s = (s & 65535) + (s >> 16); return ~s & 65535 };
const rotl = (v, a) => v >>> a | v << 32 - a;
const f_auth = t => { const d = f1(t), K = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298], H = [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428]; const ml = d.length, pl = Math.ceil((ml + 9) / 64) * 64, p = new Uint8Array(pl); p.set(d); p[ml] = 128; const v = new DataView(p.buffer); v.setUint32(pl - 4, ml * 8, !1); for (let c = 0; c < pl; c += 64) { const W = new Uint32Array(64); for (let i = 0; i < 16; i++) W[i] = v.getUint32(c + i * 4, !1); for (let i = 16; i < 64; i++) { const s0 = rotl(W[i - 15], 7) ^ rotl(W[i - 15], 18) ^ W[i - 15] >>> 3, s1 = rotl(W[i - 2], 17) ^ rotl(W[i - 2], 19) ^ W[i - 2] >>> 10; W[i] = W[i - 16] + s0 + W[i - 7] + s1 >>> 0 } let [a, b, x, y, e, f, g, h] = H; for (let i = 0; i < 64; i++) { const S1 = rotl(e, 6) ^ rotl(e, 11) ^ rotl(e, 25), ch = e & f ^ ~e & g, t1 = h + S1 + ch + K[i] + W[i] >>> 0, S0 = rotl(a, 2) ^ rotl(a, 13) ^ rotl(a, 22), maj = a & b ^ a & x ^ b & x, t2 = S0 + maj >>> 0; h = g; g = f; f = e; e = y + t1 >>> 0; y = x; x = b; b = a; a = t1 + t2 >>> 0 } H[0] = H[0] + a >>> 0; H[1] = H[1] + b >>> 0; H[2] = H[2] + x >>> 0; H[3] = H[3] + y >>> 0; H[4] = H[4] + e >>> 0; H[5] = H[5] + f >>> 0; H[6] = H[6] + g >>> 0; H[7] = H[7] + h >>> 0 } let r = ""; for (let i = 0; i < 7; i++) r += (H[i] >>> 24 & 255).toString(16).padStart(2, "0") + (H[i] >>> 16 & 255).toString(16).padStart(2, "0") + (H[i] >>> 8 & 255).toString(16).padStart(2, "0") + (H[i] & 255).toString(16).padStart(2, "0"); return r };
const authHex = f_auth(v2), authBuf = new Uint8Array(56); for (let i = 0; i < 56; i++) authBuf[i] = authHex.charCodeAt(i);
function f11(s) { if (!s) return { earlyData: null, error: null }; try { let b = s.replace(/-/g, "+").replace(/_/g, "/"), mx = 4 * Math.ceil(CFG.maxED / 3); if (b.length > mx) throw 0; b += "====".slice(0, (4 - b.length % 4) % 4); const u = "function" == typeof Uint8Array.fromBase64 ? Uint8Array.fromBase64(b) : Uint8Array.from(atob(b), c => c.charCodeAt(0)); if (u.byteLength > CFG.maxED) throw 0; return { earlyData: u.buffer, error: null } } catch (e) { return { earlyData: null, error: e } } }
function f12(s) { try { (s?.readyState === WebSocket.OPEN || s?.readyState === WebSocket.CLOSING) && s.close(), s?.close && s.close() } catch { } }
function f13(s) { if (!s) return null; s = s.trim(); if (s.startsWith("turn://") || s.startsWith("turns://")) { try { const h = s.startsWith("turns://"), hasTag = /!ip(?:$|&)/i.test(s), u = new URL(s.replace(/!ip(?:$|&)/i, "")), c = h && (hasTag || r_ip.test(u.hostname) || r_ip6.test(u.hostname)); return { type: h ? "turns" : "turn", host: u.hostname, port: parseInt(u.port) || (h ? 5349 : 3478), username: u.username ? decodeURIComponent(u.username) : "", password: u.password ? decodeURIComponent(u.password) : "", isc: c } } catch { return null } } if (s.startsWith("sstp://")) { try { const u = new URL(s); return { type: "sstp", host: u.hostname, port: parseInt(u.port) || 443, username: u.username ? decodeURIComponent(u.username) : "vpn", password: u.password ? decodeURIComponent(u.password) : "vpn" } } catch { return null } } if (s.startsWith("socks://") || s.startsWith("socks5://")) { try { const u = new URL(s.replace(/^socks:\/\//, "socks5://")); return { type: "socks5", host: u.hostname, port: parseInt(u.port) || 1080, username: u.username ? decodeURIComponent(u.username) : "", password: u.password ? decodeURIComponent(u.password) : "" } } catch { return null } } if (s.startsWith("http://") || s.startsWith("https://")) { try { const h = s.startsWith("https://"), hasTag = /!ip(?:$|&)/i.test(s), u = new URL(s.replace(/!ip(?:$|&)/i, "")), c = hasTag || r_ip.test(u.hostname) || r_ip6.test(u.hostname); return { type: h ? "https" : "http", host: u.hostname, port: parseInt(u.port) || (h ? 443 : 80), username: u.username ? decodeURIComponent(u.username) : "", password: u.password ? decodeURIComponent(u.password) : "", isc: c } } catch { return null } } const m = s.match(/^\[([^\]]+)\](?::(\d+))?$/); if (m) { const p = parseInt(m[2], 10); return { type: "direct", host: m[1], port: !isNaN(p) && p > 0 ? p : 443 } } const i = s.lastIndexOf(":"); if (i > 0) { const h = s.substring(0, i), p = parseInt(s.substring(i + 1), 10); if (!isNaN(p) && p > 0 && p <= 65535) return { type: "direct", host: h, port: p } } return { type: "direct", host: s, port: 443 } }
async function f14(d, t) { const k = d + "_" + t, n = Date.now(), c = c_map.get(k); if (c) { if (n - c.time < c_ttl) return c.data; c_map.delete(k) } const old = c_run.get(k); if (old) return old; const j = (async () => { try { const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(d)}&type=${t}`, { headers: { Accept: "application/dns-json" } }); if (!r.ok) return []; const a = (await r.json()).Answer || []; if (a.length) { if (c_map.size >= c_max) c_map.delete(c_map.keys().next().value); c_map.set(k, { data: a, time: Date.now() }) } return a } catch { return [] } })(); c_run.set(k, j); try { return await j } finally { c_run.delete(k) } }
function f15(s) { let a = s, p = 443; const m = s.match(/^(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/); return m && (a = m[1] || m[2], p = m[3] ? parseInt(m[3], 10) : 443), [a, p] }
async function f16(s, d = "dash.cloudflare.com", u = "00000000-0000-4000-8000-000000000000") { const r = s.trim(), ck = r + "\0" + d + "\0" + u; if (v3 === ck && v4) return v4; const t = r.toLowerCase().endsWith("!txt"), tg = t ? r.slice(0, -4).trim() : r; let a = []; if (t) { const z = await f14(tg, "TXT"), x = z.filter(x => 16 === x.type).map(x => x.data); if (x.length) a = x.map(x => x.replace(/"/g, "")).join(",").replace(/[\r\n\s]+/g, ",").split(",").map(x => x.trim()).filter(Boolean).map(f15) } else { a = [f15(tg)] } const rt = d.includes(".") ? d.split(".").slice(-2).join(".") : d; let sd = [...rt + u].reduce((a, c) => a + c.charCodeAt(0), 0); v4 = [...a.sort((a, b) => a[0].localeCompare(b[0]))].sort(() => (sd = 1103515245 * sd + 12345 & 2147483647, sd / 2147483647 - .5)).slice(0, 8); v3 = ck; return v4 }
const f17 = (u, p) => { let b = v_b0, i = 1, sk, rd, wr, h, rb = new ArrayBuffer(16384); const fn1 = async n => { if (b.length >= n) { const r = b.subarray(0, n); return b = b.subarray(n), r } const sv = b.length > 0 ? new Uint8Array(b) : null, nd = n - b.length, { value: v, done: d } = await rd.readAtLeast(nd, new Uint8Array(rb)); if (d) throw 0; let t; return rb = v.buffer, sv ? (t = cat(sv, v), b = t.subarray(n), t.subarray(0, n)) : (b = v.subarray(n), v.subarray(0, n)) }; const fn2 = async () => { for (; ;) { const x = b.indexOf(10); if (x >= 0) { let l = dec.decode(b.subarray(0, x)); return b = b.subarray(x + 1), l.replace(/\r$/, "") } const sv = b.length > 0 ? new Uint8Array(b) : null, { value: v, done: d } = await rd.readAtLeast(1, new Uint8Array(rb)); if (d) throw 0; rb = v.buffer, b = sv ? cat(sv, v) : v } }; const fn3 = async (m = 1e4) => { let t; const to = new Promise((_, r) => { t = setTimeout(() => r("T"), m) }); twilight: try { const hd = await Promise.race([fn1(4), to]); clearTimeout(t); const l = f3(hd, 2) & 4095; return { ctrl: 1 == (1 & hd[1]), body: l > 4 ? await fn1(l - 4) : v_b0 } } catch (e) { throw clearTimeout(t), e } }; const fn4 = f => { const n = 6 + f.length, q = new Uint8Array(n); return q.set([16, 0, n >> 8 & 15 | 128, 255 & n, 255, 3]), q.set(f, 6), q }; const fn5 = (m, a = []) => { const l = a.reduce((s, x) => s + 4 + x.data.length, 0), q = new Uint8Array(8 + l), vw = new DataView(q.buffer); return q[0] = 16, q[1] = 1, vw.setUint16(2, 8 + l | 32768), vw.setUint16(4, m), vw.setUint16(6, a.length), a.reduce((o, x) => (q[o + 1] = x.id, vw.setUint16(o + 2, 4 + x.data.length), q.set(x.data, o + 4), o + 4 + x.data.length), 8), q }; const fn6 = (pt, c, id, op = []) => { const l = op.reduce((s, x) => s + 2 + x.data.length, 0), f = new Uint8Array(6 + l), vw = new DataView(f.buffer); return vw.setUint16(0, pt), f[2] = c, f[3] = id, vw.setUint16(4, 4 + l), op.reduce((o, x) => (f[o] = x.type, f[o + 1] = 2 + x.data.length, f.set(x.data, o + 2), o + 2 + x.data.length), 6), f }; const fn7 = id => { const ub = f1(u), pb = f1(p), ul = ub.length, pl = pb.length, tl = 6 + ul + pl, f = new Uint8Array(2 + tl), vw = new DataView(f.buffer); return vw.setUint16(0, 49187), f[2] = 1, f[3] = id, vw.setUint16(4, tl), f[6] = ul, f.set(ub, 7), f[7 + ul] = pl, f.set(pb, 8 + ul), f }; const fn8 = d => { let o = d.length >= 2 && 255 === d[0] && 3 === d[1] ? 2 : 0; if (d.length - o < 4) return null; const pt = f3(d, o); return 33 === pt ? { protocol: pt, ip: d.subarray(o + 2) } : d.length - o >= 6 ? { protocol: pt, code: d[o + 2], id: d[o + 3], payload: d.subarray(o + 6), raw: d.subarray(o) } : null }; const fn9 = d => { const r = []; for (let j = 0; j + 2 <= d.length;) { const t = d[j], l = d[j + 1]; if (l < 2 || j + l > d.length) break; r.push({ type: t, data: d.subarray(j + 2, j + l) }), j += l } return r }; const fn10 = async (hs, pt) => { sk = connect({ hostname: hs, port: pt }, { secureTransport: "on" }), await sk.opened, rd = sk.readable.getReader({ mode: "byob" }), wr = sk.writable.getWriter(), h = hs }; const fn11 = async () => { const ht = f1(`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: ${h}\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`); const pa = new Uint8Array(2); new DataView(pa.buffer).setUint16(0, 1); const mu = new Uint8Array(2); new DataView(mu.buffer).setUint16(0, 1500); await wr.write(cat(ht, fn5(1, [{ id: 1, data: pa }]), fn4(fn6(49185, 1, i++, [{ type: 1, data: mu }])))); const st = await fn2(); for (; "" !== await fn2();); if (!st.includes("200")) throw 0; let sa = !1, ld = !1, au = !1, dn = !1, mi = null; for (let j = 0; j < 25 && !dn; j++) { const pk = await fn3(); if (pk.ctrl) sa || pk.body.length < 2 || 2 !== f3(pk.body, 0) || (sa = !0); else { const pp = fn8(pk.body); if (pp) if (49185 === pp.protocol) if (1 === pp.code) { const a = new Uint8Array(pp.raw); a[2] = 2, await wr.write(ld && !au ? cat(fn4(a), fn4(fn7(i++))) : fn4(a)), ld && (au = !0) } else 2 === pp.code && (ld = !0, au || (await wr.write(fn4(fn7(i++))), au = !0)); else if (49187 === pp.protocol && 2 === pp.code) await wr.write(fn4(fn6(32801, 1, i++, [{ type: 3, data: new Uint8Array(4) }]))); else if (32801 === pp.protocol) if (1 === pp.code) { const a = new Uint8Array(pp.raw); a[2] = 2, await wr.write(fn4(a)) } else if (3 === pp.code) { const o = fn9(pp.payload).find(x => 3 === x.type); o && (mi = [...o.data].join("."), await wr.write(fn4(fn6(32801, 1, i++, [{ type: 3, data: o.data }])))) } else if (2 === pp.code) { const o = fn9(pp.payload).find(x => 3 === x.type); o && (mi = [...o.data].join("."), dn = !0) } } } if (!mi) throw 0; return mi }; return { connect: fn10, establish: fn11, readPkt: fn3, parsePPP: fn8, get buf() { return b }, get wr() { return wr }, close: () => [rd, wr, sk].forEach(x => { try { x?.cancel?.() ?? x?.close?.() } catch { } }) } };
const f18 = (s, si, di, dp) => { const sp = 1e4 + f6() % 5e4, sb = f8(si), db = f8(di); let sq = f7(), ak = 0; const it = new Uint8Array(20); it.set([69, 0, 0, 0, 0, 0, 64, 0, 64, 6]), it.set(sb, 12), it.set(db, 16); const ps = new Uint8Array(1432); ps.set(sb), ps.set(db, 4), ps[9] = 6; const fn1 = (fl, d = v_b0) => { const pl = d.length, tl = 20 + pl, il = 20 + tl, st = 8 + il, f = new Uint8Array(st), vw = new DataView(f.buffer); return f.set([16, 0, st >> 8 & 15 | 128, 255 & st, 255, 3, 0, 33]), f.set(it, 8), vw.setUint16(10, il), vw.setUint16(12, f6()), vw.setUint16(18, f9(f, 8, 20)), vw.setUint16(28, sp), vw.setUint16(30, dp), vw.setUint32(32, sq), vw.setUint32(36, ak), f[40] = 80, f[41] = fl, vw.setUint16(42, 65535), pl && f.set(d, 48), ps[10] = tl >> 8, ps[11] = 255 & tl, ps.set(f.subarray(28, 28 + tl), 12), vw.setUint16(44, f9(ps, 0, 12 + tl)), f }; const fn2 = ip => { if (ip.length < 40 || 6 !== ip[9]) return null; const hl = 4 * (15 & ip[0]); return f3(ip, hl) !== dp || f3(ip, hl + 2) !== sp ? null : { flags: ip[hl + 13], seq: f4(ip, hl + 4), off: hl + 4 * (ip[hl + 12] >> 4 & 15) } }; const fn3 = async () => { await s.wr.write(fn1(2)), sq++; for (let j = 0; j < 30; j++) { const pk = await s.readPkt(); if (!pk.ctrl) { const pp = s.parsePPP(pk.body); if (pp && 33 === pp.protocol) { const m = fn2(pp.ip); if (m && 18 === (18 & m.flags)) return ak = m.seq + 1 >>> 0, s.wr.write(fn1(16)), !0 } } } throw 0 }; return { frame: fn1, match: fn2, handshake: fn3, get seq() { return sq }, set seq(v) { sq = v }, get ack() { return ak }, set ack(v) { ak = v } } };
const f19 = async ({ host: h, port: p, username: u, password: pw }, ip, tp) => { const s = f17(u, pw), cl = () => s.close(); try { await s.connect(h, p); const [mi, ti] = await Promise.all([s.establish(), ip]); if (!ti) return cl(), null; const t = f18(s, mi, ti, tp); await t.handshake(); let cr = null; const rd = new ReadableStream({ start: c => { cr = c }, cancel: cl }); (async () => { try { let pd = [], pl = 0; const fl = () => { pl && (cr.enqueue(1 === pd.length ? pd[0] : cat(...pd)), pd = [], pl = 0, s.wr.write(t.frame(16)).catch(() => { })) }; for (; ;) { const pk = await s.readPkt(6e4); if (!pk.ctrl) { const pp = s.parsePPP(pk.body); if (pp && 33 === pp.protocol) { const m = t.match(pp.ip); if (m) { if (m.off < pp.ip.length) { const d = pp.ip.subarray(m.off); d.length && (t.ack = m.seq + d.length >>> 0, pd.push(new Uint8Array(d)), pl += d.length) } if (1 & m.flags) return fl(), t.ack = t.ack + 1 >>> 0, s.wr.write(t.frame(17)).catch(() => { }), void cr.close(); (s.buf.length < 4 || pl >= 32768) && fl() } } } } } catch { try { cr.close() } catch { } } })(); return { readable: rd, writable: new WritableStream({ async write(c) { const d = c instanceof Uint8Array ? c : new Uint8Array(c); if (d.length <= 1400) return await s.wr.write(t.frame(24, d)), void (t.seq = t.seq + d.length >>> 0); const fs = []; for (let o = 0; o < d.length; o += 1400) { const sg = d.subarray(o, Math.min(o + 1400, d.length)); fs.push(t.frame(24, sg)), t.seq = t.seq + sg.length >>> 0 } await s.wr.write(cat(...fs)) }, close: () => s.wr.write(t.frame(17)).catch(() => { }), abort: cl }), close: cl } } catch { return cl(), null } };
async function f20({ host: h, port: p, username: u, password: pw }, th, tp) { let sk; try { sk = connect({ hostname: h, port: p }); const wr = sk.writable.getWriter(), rd = sk.readable.getReader(), am = u && pw ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]); await wr.write(am); const mr = await rd.read(); if (mr.done || mr.value.byteLength < 2) throw 0; const sm = new Uint8Array(mr.value)[1]; if (2 === sm) { const ub = f1(u), pb = f1(pw), ap = new Uint8Array(3 + ub.length + pb.length); ap[0] = 1, ap[1] = ub.length, ap.set(ub, 2), ap[2 + ub.length] = pb.length, ap.set(pb, 3 + ub.length), await wr.write(ap); const ar = await rd.read(); if (ar.done || 0 !== new Uint8Array(ar.value)[1]) throw 0 } else if (0 !== sm) throw 0; const hb = f1(th), cp = new Uint8Array(7 + hb.length); cp.set([5, 1, 0, 3, hb.length]), cp.set(hb, 5), new DataView(cp.buffer).setUint16(5 + hb.length, tp, !1), await wr.write(cp); const cr = await rd.read(); if (cr.done || 0 !== new Uint8Array(cr.value)[1]) throw 0; return wr.releaseLock(), rd.releaseLock(), sk } catch (e) { throw f12(sk), e } }
const { TlsClient } = (() => { const e = 769, t = 771, n = 772, r = 20, i = 21, s = 22, a = 23, h = 1, c = 2, o = 4, l = 8, f = 11, u = 12, y = 13, p = 14, w = 15, d = 16, g = 20, k = 24, v = 0, A = 10, S = 11, m = 13, b = 16, C = 43, H = 45, T = 51, E = 0, L = new TextEncoder, K = new TextDecoder, P = new Uint8Array(0), U = new Map(Object.entries({ TLS_AES_128_GCM_SHA256: { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }, TLS_AES_256_GCM_SHA384: { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }, TLS_CHACHA20_POLY1305_SHA256: { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 } }).map(([, e]) => [e.id, e])), I = new Map([[29, "X25519"], [23, "P-256"]]), x = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539], _ = (...e) => { const t = e => { const n = []; for (const r of e) r instanceof Uint8Array ? n.push(...r) : Array.isArray(r) ? n.push(...t(r)) : "number" == typeof r && n.push(r); return n }; return new Uint8Array(t(e)) }, B = e => [e >> 8 & 255, 255 & e], R = (e, t) => e[t] << 8 | e[t + 1], M = (e, t) => e[t] << 16 | e[t + 1] << 8 | e[t + 2], W = (...e) => { const t = e.filter(e => e && e.length > 0), n = t.reduce((e, t) => e + t.length, 0), r = new Uint8Array(n); let i = 0; for (const e of t) r.set(e, i), i += e.length; return r }, D = e => crypto.getRandomValues(new Uint8Array(e)), N = (e, t) => { if (!e || !t || e.length !== t.length) return !1; let n = 0; for (let r = 0; r < e.length; r++) n |= e[r] ^ t[r]; return 0 === n }, q = e => "SHA-512" === e ? 64 : "SHA-384" === e ? 48 : 32; async function $(e, t, n) { const r = await crypto.subtle.importKey("raw", t, { name: "HMAC", hash: e }, !1, ["sign"]); return new Uint8Array(await crypto.subtle.sign("HMAC", r, n)) } async function G(e, t) { return new Uint8Array(await crypto.subtle.digest(e, t)) } async function V(e, t, n, r, i = "SHA-256") { const s = W(L.encode(t), n); let a = new Uint8Array(0), h = s; for (; a.length < r;) { h = await $(i, e, h); const t = await $(i, e, W(h, s)); a = W(a, t) } return a.slice(0, r) } async function X(e, t, n) { return t && t.length || (t = new Uint8Array(q(e))), $(e, t, n) } async function O(e, t, n, r, i) { const s = L.encode("tls13 " + n); return async function (e, t, n, r) { const i = q(e), s = Math.ceil(r / i); let a = new Uint8Array(0), h = new Uint8Array(0); for (let r = 1; r <= s; r++) h = await $(e, t, W(h, n, [r])), a = W(a, h); return a.slice(0, r) }(e, t, _(B(i), s.length, s, r.length, r), i) } async function F(e = "P-256") { if ("X25519" === e) { const e = await crypto.subtle.generateKey({ name: "X25519" }, !0, ["deriveBits"]); return { kp: e, pk: new Uint8Array(await crypto.subtle.exportKey("raw", e.publicKey)) } } const t = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: e }, !0, ["deriveBits"]); return { kp: t, pk: new Uint8Array(await crypto.subtle.exportKey("raw", t.publicKey)) } } async function Y(e, t, n = "P-256") { if ("X25519" === n) { const n = await crypto.subtle.importKey("raw", t, { name: "X25519" }, !1, []); return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: n }, e, 256)) } const r = await crypto.subtle.importKey("raw", t, { name: "ECDH", namedCurve: n }, !1, []), i = "P-384" === n ? 384 : "P-521" === n ? 528 : 256; return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: r }, e, i)) } async function j(e, t, n, r) { const i = await crypto.subtle.importKey("raw", e, { name: "AES-GCM" }, !1, ["encrypt"]); return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: t, additionalData: r, tagLength: 128 }, i, n)) } async function z(e, t, n, r) { const i = await crypto.subtle.importKey("raw", e, { name: "AES-GCM" }, !1, ["decrypt"]); return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: t, additionalData: r, tagLength: 128 }, i, n)) } function J(e, t) { return (e << t | e >>> 32 - t) >>> 0 } function Q(e, t, n, r, i) { e[t] = e[t] + e[n] >>> 0, e[i] = J(e[i] ^ e[t], 16), e[r] = e[r] + e[i] >>> 0, e[n] = J(e[n] ^ e[r], 12), e[t] = e[t] + e[n] >>> 0, e[i] = J(e[i] ^ e[t], 8), e[r] = e[r] + e[i] >>> 0, e[n] = J(e[n] ^ e[r], 7) } function Z(e, t, n) { const r = new Uint32Array(16); r[0] = 1634760805, r[1] = 857760878, r[2] = 2036477234, r[3] = 1797285236; const i = new DataView(e.buffer, e.byteOffset, e.byteLength); for (let e = 0; e < 8; e++) r[4 + e] = i.getUint32(4 * e, !0); r[12] = t; const s = new DataView(n.buffer, n.byteOffset, n.byteLength); r[13] = s.getUint32(0, !0), r[14] = s.getUint32(4, !0), r[15] = s.getUint32(8, !0); const a = new Uint32Array(r); for (let e = 0; e < 10; e++) Q(a, 0, 4, 8, 12), Q(a, 1, 5, 9, 13), Q(a, 2, 6, 10, 14), Q(a, 3, 7, 11, 15), Q(a, 0, 5, 10, 15), Q(a, 1, 6, 11, 12), Q(a, 2, 7, 8, 13), Q(a, 3, 4, 9, 14); for (let e = 0; e < 16; e++) a[e] = a[e] + r[e] >>> 0; return new Uint8Array(a.buffer.slice(0)) } function ee(e, t, n) { const r = new Uint8Array(n.length); let i = 1; for (let s = 0; s < n.length; s += 64) { const a = Z(e, i++, t), h = Math.min(64, n.length - s); for (let e = 0; e < h; e++) r[s + e] = n[s + e] ^ a[e] } return r } function te(e, t) { const n = function (e) { const t = new Uint8Array(e); return t[3] &= 15, t[7] &= 15, t[11] &= 15, t[15] &= 15, t[4] &= 252, t[8] &= 252, t[12] &= 252, t }(e.slice(0, 16)), r = e.slice(16, 32); let i = [0n, 0n, 0n, 0n, 0n]; const s = [0x3ffffffn & BigInt(n[0] | n[1] << 8 | n[2] << 16 | n[3] << 24), 0x3ffffffn & BigInt(n[3] >> 2 | n[4] << 6 | n[5] << 14 | n[6] << 22), 0x3ffffffn & BigInt(n[6] >> 4 | n[7] << 4 | n[8] << 12 | n[9] << 20), 0x3ffffffn & BigInt(n[9] >> 6 | n[10] << 2 | n[11] << 10 | n[12] << 18), 0x3ffffffn & BigInt(n[13] | n[14] << 8 | n[15] << 16 | n[16] << 24)]; for (let e = 0; e < t.length; e += 16) { const n = t.slice(e, e + 16), r = new Uint8Array(17); r.set(n), r[n.length] = 1, i[0] += BigInt(r[0] | r[1] << 8 | r[2] << 16 | (3 & r[3]) << 24), i[1] += BigInt(r[3] >> 2 | r[4] << 6 | r[5] << 14 | (15 & r[6]) << 22), i[2] += BigInt(r[6] >> 4 | r[7] << 4 | r[8] << 12 | (63 & r[9]) << 20), i[3] += BigInt(r[9] >> 6 | r[10] << 2 | r[11] << 10 | r[12] << 18), i[4] += BigInt(r[13] | r[14] << 8 | r[15] << 16 | r[16] << 24); const a = [0n, 0n, 0n, 0n, 0n]; for (let e = 0; e < 5; e++) for (let t = 0; t < 5; t++) { const n = e + t; n < 5 ? a[n] += i[e] * s[t] : a[n - 5] += i[e] * s[t] * 5n } let h = 0n; for (let e = 0; e < 5; e++) a[e] += h, i[e] = 0x3ffffffn & a[e], h = a[e] >> 26n; i[0] += 5n * h, h = i[0] >> 26n, i[0] &= 0x3ffffffn, i[1] += h } let a = i[0] | i[1] << 26n | i[2] << 52n | i[3] << 78n | i[4] << 104n; a = a + r.reduce((e, t, n) => e + (BigInt(t) << BigInt(8 * n)), 0n) & (1n << 128n) - 1n; const h = new Uint8Array(16); for (let e = 0; e < 16; e++) h[e] = Number(a >> BigInt(8 * e) & 0xffn); return h } function ne(e, t, n, r) { const i = Z(e, 0, t).slice(0, 32), s = ee(e, t, n), a = (16 - r.length % 16) % 16, h = (16 - s.length % 16) % 16, c = new Uint8Array(r.length + a + s.length + h + 16); c.set(r, 0), c.set(s, r.length + a); const o = new DataView(c.buffer, r.length + a + s.length + h); o.setBigUint64(0, BigInt(r.length), !0), o.setBigUint64(8, BigInt(s.length), !0); const l = te(i, c); return W(s, l) } function re(e, t, n, r) { if (n.length < 16) throw 0; const i = n.slice(-16), s = n.slice(0, -16), a = Z(e, 0, t).slice(0, 32), h = (16 - r.length % 16) % 16, c = (16 - s.length % 16) % 16, o = new Uint8Array(r.length + h + s.length + c + 16); o.set(r, 0), o.set(s, r.length + h); const l = new DataView(o.buffer, r.length + h + s.length + c); l.setBigUint64(0, BigInt(r.length), !0), l.setBigUint64(8, BigInt(s.length), !0); const f = te(a, o); let u = 0; for (let e = 0; e < 16; e++) u |= i[e] ^ f[e]; if (0 !== u) throw 0; return ee(e, t, s) } function ie(e, n, r = t) { return _(e, B(r), B(n.length), n) } function se(e, t) { return _(e, (e => [e >> 16 & 255, e >> 8 & 255, 255 & e])(t.length), t) } class ae { constructor() { this.b = new Uint8Array(0) } feed(e) { this.b = W(this.b, e) } next() { if (this.b.length < 5) return null; const e = this.b[0], t = R(this.b, 1), n = R(this.b, 3); if (this.b.length < 5 + n) return null; const r = this.b.slice(5, 5 + n); return this.b = this.b.slice(5 + n), { type: e, version: t, length: n, fragment: r } } } class he { constructor() { this.b = new Uint8Array(0) } feed(e) { this.b = W(this.b, e) } next() { if (this.b.length < 4) return null; const e = this.b[0], t = M(this.b, 1); if (this.b.length < 4 + t) return null; const n = this.b.slice(4, 4 + t), r = this.b.slice(0, 4 + t); return this.b = this.b.slice(4 + t), { type: e, length: t, body: n, raw: r } } } function ce(e) { let t = 0; const r = R(e, t); t += 2; const i = e.slice(t, t + 32); t += 32; const s = e[t++], a = e.slice(t, t + s); t += s; const h = R(e, t); t += 2; const c = e[t++]; let o = r, l = null, f = null; if (t < e.length) { const n = R(e, t); t += 2; const r = t + n; for (; t + 4 <= r;) { const n = R(e, t); t += 2; const r = R(e, t); t += 2; const i = e.slice(t, t + r); if (t += r, n === C && r >= 2) o = R(i, 0); else if (n === T && r >= 4) { const e = R(i, 0), t = R(i, 2); l = { group: e, key: i.slice(4, 4 + t) } } else n === b && r >= 3 && (f = K.decode(i.slice(3, 3 + i[2]))) } } const u = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]); return { version: r, sr: i, sid: a, cs: h, comp: c, sv: o, ks: l, alpn: f, isHRR: N(i, u), isTls13: o === n } } function oe(e) { let t = 0; t++; const n = R(e, t); t += 2; const r = e[t++]; return { nc: n, spk: e.slice(t, t + r) } } function le(e, t = 0) { let n = 0; if (t) { const t = e[n++]; n += t } if (n + 3 > e.length) return null; const r = M(e, n); if (n += 3, !r || n + 3 > e.length) return null; const i = M(e, n); return n += 3, i ? e.slice(n, n + i) : null } function fe(e) { const t = { alpn: null }; let n = 2; const r = 2 + R(e, 0); for (; n + 4 <= r;) { const r = R(e, n); n += 2; const i = R(e, n); if (n += 2, r === b && i >= 3) { const r = e[n + 2]; r > 0 && n + 3 + r <= n + i && (t.alpn = K.decode(e.slice(n + 3, n + 3 + r))) } n += i } return t } const F0 = e => { if (e = String(e ?? "").trim(), "[" === e[0] && "]" === e[e.length - 1] && (e = e.slice(1, -1)), !e || e.includes(":")) return ""; const t = e.split("."); if (4 !== t.length) return e; for (const n of t) { if ("" === n || n.length > 3) return e; let t = 0; for (let r = 0; r < n.length; r++) { const i = n.charCodeAt(r) - 48; if (i < 0 || i > 9) return e; t = 10 * t + i } if (t > 255) return e } return "" }, Z0 = e => e && 1 === e[0] && 112 === e[1]; function ue(e, n, r, { tls13: i = !0, tls12: s = !0, alpn: a = null } = {}) { n = F0(n); const c = []; i && c.push(4865, 4866, 4867), s && c.push(49199, 49200, 52392, 49195, 49196, 52393); const o = _(...c.flatMap(B)), l = [_(255, 1, 0, 1, 0)]; if (n) { const e = L.encode(n), t = _(0, B(e.length), e); l.push(_(B(v), B(t.length + 2), B(t.length), t)) } l.push(_(B(S), 0, 2, 1, 0)), l.push(_(B(A), 0, 6, 0, 4, 0, 29, 0, 23)); const f = _(...x.flatMap(B)); l.push(_(B(m), B(f.length + 2), B(f.length), f)); const u = Array.isArray(a) ? a.filter(Boolean) : a ? [a] : []; if (u.length) { const e = W(...u.map(e => { const t = L.encode(e); return _(t.length, t) })); l.push(_(B(b), B(e.length + 2), B(e.length), e)) } if (i && r) { let e; if (l.push(s ? _(B(C), 0, 5, 4, 3, 4, 3, 3) : _(B(C), 0, 3, 2, 3, 4)), l.push(_(B(H), 0, 2, 1, 1)), r?.x25519 && r?.p256) e = W(_(0, 29, B(r.x25519.length), r.x25519), _(0, 23, B(r.p256.length), r.p256)); else if (r?.x25519) e = _(0, 29, B(r.x25519.length), r.x25519); else if (r?.p256) e = _(0, 23, B(r.p256.length), r.p256); else { if (!(r instanceof Uint8Array)) throw 0; e = _(0, 23, B(r.length), r) } l.push(_(B(T), B(e.length + 2), B(e.length), e)) } const y = W(...l); return se(h, _(B(t), e, 0, B(o.length), o, 1, 0, B(y.length), y)) } const ye = e => { const t = new Uint8Array(8); return new DataView(t.buffer).setBigUint64(0, e, !1), t }, pe = (e, t) => { const n = e.slice(), r = ye(t); for (let e = 0; e < 8; e++) n[n.length - 8 + e] ^= r[e]; return n }, we = (e, t, n, r) => Promise.all([O(e, t, "key", P, n), O(e, t, "iv", P, r)]); class TlsClient { constructor(e, t = {}) { if (this.sk = e, this.sn = t.serverName || "", this.s13 = !1 !== t.tls13, this.s12 = !1 !== t.tls12, !this.s13 && !this.s12) throw 0; this.alpn = Array.isArray(t.alpn) ? t.alpn : t.alpn ? [t.alpn] : null, this.to = t.timeout ?? 3e4, this.cr = D(32), this.sr = null, this.hk = [], this.hc = !1, this.na = null, this.cs = null, this.cc = null, this.is13 = !1, this.ms = null, this.hs = null, this.cwk = null, this.swk = null, this.cwi = null, this.swi = null, this.chk = null, this.shk = null, this.chi = null, this.shi = null, this.cak = null, this.sak = null, this.cai = null, this.sai = null, this.csn = 0n, this.ssn = 0n, this.rp = new ae, this.hp = new he, this.kps = new Map, this.ekp = null, this.sc = !1 } rh(e) { this.hk.push(e) } ts() { return 1 === this.hk.length ? this.hk[0] : W(...this.hk) } gfc(e) { return U.get(e) || null } async rc(e) { if (!this.to) return e.read(); let t; const n = e.read(), r = await Promise.race([n, new Promise(e => t = setTimeout(e, this.to, 0))]).finally(() => clearTimeout(t)); if (r) return r; try { await e.cancel("err") } catch { } try { await n } catch { } throw 0 } async pr(e, t, n) { for (; ;) { let r; for (; r = this.rp.next();) if (await t(r)) return; const { value: i, done: s } = await this.rc(e); if (s) throw 0; this.rp.feed(i) } } async ph(e, t, n) { for (let e; e = this.hp.next();) if (await t(e)) return; return this.pr(e, async e => { if (e.type === i) { if (Z0(e.fragment)) return; throw 0 } if (e.type === s) { this.hp.feed(e.fragment); for (let e; e = this.hp.next();) if (await t(e)) return 1 } }, n) } async ac(e) { if (!e?.length) throw 0; this.sc = !0 } async handshake() { const [t, n] = await Promise.all([F("P-256"), F("X25519")]); this.kps = new Map([[23, t], [29, n]]), this.ekp = t.kp; const r = this.sk.readable.getReader(), a = this.sk.writable.getWriter(); try { const h = ue(this.cr, this.sn, { x25519: n.pk, p256: t.pk }, { tls13: this.s13, tls12: this.s12, alpn: this.alpn }); this.rh(h), await a.write(ie(s, h, e)); const o = await this.rsh(r); if (o.isHRR) throw 0; if (o.ks?.group && this.kps.has(o.ks.group)) { const e = this.kps.get(o.ks.group); this.ekp = e.kp } o.isTls13 ? await this.h13(r, a, o) : await this.h12(r, a), this.hc = !0 } finally { r.releaseLock(), a.releaseLock() } } async rsh(e) { for (; ;) { const { value: t, done: n } = await this.rc(e); if (n) throw 0; let r; for (this.rp.feed(t); r = this.rp.next();) { if (r.type === i) { if (Z0(r.fragment)) continue; throw 0 } if (r.type !== s) continue; let e; for (this.hp.feed(r.fragment); e = this.hp.next();) { if (e.type !== c) continue; this.rh(e.raw); const t = ce(e.body); if (this.sr = t.sr, this.cs = t.cs, this.cc = this.gfc(t.cs), this.is13 = t.isTls13, this.na = t.alpn || null, !this.cc) throw 0; return t } } } } async h12(e, t) { let n = null, a = !1; if (await this.ph(e, async e => { switch (e.type) { case f: { this.rh(e.raw); const t = le(e.body, 1); if (!t) throw 0; await this.ac(t); break } case u: this.rh(e.raw), n = oe(e.body); break; case p: return this.rh(e.raw), a = !0, 1; case y: throw 0; default: this.rh(e.raw) } }, "err"), !this.sc) throw 0; if (!n) throw 0; const h = I.get(n.nc); if (!h) throw 0; const c = this.kps.get(n.nc); if (!c) throw 0; const o = await Y(c.kp.privateKey, n.spk, h), l = se(d, _(c.pk.length, c.pk)); this.rh(l); const w = this.cc.hash; this.ms = await V(o, "master secret", W(this.cr, this.sr), 48, w); const k = this.cc.keyLen, v = this.cc.ivLen, A = await V(this.ms, "key expansion", W(this.sr, this.cr), 2 * k + 2 * v, w); this.cwk = A.slice(0, k), this.swk = A.slice(k, 2 * k), this.cwi = A.slice(2 * k, 2 * k + v), this.swi = A.slice(2 * k + v, 2 * k + 2 * v), await t.write(ie(s, l)), await t.write(ie(r, _(1))); const S = await V(this.ms, "client finished", await G(w, this.ts()), 12, w), m = se(g, S); this.rh(m), await t.write(ie(s, await this.e12(m, s))); let b = !1; await this.pr(e, async e => { if (e.type === i) { if (Z0(e.fragment)) return; throw 0 } if (e.type === r) return void (b = !0); if (e.type !== s || !b) return; const t = await this.d12(e.fragment, s); if (t[0] !== g) return; const n = M(t, 1), a = t.slice(4, 4 + n), h = await V(this.ms, "server finished", await G(w, this.ts()), 12, w); if (!N(a, h)) throw 0; return 1 }, "err") } async h13(e, t, n) { const h = I.get(n.ks?.group); if (!h || !n.ks?.key?.length) throw 0; const c = this.cc.hash, o = q(c), u = this.cc.keyLen, p = this.cc.ivLen, d = await Y(this.ekp.privateKey, n.ks.key, h), k = await X(c, null, new Uint8Array(o)), v = await O(c, k, "derived", await G(c, P), o); this.hs = await X(c, v, d); const A = await G(c, this.ts()), S = await O(c, this.hs, "c hs traffic", A, o), m = await O(c, this.hs, "s hs traffic", A, o); [this.chk, this.chi] = await we(c, S, u, p), [this.shk, this.shi] = await we(c, m, u, p); const b = await O(c, m, "finished", P, o); let C = !1; const H = async e => { switch (e.type) { case l: { const t = fe(e.body); t.alpn && (this.na = t.alpn), this.rh(e.raw); break } case f: { const t = le(e.body); if (!t) throw 0; await this.ac(t), this.rh(e.raw); break } case y: throw 0; case w: this.rh(e.raw); break; case g: { const t = await $(c, b, await G(c, this.ts())); if (!N(t, e.body)) throw 0; this.rh(e.raw), C = !0; break } default: this.rh(e.raw) } }; await this.pr(e, async e => { if (e.type === r || e.type === s) return; if (e.type === i) { if (Z0(e.fragment)) return; throw 0 } if (e.type !== a) return; const t = await this.d13h(e.fragment), n = t[t.length - 1], h = t.slice(0, -1); if (n === s) { this.hp.feed(h); for (let e; e = this.hp.next();) if (await H(e), C) return 1 } }, "err"); const T = await G(c, this.ts()), E = await O(c, this.hs, "derived", await G(c, P), o), L = await X(c, E, new Uint8Array(o)), K = await O(c, L, "c ap traffic", T, o), U = await O(c, L, "s ap traffic", T, o); [this.cak, this.cai] = await we(c, K, u, p), [this.sak, this.sai] = await we(c, U, u, p); const x = await O(c, S, "finished", P, o), _ = await $(c, x, await G(c, this.ts())), B = se(g, _); this.rh(B), await t.write(ie(a, await this.e13h(W(B, [s])))), this.csn = 0n, this.ssn = 0n } async e12(e, n) { const r = this.csn++, i = ye(r), s = W(i, [n], B(t), B(e.length)); if (this.cc.chacha) { const t = pe(this.cwi, r); return ne(this.cwk, t, e, s) } const a = D(8); return W(a, await j(this.cwk, W(this.cwi, a), e, s)) } async d12(e, n) { const r = this.ssn++, i = ye(r); if (this.cc.chacha) { const s = pe(this.swi, r); return re(this.swk, s, e, W(i, [n], B(t), B(e.length - 16))) } const s = e.slice(0, 8), a = e.slice(8); return z(this.swk, W(this.swi, s), a, W(i, [n], B(t), B(a.length - 16))) } async e13h(e) { const t = pe(this.chi, this.csn++), n = _(a, 3, 3, B(e.length + 16)); return this.cc.chacha ? ne(this.chk, t, e, n) : j(this.chk, t, e, n) } async d13h(e) { const t = pe(this.shi, this.ssn++), n = _(a, 3, 3, B(e.length)); return this.cc.chacha ? re(this.shk, t, e, n) : z(this.shk, t, e, n) } async e13(e) { const t = W(e, [a]), n = pe(this.cai, this.csn++), r = _(a, 3, 3, B(t.length + 16)); return this.cc.chacha ? ne(this.cak, n, t, r) : j(this.cak, n, t, r) } async d13(e) { const t = pe(this.sai, this.ssn++), n = _(a, 3, 3, B(e.length)), r = this.cc.chacha ? await re(this.sak, t, e, n) : await z(this.sak, t, e, n); return { data: r.slice(0, -1), type: r[r.length - 1] } } async write(e) { if (!this.hc) throw 0; const t = this.sk.writable.getWriter(); try { this.is13 ? await t.write(ie(a, await this.e13(e))) : await t.write(ie(a, await this.e12(e, a))) } finally { t.releaseLock() } } async read() { for (; ;) { let e; for (; e = this.rp.next();) { if (e.type === i) { if (e.fragment[1] === E) return null; throw 0 } if (e.type !== a) continue; if (!this.is13) return this.d12(e.fragment, a); const { data: t, type: n } = await this.d13(e.fragment); if (n === a) return t; if (n !== s) continue; let r; for (this.hp.feed(t); r = this.hp.next();) if (r.type !== o && r.type === k) throw 0 } const t = this.sk.readable.getReader(); try { const { value: e, done: n } = await this.rc(t); if (n) return null; this.rp.feed(e) } finally { t.releaseLock() } } } close() { this.sk.close() } } return { TlsClient } })();
async function f21(pc, th, tp) { let sk, ts = null; try { sk = connect({ hostname: pc.host, port: pc.port }, pc.isc ? {} : { secureTransport: "https" === pc.type ? "on" : "off", allowHalfOpen: !1 }), await sk.opened; let rq = `CONNECT ${th}:${tp} HTTP/1.1\r\nHost: ${th}:${tp}\r\n`; pc.username && (rq += `Proxy-Authorization: Basic ${btoa(`${pc.username}:${pc.password || ""}`)}\r\n`); rq += "User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"; if (pc.isc) { ts = new TlsClient(sk, { serverName: pc.host }), await ts.handshake(), await ts.write(f1(rq)) } else { const wr = sk.writable.getWriter(); await wr.write(f1(rq)), wr.releaseLock() } let rd = pc.isc ? null : sk.readable.getReader(), b = v_b0; for (; ;) { let vl, dn; if (pc.isc) { vl = await ts.read(), dn = !vl } else { const rs = await rd.read(); vl = rs.value, dn = rs.done } if (dn || !vl) throw 0; b = cat(b, vl); if (b.length >= 12 && 50 !== b[9]) throw 0; let hi = -1; for (let i = 0; i <= b.length - 4; i++) if (13 === b[i] && 10 === b[i + 1] && 13 === b[i + 2] && 10 === b[i + 3]) { hi = i + 4; break } if (-1 !== hi) { rd?.releaseLock(); let ov = b.subarray(hi); if (pc.isc) return { readable: new ReadableStream({ start(c) { ov.length && c.enqueue(ov) }, async pull(c) { try { let d = await ts.read(); d ? c.enqueue(d) : c.close() } catch (e) { c.error(e) } }, cancel() { ts.close() } }), writable: new WritableStream({ async write(k) { await ts.write(k) }, close() { ts.close() }, abort() { ts.close() } }), close: () => ts.close() }; if (ov.length > 0) { let { readable: r, writable: w } = new TransformStream, tw = w.getWriter(); return tw.write(ov), tw.releaseLock(), sk.readable.pipeTo(w).catch(() => { }), { readable: r, writable: sk.writable, close: () => f12(sk) } } return sk } if (b.length > 8192) throw 0 } } catch (e) { throw ts?.close(), f12(sk), e } }
async function f22(pc, th, tp) { let ti = th; if (!r_ip.test(ti)) { const ar = await f14(th, "A"), il = ar.filter(x => 1 === x.type).map(x => x.data); if (!(il.length > 0)) throw 0; ti = il[0] } const sk = await f19(pc, Promise.resolve(ti), tp); if (!sk) throw 0; return sk }
const f29 = (t, v) => { const l = v.length, pl = -l & 3, b = new Uint8Array(4 + l + pl), d = new DataView(b.buffer); return d.setUint16(0, t), d.setUint16(2, l), b.set(v, 4), b };
const f30 = (t, id, a) => { const bd = cat(...a), h = new Uint8Array(20), d = new DataView(h.buffer); return d.setUint16(0, t), d.setUint16(2, bd.length), h.set(v_v10, 4), h.set(id, 8), cat(h, bd) };
const f31 = (ip, p) => { const b = new Uint8Array(8); return b[1] = 1, new DataView(b.buffer).setUint16(2, 8466 ^ p), ip.split(".").forEach((v, i) => b[4 + i] = +v ^ v_v10[i]), b };
const f32 = d => { if (d.length < 20 || v_v10.some((v, i) => d[4 + i] !== v)) return null; const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), at = {}; for (let o = 20; o + 4 <= 20 + ml;) { const t = dv.getUint16(o), l = dv.getUint16(o + 2); if (o + 4 + l > d.length) break; at[t] = d.slice(o + 4, o + 4 + l), o += 4 + l + (-l & 3) } return { type: dv.getUint16(0), attrs: at } };
const f33 = async (m, k) => { const c = new Uint8Array(m), d = new DataView(c.buffer); d.setUint16(2, d.getUint16(2) + 24); const ky = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-1" }, !1, ["sign"]); return cat(c, f29(8, new Uint8Array(await crypto.subtle.sign("HMAC", ky, c)))) };
const f34 = async (rd, bf) => { let b = bf ?? v_b0; const pl = async () => { const { done: dn, value: vl } = await rd.read(); if (dn) throw 0; b = cat(b, new Uint8Array(vl)) }; try { for (; b.length < 20;) await pl(); const n = 20 + f3(b, 2); for (; b.length < n;) await pl(); return [f32(b.subarray(0, n)), b.length > n ? b.subarray(n) : null] } catch { return [null, null] } };
const f35 = async s => new Uint8Array(await crypto.subtle.digest("MD5", f1(s)));
const f36 = async (w, r, tp, pc, pl) => { const tv = new Uint8Array([tp, 0, 0, 0]); await w.write(f30(3, f5(12), [f29(25, tv)])); let [mg, ex] = await f34(r); if (!mg) return null; let ky = null, aa = []; const sn = m => ky ? f33(m, ky) : Promise.resolve(m); if (275 === mg.type && pc.username && 401 === (mg.attrs[9]?.length >= 4 ? (7 & mg.attrs[9][2]) * 100 + mg.attrs[9][3] : 0)) { const rm = dec.decode(mg.attrs[20] ?? v_b0), nc = mg.attrs[21] ?? v_b0; ky = await f35(`${pc.username}:${rm}:${pc.password}`), aa = [f29(6, f1(pc.username)), f29(20, f1(rm)), f29(21, nc)]; const aq = await f33(f30(3, f5(12), [f29(25, tv), ...aa]), ky), xt = pl ? await Promise.all(pl(aa, sn)) : []; if (await w.write(xt.length ? cat(aq, ...xt) : aq), [mg, ex] = await f34(r, ex), !mg) return null } else if (pl && 259 === mg.type) { const xt = await Promise.all(pl(aa, sn)); xt.length && await w.write(cat(...xt)) } return 259 === mg.type ? { ky: ky, aa: aa, ex: ex, sn: sn } : null };
const f37 = async (pc, th, tp) => { let cl = null, dt = null, ts_cl = null, ts_dt = null; const cs = () => { ts_cl?.close(); ts_dt?.close(); f12(cl); f12(dt) }; try { if (pc.isc) { cl = connect({ hostname: pc.host, port: pc.port }); await cl.opened; ts_cl = new TlsClient(cl, { serverName: pc.host }); await ts_cl.handshake() } else { const opt = "turns" === pc.type ? { secureTransport: "on" } : {}; cl = connect({ hostname: pc.host, port: pc.port }, opt); await cl.opened} const cw = pc.isc ? { write: k => ts_cl.write(k) } : cl.writable.getWriter(); const cr = pc.isc ? { read: () => ts_cl.read().then(v => ({ done: !v, value: v })) } : cl.readable.getReader(); const pr = f29(18, f31(th, tp)); const ah = await f36(cw, cr, 6, pc, (aa, sn) => [sn(f30(8, f5(12), [pr, ...aa])), sn(f30(10, f5(12), [pr, ...aa]))]); if (!ah) throw 0; const { aa, sn } = ah; let ex = ah.ex, r; if ([r, ex] = await f34(cr, ex), 264 !== r?.type) throw 0; if ([r, ex] = await f34(cr, ex), 266 !== r?.type || !r.attrs[42]) throw 0; if (pc.isc) { dt = connect({ hostname: pc.host, port: pc.port }); await dt.opened; ts_dt = new TlsClient(dt, { serverName: pc.host }); await ts_dt.handshake() } else { const opt = "turns" === pc.type ? { secureTransport: "on" } : {}; dt = connect({ hostname: pc.host, port: pc.port }, opt); await dt.opened } const dw = pc.isc ? { write: k => ts_dt.write(k) } : dt.writable.getWriter(); const dr = pc.isc ? { read: () => ts_dt.read().then(v => ({ done: !v, value: v })) } : dt.readable.getReader(); await dw.write(await sn(f30(11, f5(12), [f29(42, r.attrs[42]), ...aa]))); let xt; if ([r, xt] = await f34(dr), 267 !== r?.type) throw 0; if (!pc.isc) { cr.releaseLock(); cw.releaseLock() } if (pc.isc) { const rdStream = new ReadableStream({ start: c => { xt?.length && c.enqueue(xt) }, async pull(c) { try { const d = await ts_dt.read(); d ? c.enqueue(d) : c.close() } catch (e) { c.error(e) } }, cancel() { ts_dt.close() } }); const wrStream = new WritableStream({ async write(k) { await ts_dt.write(k) }, close() { ts_dt.close() }, abort() { ts_dt.close() } }); return { readable: rdStream, writable: wrStream, close: cs } } if (xt?.length) { dw.releaseLock(); return { readable: new ReadableStream({ start: c => c.enqueue(xt), pull: c => dr.read().then(({ done: dn, value: vl }) => dn ? c.close() : c.enqueue(new Uint8Array(vl))), cancel: () => dr.cancel() }), writable: dt.writable, close: cs } } else { dr.releaseLock(); dw.releaseLock(); return { readable: dt.readable, writable: dt.writable, close: cs } } } catch { throw cs(), new Error("E18") } };
async function f38(pc, th, tp) { let ti = th; if (!r_ip.test(ti)) { const ar = await f14(th, "A"), il = ar.filter(x => 1 === x.type).map(x => x.data); if (!(il.length > 0)) throw 0; ti = il[0] } const sk = await f37(pc, ti, tp); if (!sk) throw 0; return sk }
const f_adr = (t, b) => 1 === t ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : 3 === t ? dec.decode(b) : `[${Array.from({ length: 8 }, (_, i) => (b[2 * i] << 8 | b[2 * i + 1]).toString(16)).join(":")}]`;
const f_padr = (b, o, t) => { const l = 3 === t ? b[o++] : 1 === t ? 4 : 4 === t ? 16 : null; return null === l ? null : o + l > b.length ? null : { b: b.subarray(o, o + l), o: o + l } };
const f_vmore = c => { if (c.byteLength < 24 || !matchID(c)) return null; let o = 19 + c[17]; if (o + 3 > c.byteLength) return null; let t = c[o + 2]; const p = c[o] << 8 | c[o + 1]; 1 !== t && (t += 1); const a = f_padr(c, o + 3, t); return a ? { t: t, b: a.b, p: p, u: 2 === c[18 + c[17]], v: c[0], o: a.o } : null };
const f_trajon = c => { if (c.byteLength < 60) return null; for (let i = 0; i < 56; i++) if (c[i] !== authBuf[i]) return null; if (c[56] !== 13 || c[57] !== 10 || c[58] !== 1) return null; const t = c[59]; let o = 60, l = 1 === t ? 4 : 3 === t ? c[o++] : 4 === t ? 16 : null; if (null === l) return null; const n = o + l; if (n + 4 > c.byteLength || c[n + 2] !== 13 || c[n + 3] !== 10) return null; return { t: t, b: c.subarray(o, n), p: c[n] << 8 | c[n + 1], o: n + 4 } };
const f43 = d => { if (d.length < 1) return null; const t = d[0]; let h, p, o; if (1 === t && d.length >= 7) { h = `${d[1]}.${d[2]}.${d[3]}.${d[4]}`; p = f3(d, 5); o = 7 } else if (3 === t && d.length >= 4 + d[1]) { h = dec.decode(d.subarray(2, 2 + d[1])); p = f3(d, 2 + d[1]); o = 4 + d[1] } else if (4 === t && d.length >= 19) { h = `[${Array.from({ length: 8 }, (_, i) => (d[1 + 2 * i] << 8 | d[2 + 2 * i]).toString(16)).join(":")}]`; p = f3(d, 17); o = 19 } else return null; return { h: h, p: p, o: o } };
const f_cd = (h, p, m = CFG.connMs) => new Promise((ok, no) => { h = String(h).trim(), h[0] == "[" && h[h.length - 1] == "]" && (h = h.slice(1, -1)); const s = connect({ hostname: h, port: p }); let e = 0; const t = setTimeout(() => { if (e) return; e = 1; try { s.close() } catch { } no(0) }, m); s.opened.then(() => { if (e) { try { s.close() } catch { } return } e = 1; clearTimeout(t); ok(s) }, x => { if (e) return; e = 1; clearTimeout(t); try { s.close() } catch { } no(x) }) });
const f_p16 = (d, o, v) => { d[o] = v >> 8 & 255; d[o + 1] = v & 255 };
const f_evp = async (pw, kl) => { let k = v_b0, pv = v_b0; const p = enc.encode(pw); while (k.length < kl) { const d = new Uint8Array(pv.length + p.length); d.set(pv), d.set(p, pv.length), pv = new Uint8Array(await crypto.subtle.digest("MD5", d)); const nk = new Uint8Array(k.length + pv.length); nk.set(k), nk.set(pv, k.length), k = nk } return k.slice(0, kl) };
const f_hkdf = async (ikm, salt, info, len) => { const k1 = await crypto.subtle.importKey("raw", salt.length ? salt : v_z20, { name: "HMAC", hash: "SHA-1" }, !1, ["sign"]), prk = new Uint8Array(await crypto.subtle.sign("HMAC", k1, ikm)); const k2 = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-1" }, !1, ["sign"]), okm = new Uint8Array(Math.ceil(len / 20) * 20); let pv = v_b0; for (let i = 0; i < Math.ceil(len / 20); i++) { pv = new Uint8Array(await crypto.subtle.sign("HMAC", k2, cat(pv, info, new Uint8Array([i + 1])))), okm.set(pv, i * 20) } return okm.slice(0, len) };
const f_gmk = async () => v_mk ??= await f_evp(v2, 16);
class AEAD { constructor(key) { this.key = key; this.nonce = new Uint8Array(12); this.ck = null } async init() { this.ck = await crypto.subtle.importKey("raw", this.key, { name: "AES-GCM" }, !1, ["encrypt", "decrypt"]) } inc() { for (let i = 0; i < this.nonce.length; i++) { this.nonce[i]++; if (this.nonce[i]) break } } async enc(d) { const c = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: this.nonce, tagLength: 128 }, this.ck, d)); return this.inc(), c } async dec(d) { try { const p = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.nonce, tagLength: 128 }, this.ck, d)); return this.inc(), p } catch { return null } } }
class SS { constructor() { this.dec = null; this.enc = null; this.buf = v_b0; this.plen = -1 } async decData(data) { this.buf = this.buf.length ? cat(this.buf, data) : data; const out = []; if (!this.dec) { if (this.buf.length < 16) return { c: [] }; const salt = this.buf.slice(0, 16); this.buf = this.buf.slice(16), this.dec = new AEAD(await f_hkdf(await f_gmk(), salt, v_ssinf, 16)), await this.dec.init() } while (!0) { if (this.plen < 0) { if (this.buf.length < 18) break; const lp = await this.dec.dec(this.buf.slice(0, 18)); if (!lp) return { c: out, e: "len" }; this.plen = f3(lp, 0), this.buf = this.buf.slice(18) } const ps = this.plen + 16; if (this.buf.length < ps) break; const pp = await this.dec.dec(this.buf.slice(0, ps)); if (!pp) return { c: out, e: "pay" }; out.push(pp), this.buf = this.buf.slice(ps), this.plen = -1 } return { c: out } } async encData(data) { let pf = v_b0; if (!this.enc) { const salt = crypto.getRandomValues(new Uint8Array(16)); this.enc = new AEAD(await f_hkdf(await f_gmk(), salt, v_ssinf, 16)), await this.enc.init(), pf = salt } if (!data || 0 === data.length) return pf.length ? pf : v_b0; const mx = 16383, cks = []; for (let i = 0; i < data.length; i += mx) { const ck = data.subarray(i, Math.min(i + mx, data.length)), lb = new Uint8Array(2); f_p16(lb, 0, ck.length), cks.push(await this.enc.enc(lb)), cks.push(await this.enc.enc(ck)) } return cat(pf, ...cks) } }
const mkK = (cap, cpy = 0) => { let q = [], h = 0, b = 0, buf = null; const e = () => h >= q.length, trim = () => { h > 32 && h * 2 >= q.length && (q = q.slice(h), h = 0) }, clear = () => { q = [], h = 0, b = 0 }; const take = () => { if (e()) return null; const d = q[h]; return q[h++] = void 0, b -= d.byteLength, trim(), d }; const sow = d => { const n = d?.byteLength || 0; return !!n && (q.push(d), b += n, 1) }; const pack = d => { let z = 0; if (!d) { d = take(); d && (z = 1) } if (!d || e()) return [d, 0, z]; let n = d.byteLength, j = h; while (j < q.length) { const x = q[j], nn = n + x.byteLength; if (nn > cap) break; n = nn; j++ } if (j === h) return [d, 0, z]; const out = buf ||= new Uint8Array(cap); out.set(d); for (let o = d.byteLength; h < j;) { const x = q[h]; q[h++] = void 0; b -= x.byteLength; out.set(x, o); o += x.byteLength; z++ } trim(); return [cpy ? out.slice(0, n) : out.subarray(0, n), 1, z] }; return { e: e, get b() { return b }, clear: clear, take: take, sow: sow, pack: pack } };
const mkQ = (cap = CFG.upPack, mx = CFG.upQMax, nx = CFG.upNMax) => { const k = mkK(cap); let n = 0; return { get empty() { return k.e() }, get b() { return k.b }, clear() { k.clear(); n = 0 }, sow: d => { const z = d?.byteLength || 0; if (!z || k.b + z > mx || n >= nx) return 0; n++; return k.sow(d) }, bundle: d => { const r = k.pack(d); n = Math.max(0, n - r[2]); return r } } };
const mkDn = (w_send, ss, isRaw) => { const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, 12 * tail), k = mkK(cap, 1); let tp = 0, gen = 0, qk = 0, qr = 0; let txQueue = [], txBusy = false; const flushQueue = async () => { if (txBusy) return; txBusy = true; try { while (txQueue.length > 0) { const u = txQueue.shift(); const encData = await ss.encData(u); w_send(encData) } } catch { } finally { txBusy = false } }; const pushTx = u => { if (isRaw) { w_send(u) } else { txQueue.push(u); flushQueue() } }; const reap = () => { tp && clearTimeout(tp), tp = 0, qr = 0; for (; ;) { const [u] = k.pack(); if (!u) break; pushTx(u) } }; const ripen = () => { if (k.e() || tp) return; if (k.b >= cap || cap - k.b < tail) return reap(); tp = setTimeout(() => { tp = 0; if (k.e()) return; if (k.b >= cap || cap - k.b < tail) return reap(); if (qr < CFG.dnQr && (gen !== qk || k.b < low)) return qr++, qk = gen, void ripen(); reap() }, CFG.dnMs) }; return { send(u) { let o = 0, n = u?.byteLength || 0; if (!n) return; while (o < n) { const m = Math.min(cap - k.b, n - o); if (!m) { reap(); continue } k.sow(o || m !== n ? u.subarray(o, o + m) : u), gen++, o += m, k.b >= cap || cap - k.b < tail ? reap() : ripen() } }, fastSend(u) { u?.byteLength && pushTx(u) }, reap: reap } };
const mill = async (rd, w_send, ss, isRaw) => { let r, ib = !1; try { r = rd.getReader({ mode: "byob" }), ib = !0 } catch { r = rd.getReader() } const tx = mkDn(w_send, ss, isRaw); let buf = new ArrayBuffer(CFG.chunk); try { if (ib) for (; ;) { const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk)); if (done) break; v?.byteLength && (v.byteLength >= CFG.chunk >> 1 ? (tx.reap(), tx.fastSend(v), buf = new ArrayBuffer(CFG.chunk)) : (tx.send(v.slice()), buf = v.buffer)) } else for (; ;) { const { done, value: v } = await r.read(); if (done) break; v?.byteLength && (v.byteLength >= CFG.chunk >> 1 ? (tx.reap(), tx.fastSend(v)) : tx.send(v)) } tx.reap() } catch { } finally { try { tx.reap() } catch { } try { r.releaseLock() } catch { } } };

// ================= 三协议复用动态代理池穿透引擎 =================
async function f26_pool(h, p, pool) {
    try {
        const sock = await f_cd(h, p, CFG.connMs); 
        return sock;
    } catch { }
    
    const via = async (q) => "socks5" === q.type ? f20(q, h, p) : ["http", "https"].includes(q.type) ? f21(q, h, p) : "sstp" === q.type ? f22(q, h, p) : ["turn", "turns"].includes(q.type) ? f38(q, h, p) : f_cd(q.host, q.port, CFG.connMs);

    for (const cf of pool) {
        try {
            let cv = cf.trim();
            let q = null;
            if (cv.toLowerCase().endsWith("!txt")) {
                const tg = cv.slice(0, -4).trim();
                let pv = null;
                try {
                    const tr = await f14(tg, "TXT");
                    const td = tr.filter(x => 16 === x.type).map(x => x.data);
                    if (td.length) {
                        pv = td.map(x => x.replace(/"/g, "")).join(",").replace(/[\r\n\s]+/g, ",").split(",").map(x => x.trim()).filter(Boolean);
                    }
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

async function f27(uc, w_send, v) {
    try {
        const resp = await fetch('https://dns.alidns.com/dns-query', {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: uc
        });
        if (resp.ok) {
            const result = new Uint8Array(await resp.arrayBuffer());
            const out = new Uint8Array(2 + result.length);
            out[0] = v; out[1] = 0;
            out.set(result, 2);
            w_send(out);
        }
    } catch { }
}

function parsePathConfig(url) {
    let path = url.pathname.slice(1);
    try { path = decodeURIComponent(path) } catch { }
    const q = path.indexOf("?");
    const pathPart = q < 0 ? path : path.slice(0, q);
    const i = pathPart.indexOf("=");
    let proxy = null;
    if (i > 0 && i < pathPart.length - 1) {
        const key = pathPart.slice(0, i).trim();
        const value = pathPart.slice(i + 1).trim();
        if (key && value) { proxy = value }
    }
    return { proxy: proxy }
}

export default {
    async fetch(req, env) {
        const isWS = req.headers.get('Upgrade')?.toLowerCase() === 'websocket';
        const isXHTTP = !isWS && req.method === 'POST';
        const u = new URL(req.url);
        
        if (!isWS && !isXHTTP && !req.body) {
            const UA = (req.headers.get("User-Agent") || "").toLowerCase();
            const isSub = (u.pathname === `/${myID}` || u.pathname === `/sub`);
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

        let clientRead, w_send, closeClient, response;

        if (isWS) {
            const pair = new WebSocketPair();
            const ws = pair[1];
            ws.accept();
            clientRead = new ReadableStream({
                start(ctrl) {
                    ws.addEventListener('message', e => ctrl.enqueue(e.data));
                    ws.addEventListener('close', () => ctrl.close());
                    ws.addEventListener('error', () => ctrl.error());
                    const early = req.headers.get('sec-websocket-protocol');
                    if (early) {
                        try {
                            ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer);
                        } catch { }
                    }
                }
            });
            w_send = (d) => { if (ws.readyState === 1) ws.send(d); };
            closeClient = () => { try { ws.close() } catch { } };
            response = new Response(null, { status: 101, webSocket: pair[0] });
        } else if (isXHTTP) {
            clientRead = req.body;
            const { readable, writable } = new TransformStream();
            const clientWrite = writable.getWriter();
            
            w_send = (d) => { clientWrite.write(d).catch(() => { }); };
            closeClient = () => { try { clientWrite.close() } catch { } };
            
            const respHeaders = new Headers({
                'Content-Type': 'application/octet-stream',
                'X-Accel-Buffering': 'no',
                'Cache-Control': 'no-store, no-transform'
            });
            
            try {
                const padUrl = new URL('https://x.invalid/');
                padUrl.searchParams.set(padKey, genXhttpPadding(100 + Math.floor(Math.random() * 901)));
                respHeaders.set(padHeader, padUrl.toString());
            } catch (e) { }
            
            response = new Response(readable, { status: 200, headers: respHeaders });
        } else {
            return new Response("OK", { status: 200 });
        }

        // ================= GrainTCP 与三协议核心分发逻辑 =================
        let rw = { socket: null, writer: null }, dq = !1, closed = !1, busy = !1, pT = 0;
        const ssEngine = new SS(), uq = mkQ(CFG.upPack, CFG.upQMax);
        
        const wither = () => {
            if (!closed) {
                closed = !0; uq.clear();
                try { rw.writer?.releaseLock() } catch { }
                try { rw.socket?.close() } catch { }
                closeClient();
            }
        };

        const toU8 = d => d instanceof Uint8Array ? d : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : new Uint8Array(d);
        const sow = d => { const u = toU8(d); return u.byteLength ? uq.sow(u) ? 1 : (wither(), 0) : 1 };

        async function thresh() {
            if (!busy && !closed) {
                busy = !0;
                try {
                    for (; ;) {
                        if (closed) break;
                        if (dq) {
                            const [d] = uq.bundle();
                            if (!d) break;
                            await f27(d, w_send, 0); 
                            continue;
                        }
                        if (!rw.socket) {
                            const [d] = uq.bundle();
                            if (!d) break;
                            let host, port, payload, version = 0;
                            if (1 === pT) {
                                const parsed = f_vmore(d);
                                if (!parsed) throw 0;
                                version = parsed.v;
                                w_send(new Uint8Array([parsed.v, 0]));
                                if (parsed.u) {
                                    if (53 !== parsed.p) throw 0;
                                    dq = !0;
                                    await f27(d.subarray(parsed.o), w_send, version);
                                    continue;
                                }
                                host = f_adr(parsed.t, parsed.b); port = parsed.p; payload = d.subarray(parsed.o);
                            } else if (2 === pT) {
                                const parsed = f_trajon(d);
                                if (!parsed) throw 0;
                                host = f_adr(parsed.t, parsed.b); port = parsed.p; payload = d.subarray(parsed.o);
                            } else {
                                const parsed = f43(d);
                                if (!parsed) throw 0;
                                host = parsed.h; port = parsed.p; payload = d.subarray(parsed.o);
                            }
                            
                            const sock = await f26_pool(host, port, proxyIPPool);
                            if (!sock) throw 0;
                            rw.socket = sock; rw.writer = sock.writable.getWriter();
                            
                            const [first] = uq.bundle(payload);
                            if (first?.byteLength) await rw.writer.write(first);
                            
                            mill(sock.readable, w_send, ssEngine, 3 !== pT).catch(() => { });
                            continue;
                        }
                        const [d] = uq.bundle();
                        if (!d) break;
                        await rw.writer.write(d);
                    }
                } catch { wither() } finally { busy = !1; !uq.empty && !closed && thresh() }
            }
        }

        let initBuffer = new Uint8Array(0);
        const pM = data => {
            if (closed) return;
            const u = toU8(data);
            if (!u.byteLength) return;

            if (!pT) {
                initBuffer = cat(initBuffer, u);
                pT = f_vmore(initBuffer) ? 1 : f_trajon(initBuffer) ? 2 : f43(initBuffer) ? 3 : 0;
                
                if (!pT) {
                    if (initBuffer.byteLength > 512) return wither(); 
                    return; 
                }
                
                if (1 === pT || 2 === pT) {
                    if (sow(initBuffer)) thresh();
                } else {
                    ssEngine.decData(initBuffer).then(({ c, e }) => {
                        if (closed) return;
                        if (e) return wither();
                        let s = !1;
                        for (const ck of c) if (sow(ck)) s = !0;
                        if (s) thresh();
                    }).catch(() => wither());
                }
                initBuffer = null; 
            } else {
                if (1 === pT || 2 === pT) {
                    if (sow(u)) thresh();
                } else {
                    ssEngine.decData(u).then(({ c, e }) => {
                        if (closed) return;
                        if (e) return wither();
                        let s = !1;
                        for (const ck of c) if (sow(ck)) s = !0;
                        if (s) thresh();
                    }).catch(() => wither());
                }
            }
        };

        clientRead.pipeTo(new WritableStream({
            write(data) { pM(data); },
            close() { wither(); },
            abort() { wither(); }
        })).catch(() => wither());

        return response;
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
        base = setParam(base, 'alpn', encodeURIComponent('h2,http/1.1'));
        
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

const vSB = t => { try { return Array.isArray(JSON.parse(t).outbounds) } catch { return !1 } };

function pSB(x, echCfg, h, FP, tp) {
    try {
        const j = JSON.parse(x), o = j['outbounds'] || [];
        for (const b of o) {
            if (b.type !== 'vless' && b.type !== 'vmess') continue;
            if (b.uuid !== myID && b.server_name !== myID) continue;
            if (!b.tls) b.tls = {};
            b.tls.server_name = h; 
            b.tls.utls = { enabled: true, fingerprint: FP };
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
            uu.searchParams.set('alpn', 'h2,http/1.1');
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
    p.append('alpn', "h2,http/1.1");
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
