// Version: v1.2.1 | Time: 2026-08-11 22:22:12 (北京时间)
import { connect } from 'cloudflare:sockets';

const te = new TextEncoder();
const td = new TextDecoder();

const myID = '81818e2e-e597-4fb4-bff9-e998bac45460';

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
let TYPE = 'xhttp'; // 默认传输协议

// 自动演算生成 xhttp extra 混淆配置
const padHeader = myID.slice(1, 7);
const padKey = '_' + myID.slice(25, 31);
const xhttpExtra = JSON.stringify({
    "xPaddingObfsMode": true,
    "xPaddingMethod": "tokenish",
    "xPaddingPlacement": "queryInHeader",
    "xPaddingHeader": padHeader,
    "xPaddingKey": padKey
});

const EXPECTED_BYTES = new Uint8Array(16);
{
    const hex = myID.replace(/-/g, '');
    for (let i = 0; i < 16; i++) {
        EXPECTED_BYTES[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
}

function verifyID(data) {
    const u8 = new Uint8Array(data);
    if (u8.length < 17) return false;
    for (let i = 0; i < 16; i++) {
        if (u8[i + 1] !== EXPECTED_BYTES[i]) return false;
    }
    return true;
}

const xhttpBase62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function genXhttpPadding(len) {
    let res = '';
    for (let i = 0; i < len; i++) {
        res += xhttpBase62[Math.floor(Math.random() * xhttpBase62.length)];
    }
    return res;
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

        if (u.pathname.includes('%3F')) {
            const decoded = decodeURIComponent(u.pathname);
            const queryIndex = decoded.indexOf('?');
            if (queryIndex !== -1) {
                u.search = decoded.substring(queryIndex);
                u.pathname = decoded.substring(0, queryIndex);
            }
        }

        // 兼容 /p= 和 /proxyip= 两种路径写法
        let sParam = u.pathname.split('/s=')[1];
        let gParam = u.pathname.split('/g=')[1];
        let pParamInput = u.pathname.split('/p=')[1] || u.pathname.split('/proxyip=')[1];
        
        const colo = req.cf?.colo || 'LAX';
        const dynamicProxy = `${colo}.PrOxYip.CmLiuSsSs.nEt:443`;
        
        let mode = 'default';
        let skJson;
        let proxyIPPool = [];

        if (sParam && !gParam) {
            mode = 's'; skJson = getSKJson(sParam);
        } else if (gParam) {
            mode = 'g'; skJson = getSKJson(gParam);
        } else if (pParamInput) {
            mode = 'p'; 
            proxyIPPool.push(pParamInput);
        } else {
            if (PIP) proxyIPPool.push(PIP);
            proxyIPPool.push(dynamicProxy);
        }

        let clientRead, clientWrite, response, ws;

        if (isWS) {
            const pair = new WebSocketPair();
            ws = pair[1];
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
            response = new Response(null, { status: 101, webSocket: pair[0] });
        } else if (isXHTTP) {
            clientRead = req.body;
            const { readable, writable } = new TransformStream();
            clientWrite = writable.getWriter();
            
            const respHeaders = new Headers({
                'Content-Type': 'application/octet-stream',
                'X-Accel-Buffering': 'no',
                'Cache-Control': 'no-store'
            });
            
            try {
                const padUrl = new URL('https://x.invalid/');
                padUrl.searchParams.set(padKey, genXhttpPadding(100 + Math.floor(Math.random() * 901)));
                respHeaders.set(padHeader, padUrl.toString());
            } catch (e) {}
            
            response = new Response(readable, { status: 200, headers: respHeaders });
        } else {
            clientRead = req.body || new ReadableStream({start(c){c.close()}});
            const { readable, writable } = new TransformStream();
            clientWrite = writable.getWriter();
            response = new Response(readable, { status: 200 });
        }

        let remote = null, udpWriter = null, isDNS = false;

        clientRead.pipeTo(new WritableStream({
            async write(data) {
                if (isDNS) {
                    try { await udpWriter?.write(data); } catch (e) {}
                    return;
                }
                if (remote) {
                    try {
                        const w = remote.writable.getWriter();
                        await w.write(data);
                        w.releaseLock();
                    } catch (e) {}
                    return;
                }

                const u8 = new Uint8Array(data);
                if (u8.length < 24) return;
                
                if (!verifyID(u8)) {
                    try { if (isWS && ws.readyState === 1) ws.close(1008); } catch {}
                    return;
                }

                const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
                const optLen = view.getUint8(17);
                const cmd = view.getUint8(18 + optLen);
                if (cmd !== 1 && cmd !== 2) return;

                let pos = 19 + optLen;
                const port = view.getUint16(pos);
                const type = view.getUint8(pos + 2);
                pos += 3;

                let addr = '';
                if (type === 1) {
                    addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
                    pos += 4;
                } else if (type === 2) {
                    const len = view.getUint8(pos++);
                    addr = td.decode(u8.subarray(pos, pos + len));
                    pos += len;
                } else if (type === 3) {
                    const ipv6 = [];
                    for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos).toString(16));
                    addr = ipv6.join(':');
                } else return;

                const header = new Uint8Array([u8[0], 0]);
                const payload = u8.slice(pos);

                if (cmd === 2) {
                    if (port !== 53) return;
                    isDNS = true;
                    let dnsSent = false;
                    const { readable, writable } = new TransformStream({
                        transform(chunk, ctrl) {
                            const chunkU8 = new Uint8Array(chunk);
                            for (let i = 0; i < chunkU8.length;) {
                                const len = new DataView(chunkU8.buffer, chunkU8.byteOffset + i, 2).getUint16(0);
                                ctrl.enqueue(chunkU8.slice(i + 2, i + 2 + len));
                                i += 2 + len;
                            }
                        }
                    });

                    readable.pipeTo(new WritableStream({
                        async write(query) {
                            try {
                                const resp = await fetch('https://dns.alidns.com/dns-query', {
                                    method: 'POST',
                                    headers: { 'content-type': 'application/dns-message' },
                                    body: query
                                });
                                if (resp.ok) {
                                    const result = new Uint8Array(await resp.arrayBuffer());
                                    const out = new Uint8Array([...(dnsSent ? [] : header), result.length >> 8, result.length & 0xff, ...result]);
                                    if (isWS && ws.readyState === 1) ws.send(out);
                                    else if (!isWS) await clientWrite.write(out).catch(() => {});
                                    dnsSent = true;
                                }
                            } catch { }
                        }
                    })).catch(() => {});
                    udpWriter = writable.getWriter();
                    try { await udpWriter.write(payload); } catch (e) {}
                    return;
                }

                let sock = null;
                try {
                    if (mode === 's' && skJson) {
                        sock = await sConnect(addr, port, skJson);
                    } else if (mode === 'd') {
                        sock = connect({ hostname: addr, port });
                        await sock.opened;
                    } else {
                        try {
                            sock = connect({ hostname: addr, port });
                            await sock.opened;
                        } catch (err) {
                            sock = null;
                        }
                        if (!sock && proxyIPPool.length > 0) {
                            for (const proxy of proxyIPPool) {
                                try {
                                    const [ph, pp] = proxy.split(':');
                                    sock = connect({ hostname: ph, port: +(pp || 443) });
                                    await sock.opened;
                                    break;
                                } catch (e) { sock = null; }
                            }
                        }
                    }
                } catch (err) {}

                if (!sock) {
                    try { if (isWS && ws.readyState === 1) ws.close(1011); } catch {}
                    try { clientWrite.close(); } catch {}
                    return;
                }

                sock.closed.catch(() => {});
                remote = sock;

                try {
                    if (isWS && ws.readyState === 1) ws.send(header);
                    else if (!isWS) clientWrite.write(header).catch(() => {});
                    const w = sock.writable.getWriter();
                    await w.write(payload);
                    w.releaseLock();
                } catch (e) {
                    try { sock.close(); } catch {}
                    return;
                }

                const reader = sock.readable.getReader();
                const batch = [];
                let bSz = 0, bTmr = null, bytesSinceYield = 0;
                const YIELD_LIMIT = 1024 * 1024; 

                const flush = () => {
                    if (!bSz) return;
                    try {
                        let out;
                        if (batch.length === 1) out = batch[0]; 
                        else {
                            out = new Uint8Array(bSz);
                            let off = 0;
                            for (const c of batch) { out.set(c, off); off += c.length; }
                        }
                        if (isWS && ws.readyState === 1) ws.send(out);
                        else if (!isWS) clientWrite.write(out).catch(() => {});
                    } catch {}
                    batch.length = 0; bSz = 0;
                    if (bTmr) { clearTimeout(bTmr); bTmr = null; }
                };

                (async () => {
                    try {
                        while (true) {
                            const { done, value } = await reader.read();
                            if (done) { flush(); break; }
                            if (!value || value.byteLength === 0) continue;

                            bytesSinceYield += value.byteLength;
                            if (bytesSinceYield >= YIELD_LIMIT) {
                                await new Promise(r => setTimeout(r, 1)); 
                                bytesSinceYield = 0;
                            }

                            if (value.byteLength < 32768) {
                                batch.push(value); bSz += value.byteLength;
                                if (bSz >= 65536) flush(); 
                                else if (!bTmr) bTmr = setTimeout(flush, 3);
                            } else {
                                flush(); 
                                try {
                                    if (isWS && ws.readyState === 1) ws.send(value);
                                    else if (!isWS) clientWrite.write(value).catch(() => {});
                                } catch {}
                            }
                        }
                    } catch (_) {
                    } finally {
                        flush();
                        try { reader.releaseLock(); } catch { }
                        if (!isWS) { try { clientWrite.close(); } catch { } }
                        try { if (isWS && ws.readyState === 1) ws.close(1000); } catch { }
                    }
                })();
            }
        })).catch(() => { }).finally(() => { try { remote?.close(); } catch {} });

        return response;
    }
};

const SK_CACHE = new Map();
function getSKJson(path) {
    const cached = SK_CACHE.get(path);
    if (cached) return cached;
    const hasAuth = path.includes('@');
    const [cred, server] = hasAuth ? path.split('@') : [null, path];
    const [user = null, pass = null] = hasAuth ? cred.split(':') : [null, null];
    const [host, port = 443] = server.split(':');
    const result = { user, pass, host, port: +port };
    SK_CACHE.set(path, result);
    return result;
}

async function sConnect(targetHost, targetPort, skJson) {
    const sock = connect({ hostname: skJson.host, port: skJson.port });
    await sock.opened;
    sock.closed.catch(() => {});
    const w = sock.writable.getWriter(), r = sock.readable.getReader();
    await w.write(new Uint8Array([5, 2, 0, 2]));
    const auth = (await r.read()).value;
    if (auth[1] === 2 && skJson.user) {
        const user = te.encode(skJson.user), pass = te.encode(skJson.pass);
        await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
        await r.read();
    }
    const domain = te.encode(targetHost);
    await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]));
    await r.read();
    w.releaseLock(); r.releaseLock();
    return sock;
}

async function _getECH(h){try{const ps=h.split('.'),bs=[];for(const l of ps){const e=new TextEncoder().encode(l);bs.push(e.length,...e);}bs.push(0);const dn=new Uint8Array(bs);const pk=new Uint8Array(12+dn.length+4);const dv=new DataView(pk.buffer);dv.setUint16(0,Math.random()*65535|0);dv.setUint16(2,256);dv.setUint16(4,1);pk.set(dn,12);dv.setUint16(12+dn.length,65);dv.setUint16(14+dn.length,1);const rp=await fetch(ECH_DNS,{method:'POST',headers:{'Content-Type':'application/'+'dns'+'-message',Accept:'application/'+'dns'+'-message'},body:pk});if(!rp.ok)return null;const bf=new Uint8Array(await rp.arrayBuffer());const rv=new DataView(bf.buffer);const qc=rv.getUint16(4),ac=rv.getUint16(6);const sn=p=>{let c=p;while(c<bf.length){const n=bf[c];if(!n)return c+1;if((n&0xC0)===0xC0)return c+2;c+=n+1;}return c+1;};let o=12;for(let i=0;i<qc;i++)o=sn(o)+4;for(let i=0;i<ac&&o<bf.length;i++){o=sn(o);const tp=rv.getUint16(o);o+=2;o+=6;const rl=rv.getUint16(o);o+=2;if(tp===65){const rd=bf.slice(o,o+rl);let p=2;while(p<rd.length){const n=rd[p];if(!n){p++;break;}p+=n+1;}while(p+4<=rd.length){const k=(rd[p]<<8)|rd[p+1],ln=(rd[p+2]<<8)|rd[p+3];p+=4;if(k===5)return'-----BEGIN ECH CONFIGS-----\n'+btoa(String.fromCharCode(...rd.slice(p,p+ln)))+'\n-----END ECH CONFIGS-----';p+=ln;}}o+=rl;}return null;}catch{return null;}}

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

const vSB=t=>{try{return Array.isArray(JSON.parse(t).outbounds)}catch{return!1}};

function pSB(x, echCfg, h, FP, tp){
    try {
        const j=JSON.parse(x), o=j['outbounds']||[];
        for(const b of o) {
            if(b.type!=='vless'&&b.type!=='vmess') continue;
            if(b.uuid!==myID && b.server_name!==myID) continue;
            if(!b.tls) b.tls={};
            b.tls.server_name = h; 
            b.tls.utls = {enabled:true, fingerprint:FP};
            if(echCfg){ b.tls.ech={enabled:true, config:[echCfg]}; }
            
            if (TYPE === 'xhttp') {
                if (!b.transport) b.transport = {};
                b.transport.type = 'xhttp';
                b.transport.host = h;
                b.transport.path = tp;
                b.transport.extra = JSON.parse(xhttpExtra);
            } else if(b.transport && (b.transport.type === 'ws' || b.transport.type === 'http')) {
                if(!b.transport.headers) b.transport.headers = {};
                b.transport.headers.Host = h;
                b.transport.path = tp;
            }
        }
        return JSON.stringify(j);
    } catch { return x; }
}

function pCL(x, h, FP, tp){
    try {
        if(!ECH && TYPE !== 'xhttp') return x; 
        let y=x;
        if(!/^dns:\s*(?:\n|$)/m.test(y))y='dns:\n  enable: true\n  default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n  use-hosts: true\n  nameserver:\n    - https://sm2.doh.pub/dns-query\n    - https://dns.alidns.com/dns-query\n  fallback:\n    - 8.8.4.4\n    - 208.67.220.220\n  fallback-filter:\n    geoip: true\n    geoip-code: CN\n    ipcidr:\n      - 240.0.0.0/4\n      - 0.0.0.0/32\n    domain:\n      - \'+.google.com\'\n      - \'+.youtube.com\'\n'+y;
        const ls=y.split('\n');let di=-1,iD=false;
        for(let i=0;i<ls.length;i++){if(/^dns:\s*$/.test(ls[i])){iD=true;continue;}if(iD&&/^[a-zA-Z]/.test(ls[i])){di=i;break;}}
        const ne='    "'+h+'":\n      - '+ECH_DNS+'\n    "'+ECH_SNI+'":\n      - '+ECH_DNS;
        if(ECH) {
            if(/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(y)){y=y.replace(/^(\s{2}nameserver-policy:\s*\n)/m,'$1'+ne+'\n');}
            else if(di>0){ls.splice(di,0,'  nameserver-policy:',ne);y=ls.join('\n');}
        }
        
        const L=y.split('\n'),R=[];let i=0;
        while(i<L.length){
            const l=L[i],tl=l.trim();
            if(tl.startsWith('- {')&&tl.includes('uuid:')){
                let fn=l;
                const um=fn.match(/uuid:\s*([^,}\n]+)/);
                if(um&&um[1].trim()===myID.trim()){
                    fn=fn.replace(/client-fingerprint:\s*[^,}\s]+/,'client-fingerprint: ' + FP);
                    if(ECH) fn=fn.replace(/\}(\s*)$/,`, ech-opts: {enable: true, query-server-name: ${ECH_SNI}}}$1`);
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
                R.push(fn);i++;
            }else if(tl.startsWith('- name:')){
                let nl=[l];i++;
                while(i<L.length && L[i].search(/\S/)>(l.search(/\S/))){nl.push(L[i]);i++;}
                const nodeText = nl.join('\n');
                const um=nodeText.match(/uuid:\s*([^\n]+)/);
                if(um&&um[1].trim()===myID.trim()){
                    for(let j=0;j<nl.length;j++){
                        if(/client-fingerprint:/.test(nl[j])){
                            nl[j]=nl[j].replace(/client-fingerprint:\s*\S+/,'client-fingerprint: ' + FP);
                        }
                        if(/^\s*path:/i.test(nl[j])){
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
                    let ii=-1;
                    for(let j=nl.length-1;j>=0;j--)if(nl[j].trim()){ii=j;break;}
                    if(ii>=0){
                        const ind=' '.repeat(l.search(/\S/)+2);
                        let appendLines = [];
                        if (ECH) {
                            appendLines.push(ind+'ech-opts:', ind+'  enable: true', ind+'  query-server-name: '+ECH_SNI);
                        }
                        if (TYPE === 'xhttp') {
                            if (!nodeText.includes('xhttp-opts:')) appendLines.push(ind+'xhttp-opts:');
                            appendLines.push(ind+'  extra:', ind+'    xPaddingObfsMode: true', ind+'    xPaddingMethod: tokenish', ind+'    xPaddingPlacement: queryInHeader', ind+`    xPaddingHeader: "${padHeader}"`, ind+`    xPaddingKey: "${padKey}"`);
                        }
                        nl.splice(ii+1,0,...appendLines);
                    }
                }
                R.push(...nl);
            }else{R.push(l);i++;}
        }
        return R.join('\n');
    } catch { return x; }
}

async function hSub(r,c,u,UA,h){
    const now=Date.now();
    let up=SUB.trim()||h;
    
    // 注入用户要求的默认 ProxyIP 及其伪装路径
    let pip = u.searchParams.get("proxyip") || "180.214.180.226:444"; 
    let tp = (pip && pip.trim()) ? `/proxyip=${pip.trim()}` : "/";
    
    const _gDU=()=>{
        if(!ST) return null;
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
            if(ECH) uu.searchParams.set('ech', ECH_SNI + '+' + ECH_DNS);
            uu.hash = 'Worker';
            return `https://${up}/sub?base=${encodeURIComponent(uu.toString())}&token=${encodeURIComponent(ST)}`;
        } catch { return null; }
    };

    if(UA.includes('box')||UA.includes('hiddify')){
        const dU=_gDU();
        const bU=`${SUBAPI}/sub?target=singbox&url=${encodeURIComponent(dU || `https://${h}/${myID}?flag=true${pip?`&proxyip=${encodeURIComponent(pip)}`:''}`)}&config=${encodeURIComponent(SBV11)}&emoji=true&_t=${now}`;
        const o=await fetch(bU);if(!o.ok)return new Response("Err",{status:500});
        let echCfg=null;if(ECH)echCfg=await _getECH(ECH_SNI);
        return new Response(pSB(await o.text(), echCfg, h, FP, tp),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}});
    }
    if(UA.includes('clash')||UA.includes('mihomo')){
        const dU=_gDU();
        const a=`${SUBAPI}/sub?target=clash&url=${encodeURIComponent(dU || `https://${h}/${myID}?flag=true${pip?`&proxyip=${encodeURIComponent(pip)}`:''}`)}&config=${encodeURIComponent(SUBINI)}&emoji=true&_t=${now}`;
        const s=await fetch(a);if(!s.ok)return new Response("Err",{status:500});
        return new Response(pCL(await s.text(), h, FP, tp),{status:200,headers:{"Content-Type":"text/yaml; charset=utf-8"}});
    }
    
    if(ST){
        const _su=_gDU();
        try{
            const e=await fetch(_su,{headers:{"User-Agent":"Mozilla/5.0"}});
            if(e.ok){
                let t=await e.text();
                try{ t=atob(t); }catch{}
                t = t.split('\n').map(l => fixVless(l, h, tp, FP, ECH, ECH_SNI, ECH_DNS)).join('\n');
                return new Response(btoa(t),{status:200,headers:{"Content-Type":"text/plain; charset=utf-8"}});
            }
        }catch{}
        return new Response("Err",{status:502,headers:{"Content-Type":"text/plain; charset=utf-8"}});
    }

    const p=new URLSearchParams();
    p.append('uuid',myID);
    p.append("host",up);
    p.append("sni",h);
    p.append("path",tp);
    p.append("type",TYPE);
    if(TYPE === 'xhttp') {
        p.append("mode", "stream-one");
        p.append("extra", xhttpExtra);
    }
    p.append('encryption',"none");
    p.append('security','tls');
    p.append('alpn',"h2,http/1.1");
    p.append("fp",FP);
    if(ECH) p.append('ech',ECH_SNI+'+'+ECH_DNS);

    try{
        const e=await fetch(`https://${up}/sub?${p.toString()}`,{headers:{"User-Agent":"Mozilla/5.0"}});
        if(e.ok){
            let t=await e.text();
            try{ t=atob(t); }catch{}
            t = t.split('\n').map(l => fixVless(l, h, tp, FP, ECH, ECH_SNI, ECH_DNS)).join('\n');
            return new Response(btoa(t),{status:200,headers:{"Content-Type":"text/plain; charset=utf-8"}});
        }
    }catch{}
    
    return new Response("Err",{status:502,headers:{"Content-Type":"text/plain; charset=utf-8"}});
}
