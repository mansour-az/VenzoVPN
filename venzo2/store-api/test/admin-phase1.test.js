import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { readFileSync } from 'node:fs';
import { AdminState, adminState } from '../src/admin-state.js';
import { phaseOneRouter, normalizeDocument, normalizeAnnouncements, publicManagedLines, totp } from '../src/admin-phase1.js';
import { requireOwnerSession } from '../src/admin-phase1.js';
globalThis.crypto ||= webcrypto;

class Storage {
  data = new Map(); queue = Promise.resolve(); alarm = null;
  async get(k) { return structuredClone(this.data.get(k)); }
  async put(k, v) { this.data.set(k, structuredClone(v)); }
  async delete(k) { return this.data.delete(k); }
  async list({ prefix = '', end = '\uffff', limit = Infinity } = {}) {
    return new Map([...this.data].filter(([k]) => k.startsWith(prefix) && k < end)
      .sort(([a], [b]) => a.localeCompare(b)).slice(0, limit).map(([k,v])=>[k,structuredClone(v)]));
  }
  transaction(fn) { const run = this.queue.then(() => fn(this)); this.queue = run.catch(() => {}); return run; }
  async getAlarm() { return this.alarm; }
  async setAlarm(value) { this.alarm = value; }
}
function setup(legacy = {}) {
  const storage = new Storage();
  const env = { ADMIN_LOGIN_SECRET: 'test-only-password-with-more-than-32-characters',
    ADMIN_TOTP_SECRET: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', PROVISION_SECRET: 'old-provision-test',
    ORDERS: { get: async k => structuredClone(legacy[k] ?? null) } };
  const object = new AdminState({ storage }, env);
  env.ADMIN_STATE = { idFromName: x => x, get: () => ({ fetch: (url, init) => object.fetch(new Request(url, init)) }) };
  return { env, storage, object };
}
const origin = 'https://venzo.example';
function request(path, method = 'GET', body, cookie = '', extra = {}) {
  return new Request(origin + path, { method, headers: {
    origin, 'content-type': 'application/json', cookie, ...extra,
  }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
}
async function login(env) {
  const response = await phaseOneRouter(request('/v1/internal/admin/login', 'POST', {
    secret: env.ADMIN_LOGIN_SECRET,
    otp: await totp(env.ADMIN_TOTP_SECRET, Math.floor(Date.now() / 30000)),
  }), env);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('set-cookie'), /Secure; HttpOnly; SameSite=Strict/);
  return response.headers.get('set-cookie').split(';')[0];
}
const group = (extra = {}) => ({ id: 'test', name: 'test', configs: ['vless://id@example.org:443#node'], ...extra });
const document = (extra = {}) => ({ groups: [group()], policy: { enabled: true, order: ['normal','masque','warp','wireguard'] }, ...extra });

test('TOTP matches published RFC6238 SHA1 vectors', async () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  for (const [time, code] of [[59,'94287082'],[1111111109,'07081804'],[1111111111,'14050471'],[1234567890,'89005924'],[2000000000,'69279037']]) {
    assert.equal(await totp(secret, Math.floor(time / 30), 8), code);
  }
});
test('owner login fails closed, checks origin, rejects provision bearer and old cookies', async () => {
  const {env} = setup();
  for (const headers of [{authorization: 'Bearer '+env.PROVISION_SECRET},{cookie:'venzo_admin='+'a'.repeat(64)}]) {
    assert.equal((await phaseOneRouter(request('/v1/internal/admin/configs','GET',undefined,'',headers),env)).status,401);
    assert.equal((await requireOwnerSession(request('/v1/free/sources','GET',undefined,'',headers),env)).status,401);
  }
  assert.equal((await phaseOneRouter(request('/v1/internal/admin/login','POST',{},'',{origin:'https://evil.example'}),env)).status,403);
  assert.equal((await phaseOneRouter(request('/v1/internal/admin/login','POST',{}),{...env,ADMIN_TOTP_SECRET:''})).status,503);
  const cookie = await login(env);
  assert.equal((await phaseOneRouter(request('/v1/internal/admin/session','GET',undefined,cookie),env)).status,200);
  const reused = await phaseOneRouter(request('/v1/internal/admin/login','POST',{
    secret:env.ADMIN_LOGIN_SECRET,otp:await totp(env.ADMIN_TOTP_SECRET,Math.floor(Date.now()/30000)),
  }),env);
  assert.equal((await reused.json()).error,'OTP_ALREADY_USED');
  await phaseOneRouter(request('/v1/internal/admin/revoke','POST',{},cookie),env);
  assert.equal((await phaseOneRouter(request('/v1/internal/admin/session','GET',undefined,cookie),env)).status,401);
});
test('password rotation revokes existing sessions and rate limits login', async () => {
  const {env} = setup(); const cookie = await login(env);
  env.ADMIN_LOGIN_SECRET += 'rotated';
  assert.equal((await phaseOneRouter(request('/v1/internal/admin/session','GET',undefined,cookie),env)).status,401);
  let response;
  for(let i=0;i<9;i++) response=await phaseOneRouter(request('/v1/internal/admin/login','POST',{secret:'bad',otp:'000000'}),env);
  assert.equal(response.status,429);
});
test('legacy config migration preserves data; preview, optimistic publish, restore, expiry', async () => {
  const old={groups:[group()]}; const {env}=setup({'configs:managed:v1':old}); const cookie=await login(env);
  const get=()=>phaseOneRouter(request('/v1/internal/admin/configs','GET',undefined,cookie),env);
  const first=await (await get()).json(); assert.equal(first.groups.length,1);
  const input={...document({groups:[group({id:'new',transport:'warp',configs:['wireguard://key@example.org:2408'],expires_at:Date.now()+60000})]}),revision:first.revision};
  const preview=await (await phaseOneRouter(request('/v1/internal/admin/configs/preview','POST',input,cookie),env)).json();
  const publish=()=>phaseOneRouter(request('/v1/internal/admin/configs/publish','POST',{...input,fingerprint:preview.fingerprint},cookie),env);
  const responses=await Promise.all([publish(),publish()]);
  assert.deepEqual(responses.map(r=>r.status).sort(),[200,409]);
  assert.match((await publicManagedLines(env))[0],/#WARP-/);
  const policy=await (await phaseOneRouter(request('/v1/connection-policy'),env)).json();
  assert.equal(policy.groups,undefined); assert.equal(policy.order[0],'normal');
  const restored=await adminState(env,'config_restore',{revision:2,target:1});
  assert.equal(restored.revision,3); assert.deepEqual(restored.groups,old.groups);
  await adminState(env,'config_publish',{revision:3,document:document({groups:[group({expires_at:1})]})});
  assert.deepEqual(await publicManagedLines(env),[]);
  assert.deepEqual(await env.ORDERS.get('configs:managed:v1'),old);
});
test('oversized legacy config stays active while panel and policy bootstrap safely', async () => {
  const configs=Array.from({length:1400},(_,i)=>`vless://${String(i).padStart(8,'0')}@example.org:443?security=tls&type=ws&path=%2F${'x'.repeat(40)}#legacy-${i}`);
  const old={groups:[group({configs})]}; const {env}=setup({'configs:managed:v1':old});
  const doc=await adminState(env,'config_get');
  assert.equal(doc.legacy_fallback,true); assert.deepEqual(doc.groups,[]);
  assert.deepEqual(await publicManagedLines(env),configs);
  const policy=await phaseOneRouter(request('/v1/connection-policy'),env);
  assert.equal(policy.status,200); assert.equal((await policy.json()).order[0],'normal');
  assert.deepEqual(await env.ORDERS.get('configs:managed:v1'),old);
});
test('invalid/duplicate config diagnostics cannot be published and transport restrictions hold', async () => {
  const parsed=normalizeDocument(document({groups:[group({configs:['garbage','vless://id@example.org:443#a','vless://id@example.org:443#b']})]}));
  assert.deepEqual(parsed.diagnostics,{invalid:1,duplicates:1,valid:1,enabled:1});
  assert.equal(normalizeDocument(document({groups:[group({transport:'masque'})]})).diagnostics.invalid,1);
  assert.throws(()=>normalizeDocument(document({policy:{order:['warp','normal','masque','wireguard']}})),/INVALID_FALLBACK/);
  const {env}=setup(); const cookie=await login(env);
  const response=await phaseOneRouter(request('/v1/internal/admin/configs/publish','POST',document({groups:[group({configs:['bad']})]}),cookie),env);
  assert.equal((await response.json()).error,'PREVIEW_HAS_REJECTED_LINES');
});
test('announcements retain legacy rows, filter schedules and reject unsafe links', async () => {
  const row={id:'old',title:'hello',body:'world',type:'news'};
  const {env}=setup({'announcements:current':[row]});
  assert.deepEqual((await adminState(env,'announcements_get')).announcements,[row]);
  const rows=normalizeAnnouncements({announcements:[row,{...row,id:'future',starts_at:Date.now()+100000},{...row,id:'disabled',enabled:false}]});
  await adminState(env,'announcements_put',{revision:0,announcements:rows});
  const publicRows=await (await phaseOneRouter(request('/v1/announcements'),env)).json();
  assert.deepEqual(publicRows.announcements.map(a=>a.id),['old']);
  assert.throws(()=>normalizeAnnouncements({announcements:[{...row,action_url:'javascript:alert(1)'}]}),/INVALID_ACTION_URL/);
  assert.throws(()=>normalizeAnnouncements({announcements:[{...row,starts_at:100,expires_at:50}]}),/INVALID_SCHEDULE/);
});
test('telemetry requires consent, drops extra private fields and deduplicates concurrent events', async () => {
  const {env,storage}=setup();
  const event={consent:true,install_id:'a'.repeat(32),event_id:'b'.repeat(32),app_version:'2.11.0',outcome:'success',transport:'masque',duration_ms:1200,error:'none'};
  const send=e=>phaseOneRouter(request('/v1/telemetry/connection','POST',e),env);
  assert.equal((await (await send({...event,consent:false})).json()).accepted,false);
  assert.equal(storage.data.size,0);
  await Promise.all(Array.from({length:8},()=>send({...event,ip:'192.0.2.10',config:'PRIVATE_CONFIG',destination:'private.example'})));
  const quality=await adminState(env,'quality');
  assert.equal(quality.days.at(-1).success,1);
  assert.equal(quality.days.at(-1).success_duration_ms,1200);
  const stored=JSON.stringify([...storage.data]);
  for(const value of ['192.0.2.10','PRIVATE_CONFIG','private.example']) assert.ok(!stored.includes(value));
  await Promise.all(Array.from({length:20},(_,i)=>adminState(env,'connection',{...event,event_id:String(i).padStart(32,'0')})));
  assert.equal((await adminState(env,'quality')).days.at(-1).attempts,21);
  await Promise.all(Array.from({length:20},()=>adminState(env,'open',{install_id:event.install_id})));
  assert.equal((await adminState(env,'opens')).days[0].opens,20);
  assert.equal((await adminState(env,'opens')).days[0].unique,1);
});
test('expiry alarm removes expired storage but preserves renewed rates',async()=>{
  const {storage,object}=setup(); const old=Date.now()-1000;
  await storage.put('event:old',true); await storage.put(`expiry:${old}:event:old`,'event:old');
  await storage.put('rate:new',{until:Date.now()+100000}); await storage.put(`expiry:${old}:rate:new`,'rate:new');
  await object.alarm(); assert.equal(await storage.get('event:old'),undefined);
  assert.ok(await storage.get('rate:new'));
});
test('owner page ships parseable JS, restrictive CSP and no interpolated private data',async()=>{
  const response=await phaseOneRouter(request('/admin'),{});
  const html=await response.text(); const script=html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1];
  assert.doesNotThrow(()=>new Function(script));
  assert.match(response.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  assert.ok(!script.includes('innerHTML'));
  assert.ok(!html.includes('test-only-password'));
});

test('served login script boots, submits, shows rejection and opens dashboard', async () => {
  const html = process.env.VENZO_ADMIN_HTML
    ? readFileSync(process.env.VENZO_ADMIN_HTML, 'utf8')
    : await (await phaseOneRouter(request('/admin'), {})).text();
  let script = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1];
  // Exercise the same helper dependency introduced by Wrangler keepNames.
  // VENZO_ADMIN_HTML additionally allows testing the actual deployed/bundled page.
  if (!process.env.VENZO_ADMIN_HTML) script = script.replace('function ownerClient() {', 'function ownerClient() { __name(() => {}, "fixture");');
  const elements = new Map();
  const element = id => ({ id, hidden: false, value: id === 'period' ? '7' : '', textContent: '', handlers: {},
    classList: { toggle() {} }, addEventListener(event, handler) { this.handlers[event] = handler; },
    replaceChildren() {}, append() {}, reset() {}, setAttribute() {} });
  for (const match of html.matchAll(/id="([^"]+)"/g)) elements.set(match[1], element(match[1]));
  const calls = [];
  let acceptLogin = false;
  runInNewContext(script, {
    document: { getElementById: id => elements.get(id), querySelectorAll: () => [], createElement: () => element('') },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith('/session')) return { ok: false, status: 401, json: async () => ({ error: 'LOGIN_REQUIRED' }) };
      if (url.endsWith('/login')) return { ok: acceptLogin, status: acceptLogin ? 200 : 401, json: async () => acceptLogin ? { authenticated: true } : { error: 'INVALID_CREDENTIALS' } };
      return { ok: true, status: 200, json: async () => ({ days: [] }) };
    },
  });
  await new Promise(resolve => setImmediate(resolve));
  const form = elements.get('loginForm');
  assert.equal(typeof form.handlers.submit, 'function');
  elements.get('secret').value = 'fixture-password';
  elements.get('otp').value = '123456';
  const submitter = element('submit');
  const submit = () => form.handlers.submit({ preventDefault() {}, submitter, currentTarget: form });
  await submit();
  assert.equal(elements.get('message').hidden, false);
  assert.match(elements.get('message').textContent, /نادرست/);
  assert.equal(submitter.disabled, false);
  const sent = calls.find(c => c.url.endsWith('/login'));
  assert.equal(sent.options.method, 'POST');
  assert.deepEqual(JSON.parse(sent.options.body), { secret: 'fixture-password', otp: '123456' });
  acceptLogin = true;
  await submit();
  assert.equal(elements.get('app').hidden, false);
  assert.equal(elements.get('login').hidden, true);
  assert.equal(elements.get('secret').value, '');
  assert.equal(elements.get('otp').value, '');
});
