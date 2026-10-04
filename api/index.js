'use strict';
// Report Card System API - Vercel serverless function (Node) + Supabase Postgres.
// This is a port of the original api.php. The front-end (index.html) is unchanged:
// vercel.json rewrites /api.php?a=... to this function.

const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

/* ---------- small helpers ---------- */
class Out extends Error { constructor(d, c = 200) { super('out'); this.d = d; this.c = c; } }
const out = (d, c = 200) => { throw new Out(d, c); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const env = (k, d = '') => process.env[k] ?? d;
const conv = sql => { let i = 0; return sql.replace(/\?/g, () => '$' + (++i)); };
const validText = (v, max = 150) => { v = String(v ?? '').trim(); return v !== '' && [...v].length <= max && !/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(v); };
const jparse = (s, d) => { try { const x = JSON.parse(s); return x ?? d; } catch { return d; } };
const fmt = c => `to_char(${c} AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')`;
const SESSION_TTL = 12 * 3600;
const BACKUP_TABLES = ['settings', 'users', 'classes', 'students', 'scores', 'info', 'login_attempts', 'audit_log', 'recycle_bin', 'password_recovery', 'recovery_attempts', 'sms_messages', 'email_messages'];

let pool;
const getPool = () => pool ??= new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: env('DATABASE_SSL') === 'off' ? false : { rejectUnauthorized: false },
  max: 3, idleTimeoutMillis: 10000
});

/* ---------- signed-cookie session (replaces PHP sessions) ---------- */
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
function signSession(p) {
  const body = b64({ ...p, exp: Math.floor(Date.now() / 1000) + SESSION_TTL });
  return body + '.' + crypto.createHmac('sha256', process.env.SESSION_SECRET).update(body).digest('base64url');
}
function readSession(req) {
  try {
    const m = /(?:^|;\s*)rcs=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return {};
    const [body, sig] = m[1].split('.'); if (!body || !sig) return {};
    const good = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(body).digest('base64url');
    const a = Buffer.from(sig), b = Buffer.from(good);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return {};
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() / 1000 ? p : {};
  } catch { return {}; }
}

/* ---------- Ghana phone + SMS (Arkesel) ---------- */
function smsNormalizeGhana(phone) {
  let p = String(phone ?? '').trim().replace(/[\s\-()]/g, '');
  if (p === '') return '';
  if (p.startsWith('+233')) p = p.slice(1);
  else if (p.startsWith('00233')) p = p.slice(2);
  else if (p.startsWith('0') && p.length === 10) p = '233' + p.slice(1);
  return /^233\d{9}$/.test(p) ? p : '';
}
async function smsSendArkesel(recipient, message, sender) {
  if (env('SMS_ENABLED', 'true') === 'false') throw new Error('SMS gateway is disabled.');
  const key = env('ARKESEL_API_KEY').trim();
  if (!key) throw new Error('Arkesel API key is not configured (ARKESEL_API_KEY).');
  let r, data;
  try {
    r = await fetch('https://sms.arkesel.com/api/v2/sms/send', {
      method: 'POST', headers: { 'api-key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender, message, recipients: [recipient] }), signal: AbortSignal.timeout(30000)
    });
    data = await r.json().catch(() => null);
  } catch (e) { throw new Error('SMS gateway connection failed: ' + e.message); }
  if (!r.ok || !data || String(data.status ?? '').toLowerCase() !== 'success')
    throw new Error('SMS send failed: ' + (data ? (data.message ?? 'The SMS gateway rejected the request.') : 'Invalid SMS gateway response.'));
  const id = data?.data?.[0]?.id ?? data?.data?.id ?? '';
  return { message_id: String(id) };
}

/* ---------- email (Gmail SMTP) ---------- */
function mailer() {
  if (!env('SMTP_USER') || !env('SMTP_PASS')) throw new Error('Email is not configured (SMTP_USER / SMTP_PASS).');
  return nodemailer.createTransport({
    host: env('SMTP_HOST', 'smtp.gmail.com'), port: Number(env('SMTP_PORT', '587')), secure: false, requireTLS: true,
    auth: { user: env('SMTP_USER'), pass: env('SMTP_PASS') }, connectionTimeout: 15000, socketTimeout: 20000
  });
}
const mailFrom = () => env('MAIL_FROM', env('SMTP_USER'));
const cleanHeader = (v, max = 255) => String(v ?? '').replace(/[\r\n]/g, '').trim().slice(0, max);
const isEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v)) && String(v).length <= 254;

/* ======================================================================= */
module.exports = async function handler(req, res) {
  const ctx = { client: null };
  let sess = {}, dirty = false, clear = false;

  const send = (d, c) => {
    res.statusCode = c;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    const secure = (req.headers['x-forwarded-proto'] || '') === 'https' || !!process.env.VERCEL;
    const base = 'rcs=%s; Path=/; HttpOnly; SameSite=Lax' + (secure ? '; Secure' : '');
    if (clear) res.setHeader('Set-Cookie', base.replace('%s', '') + '; Max-Age=0');
    else if (dirty) res.setHeader('Set-Cookie', base.replace('%s', signSession(sess)) + '; Max-Age=' + SESSION_TTL);
    res.end(JSON.stringify(d));
  };

  /* --- database helpers (per request) --- */
  const q = (sql, p = []) => (ctx.client || getPool()).query(conv(sql), p);
  const rows = async (s, p) => (await q(s, p)).rows;
  const one = async (s, p) => (await q(s, p)).rows[0] || null;
  const col = async (s, p) => { const r = await one(s, p); return r ? Object.values(r)[0] : null; };
  const begin = async () => { ctx.client = await getPool().connect(); await ctx.client.query('BEGIN'); };
  const commit = async () => { await ctx.client.query('COMMIT'); ctx.client.release(); ctx.client = null; };
  const rollback = async () => { if (ctx.client) { try { await ctx.client.query('ROLLBACK'); } catch { } ctx.client.release(); ctx.client = null; } };

  const ip = () => String(((req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress || 'unknown')).trim().slice(0, 64) || 'unknown';
  const pub = u => ({ id: u.id, name: u.name, username: u.username, role: u.role, assign: jparse(u.assign || '[]', []), must: !!u.must_change });

  async function audit(actor, action, target = '', details = '') {
    try { await q('INSERT INTO audit_log(actor_id,action,target,details) VALUES(?,?,?,?)', [actor || null, action, String(target).slice(0, 180), String(details).slice(0, 1000)]); }
    catch (e) { console.error(e); }
  }
  async function loginWait(u, ipa) {
    const r = await one('SELECT * FROM login_attempts WHERE username=? AND ip=?', [u, ipa]);
    return r && r.locked_until && new Date(r.locked_until) > new Date() ? Math.max(1, Math.ceil((new Date(r.locked_until) - Date.now()) / 60000)) : 0;
  }
  async function bumpAttempts(table, u, ipa) {
    const r = await one(`SELECT * FROM ${table} WHERE username=? AND ip=?`, [u, ipa]); const now = new Date();
    if (!r || now - new Date(r.first_at) > 900000) {
      await q(`INSERT INTO ${table}(username,ip,attempts,first_at,last_at,locked_until) VALUES(?,?,1,?,?,NULL) ON CONFLICT(username,ip) DO UPDATE SET attempts=1,first_at=EXCLUDED.first_at,last_at=EXCLUDED.last_at,locked_until=NULL`, [u, ipa, now, now]);
      return false;
    }
    const n = Number(r.attempts) + 1, lock = n >= 5 ? new Date(Date.now() + 900000) : null;
    await q(`UPDATE ${table} SET attempts=?,last_at=?,locked_until=? WHERE username=? AND ip=?`, [n, now, lock, u, ipa]);
    return !!lock;
  }
  const loginFail = (u, ipa) => bumpAttempts('login_attempts', u, ipa);
  const loginOk = (u, ipa) => q('DELETE FROM login_attempts WHERE username=? AND ip=?', [u, ipa]);
  async function recyclePut(actor, type, id, label, payload) {
    const rid = 'rb' + crypto.randomBytes(12).toString('hex');
    await q('INSERT INTO recycle_bin(id,entity_type,entity_id,label,payload,actor_id) VALUES(?,?,?,?,?,?)', [rid, type, id, String(label).slice(0, 180), JSON.stringify(payload), actor]);
    return rid;
  }

  try {
    if (!env('DATABASE_URL')) out({ error: 'Server is not configured: DATABASE_URL is missing.' }, 500);
    if (!env('SESSION_SECRET') || env('SESSION_SECRET').length < 20) out({ error: 'Server is not configured: SESSION_SECRET is missing or too short.' }, 500);
    if (!req.headers['x-rcs']) out({ error: 'Bad request' }, 400);
    sess = readSession(req);
    let inp = req.body;
    if (typeof inp === 'string') inp = jparse(inp, {});
    if (!inp || typeof inp !== 'object') inp = {};
    const a = String(new URL(req.url, 'http://x').searchParams.get('a') || '');

    /* ---------------- public actions ---------------- */
    if (a === 'parent_login') {
      const adm = String(inp.adm ?? '').trim(), phone = String(inp.phone ?? '').replace(/[^0-9+]/g, '');
      if (adm === '' || phone === '') out({ error: 'Enter the admission number and guardian phone number.' }, 422);
      const ipa = ip(), key = 'parent:' + adm.slice(0, 100);
      const wait = await loginWait(key, ipa);
      if (wait) out({ error: `Too many failed attempts. Try again in about ${wait} minutes.` }, 429);
      const fail = async msg => { await loginFail(key, ipa); await sleep(300); out({ error: msg }, 401); };
      const seed = await one('SELECT * FROM students WHERE adm=? LIMIT 1', [adm]);
      if (!seed) await fail('Student ID or admission number was not found.');
      const norm = p => smsNormalizeGhana(p) || String(p ?? '').replace(/[^0-9+]/g, '');
      const want = norm(phone);
      const irows = await rows('SELECT student_id,data FROM info WHERE student_id IN (SELECT id FROM students WHERE adm IS NOT NULL)');
      const matched = new Set();
      for (const r of irows) {
        const d = jparse(r.data, {});
        for (const k of ['guardianPhone', 'altPhone']) if (d[k] && norm(d[k]) === want) matched.add(r.student_id);
      }
      if (!matched.has(seed.id)) await fail('The guardian phone number does not match the school record for this student.');
      await loginOk(key, ipa);
      const ids = [...matched];
      const students = await rows(`SELECT id,name,sex,COALESCE(adm,'') AS adm,class_id AS "classId" FROM students WHERE id = ANY(?) ORDER BY name`, [ids]);
      const classes = await rows('SELECT * FROM classes ORDER BY LENGTH(name),name');
      const cl = classes.map(c => ({ id: c.id, name: c.name, teacherId: c.teacher_id ?? '', subjects: jparse(c.subjects, []) }));
      const sc = {};
      for (const r of await rows('SELECT * FROM scores WHERE student_id = ANY(?)', [ids]))
        sc[`${r.year}|${r.term}|${r.student_id}|${r.subject}`] = { c: r.class_score === null ? null : parseFloat(r.class_score), e: r.exam_score === null ? null : parseFloat(r.exam_score) };
      const inf = {};
      for (const r of await rows('SELECT * FROM info WHERE student_id = ANY(?)', [ids])) inf[`${r.year}|${r.term}|${r.student_id}`] = jparse(r.data, {});
      const set = jparse(await col("SELECT v FROM settings WHERE k='main'"), {});
      // class positions (rank by average of fully-scored students)
      const positions = {};
      const classCache = {};
      for (const pst of students) {
        const pc = cl.find(c => c.id === pst.classId); if (!pc) continue;
        if (!classCache[pc.id]) {
          const members = (await rows('SELECT id FROM students WHERE class_id=?', [pc.id])).map(x => x.id);
          const sr = members.length ? await rows('SELECT student_id,term,subject,class_score,exam_score FROM scores WHERE year=? AND student_id = ANY(?)', [set.year ?? '', members]) : [];
          classCache[pc.id] = { members, sr };
        }
        const { members, sr } = classCache[pc.id];
        for (const tt of [1, 2, 3]) {
          const avgBy = {};
          for (const mid of members) {
            const vals = [];
            for (const subj of pc.subjects) {
              const rr = sr.find(x => x.student_id === mid && Number(x.term) === tt && x.subject === subj);
              if (rr && (rr.class_score !== null || rr.exam_score !== null)) vals.push(parseFloat(rr.class_score ?? 0) + parseFloat(rr.exam_score ?? 0));
            }
            if (vals.length === pc.subjects.length && vals.length > 0) avgBy[mid] = vals.reduce((x, y) => x + y, 0) / vals.length;
          }
          if (pst.id in avgBy) positions[`${pst.id}|${tt}`] = 1 + Object.values(avgBy).filter(v => v > avgBy[pst.id]).length;
        }
      }
      sess = { ...sess, parent_ids: ids }; dirty = true;
      const active = arr => (Array.isArray(arr) ? arr : []).filter(x => x && typeof x === 'object' && x.active !== false);
      out({
        ok: 1, parent: {
          school: { name: set.school ?? 'School', motto: set.motto ?? '', logo: set.logo ?? '' },
          year: set.year ?? '', term: Number(set.term ?? 1), terms: set.terms ?? [], scale: set.scale ?? [],
          students, classes: cl, scores: sc, info: inf, positions,
          announcements: active(set.announcements), calendarEvents: active(set.calendarEvents), selectedId: seed.id
        }
      });
    }
    if (a === 'parent_logout') { delete sess.parent_ids; dirty = true; out({ ok: 1 }); }

    if (a === 'request_recovery_code') {
      const u = String(inp.u ?? '').trim().toLowerCase(), email = String(inp.email ?? '').trim().toLowerCase(), ipa = ip();
      if (!/^[a-z0-9._-]{3,60}$/.test(u) || !isEmail(email)) out({ error: 'Enter a valid username and administrator email address.' }, 422);
      const ra = await one('SELECT * FROM recovery_attempts WHERE username=? AND ip=?', [u, ipa]);
      if (ra && ra.locked_until && new Date(ra.locked_until) > new Date()) out({ error: 'Too many recovery requests. Try again in about 15 minutes.' }, 429);
      const adminEmail = env('RECOVERY_ADMIN_EMAIL').trim().toLowerCase();
      const target = await one('SELECT id,username FROM users WHERE username=? LIMIT 1', [u]);
      if (!target || !adminEmail || adminEmail !== email) { await sleep(300); out({ ok: 1, message: 'If the details are valid, a recovery code has been sent to the administrator email.' }); }
      const hex = n => crypto.randomBytes(n).toString('hex').toUpperCase();
      const code = hex(4) + '-' + hex(4);
      await q(`INSERT INTO password_recovery(id,code_hash,created_at,expires_at,used_at,target_username) VALUES(1,?,?,?,NULL,?)
               ON CONFLICT(id) DO UPDATE SET code_hash=EXCLUDED.code_hash,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at,used_at=NULL,target_username=EXCLUDED.target_username`,
        [bcrypt.hashSync(code, 10), new Date(), new Date(Date.now() + 600000), u]);
      try {
        await mailer().sendMail({
          from: mailFrom(), to: adminEmail, subject: 'Jukwa Catholic D/A Basic School - Password Recovery Code',
          text: `Jukwa Catholic D/A Basic School\n\nAdministrator password recovery request\n\nStaff username: ${u}\nRecovery code: ${code}\n\nThis code expires in 10 minutes and can be used only once.\nIf you did not request this recovery code, please ignore this email.`
        });
      } catch (e) { console.error(e); out({ error: 'The recovery email could not be sent. Check the email settings (SMTP_USER / SMTP_PASS) in Vercel.' }, 503); }
      await audit(target.id, 'recovery_email_sent', u, 'Recovery code sent to the administrator email');
      out({ ok: 1, message: 'A recovery code has been sent to the administrator email.', masked_email: adminEmail.replace(/(^.).*(@.*$)/, '$1***$2') });
    }

    if (a === 'forgot_password') {
      const u = String(inp.u ?? '').trim().toLowerCase(), code = String(inp.code ?? '').trim(), nw = String(inp.new ?? ''), ipa = ip();
      if (!/^[a-z0-9._-]{3,60}$/.test(u) || code === '' || nw.length < 8) out({ error: 'Enter a valid username, recovery code and password of at least 8 characters.' }, 422);
      const ra = await one('SELECT * FROM recovery_attempts WHERE username=? AND ip=?', [u, ipa]);
      if (ra && ra.locked_until && new Date(ra.locked_until) > new Date()) out({ error: 'Too many recovery attempts. Try again in about 15 minutes.' }, 429);
      const rr = await one('SELECT * FROM password_recovery WHERE id=1');
      const expired = rr && rr.expires_at && new Date(rr.expires_at) < new Date();
      const target = await one('SELECT * FROM users WHERE username=? LIMIT 1', [u]);
      const targetMatch = rr && (rr.target_username ? rr.target_username.toLowerCase() === u : true);
      const ok = !!(rr && !rr.used_at && !expired && targetMatch && bcrypt.compareSync(code, rr.code_hash));
      if (!ok || !target) { await bumpAttempts('recovery_attempts', u, ipa); await sleep(300); out({ error: 'The username or recovery code is incorrect.' }, 401); }
      await q('UPDATE users SET pass=?,must_change=0 WHERE id=?', [bcrypt.hashSync(nw, 10), target.id]);
      await q('UPDATE password_recovery SET used_at=? WHERE id=1', [new Date()]);
      await q('DELETE FROM recovery_attempts WHERE username=? AND ip=?', [u, ipa]);
      await audit(target.id, 'password_recovered', u, 'Password reset using the school recovery code');
      out({ ok: 1, message: 'Password reset successfully.' });
    }

    if (a === 'login') {
      const uName = String(inp.u ?? '').trim().toLowerCase(), pw = String(inp.p ?? '');
      if (uName === '' || [...uName].length > 60 || pw === '') out({ error: 'Enter a valid username and password.' }, 422);
      if (Number(await col('SELECT COUNT(*) FROM users')) === 0)
        await q("INSERT INTO users(id,name,username,pass,role,assign,must_change) VALUES('admin1','Administrator','admin',?,'admin','[]',1) ON CONFLICT DO NOTHING", [bcrypt.hashSync(env('ADMIN_INITIAL_PASSWORD') || 'admin123', 10)]);
      const ipa = ip(), wait = await loginWait(uName, ipa);
      if (wait) out({ error: `Too many failed attempts. Try again in about ${wait} minutes.` }, 429);
      const u = await one('SELECT * FROM users WHERE username=?', [uName]);
      if (!u || !bcrypt.compareSync(pw, u.pass)) {
        const locked = await loginFail(uName, ipa);
        await audit(u?.id ?? null, 'login_failed', uName, locked ? 'Temporarily rate-limited' : 'Invalid credentials');
        await sleep(400);
        out({ error: locked ? 'Too many failed attempts. Try again in 15 minutes.' : 'Wrong username or password.' }, 401);
      }
      await loginOk(uName, ipa); sess = { uid: u.id }; dirty = true;
      await audit(u.id, 'login_success', uName, 'Successful sign-in'); out({ ok: 1 });
    }
    if (a === 'logout') { if (sess.uid) await audit(sess.uid, 'logout', 'session', 'User signed out'); clear = true; out({ ok: 1 }); }

    /* ---------------- signed-in actions ---------------- */
    const me = sess.uid ? await one('SELECT * FROM users WHERE id=?', [sess.uid]) : null;
    if (!me) out({ error: 'Please sign in.' }, 401);
    const adm = me.role === 'admin', manager = ['admin', 'headteacher'].includes(me.role), assign = jparse(me.assign || '[]', []);

    if (a === 'generate_recovery_code') {
      if (!adm) out({ error: 'Only the Administrator can generate a recovery code.' }, 403);
      const code = crypto.randomBytes(8).toString('hex').toUpperCase();
      await q(`INSERT INTO password_recovery(id,code_hash,created_at,expires_at,used_at,target_username) VALUES(1,?,?,?,NULL,NULL)
               ON CONFLICT(id) DO UPDATE SET code_hash=EXCLUDED.code_hash,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at,used_at=NULL,target_username=NULL`,
        [bcrypt.hashSync(code, 10), new Date(), new Date(Date.now() + 600000)]);
      await audit(me.id, 'recovery_code_generated', 'password_recovery', 'A new school password recovery code was generated');
      out({ ok: 1, code });
    }

    if (a === 'sms_send') {
      const phone = smsNormalizeGhana(inp.phone), message = String(inp.message ?? '').trim(), studentId = String(inp.studentId ?? '').trim();
      let studentName = String(inp.studentName ?? '').trim(); const template = String(inp.template ?? '').trim();
      const sender = String(inp.sender ?? env('SMS_SENDER', 'JukwaBasic')).trim();
      if (phone === '') out({ error: 'Enter a valid Ghana guardian phone number.' }, 422);
      if (message === '' || [...message].length > 1000) out({ error: 'SMS message must be between 1 and 1000 characters.' }, 422);
      if (!/^[A-Za-z0-9 ._-]{1,11}$/.test(sender)) out({ error: 'SMS sender ID must be 1-11 letters, numbers, spaces, dots, underscores or hyphens.' }, 422);
      if (studentId && !studentName) { const st = await one('SELECT name FROM students WHERE id=? LIMIT 1', [studentId]); if (st) studentName = st.name; }
      const log = (status, pid, err) => q(`INSERT INTO sms_messages(student_id,recipient,student_name,template,message,provider,provider_message_id,status,error_message,actor_id) VALUES(?,?,?,?,?,'arkesel',?,?,?,?)`,
        [studentId || null, phone, studentName || null, template || null, message, pid || null, status, err || null, me.id]);
      let r;
      try { r = await smsSendArkesel(phone, message, sender); }
      catch (e) {
        await log('failed', '', e.message); await audit(me.id, 'sms_failed', studentId || phone, e.message.slice(0, 500));
        out({ error: e.message }, 502);
      }
      await log('submitted', r.message_id, ''); await audit(me.id, 'sms_sent', studentId || phone, 'SMS submitted through Arkesel');
      out({ ok: 1, status: 'submitted', message_id: r.message_id, recipient: phone });
    }
    if (a === 'sms_history')
      out({ ok: 1, rows: await rows(`SELECT id,student_id,recipient,student_name,template,message,provider,provider_message_id,status,error_message,${fmt('created_at')} AS created_at FROM sms_messages ORDER BY id DESC LIMIT 200`) });

    if (a === 'email_send') {
      const email = String(inp.email ?? '').trim().toLowerCase(), message = String(inp.message ?? '').trim(), studentId = String(inp.studentId ?? '').trim();
      let studentName = String(inp.studentName ?? '').trim(); const template = String(inp.template ?? '').trim();
      const subject = String(inp.subject ?? '').trim(); let replyTo = String(inp.replyTo ?? '').trim();
      if (!isEmail(email)) out({ error: 'Enter a valid guardian email address.' }, 422);
      if (message === '' || [...message].length > 10000) out({ error: 'Email message must be between 1 and 10000 characters.' }, 422);
      if (subject === '' || [...subject].length > 180) out({ error: 'Email subject must be between 1 and 180 characters.' }, 422);
      if (replyTo !== '' && !isEmail(replyTo)) out({ error: 'The reply-to email address is not valid.' }, 422);
      if (studentId && !studentName) { const st = await one('SELECT name FROM students WHERE id=? LIMIT 1', [studentId]); if (st) studentName = st.name; }
      const log = (status, err) => q(`INSERT INTO email_messages(student_id,recipient,student_name,template,subject,message,provider,status,error_message,actor_id) VALUES(?,?,?,?,?,?,'smtp',?,?,?)`,
        [studentId || null, email, studentName || null, template || null, subject, message, status, err || null, me.id]);
      try { await mailer().sendMail({ from: mailFrom(), to: email, subject: cleanHeader(subject, 180) || 'School notification', text: message, replyTo: replyTo || undefined }); }
      catch (e) {
        await log('failed', String(e.message).slice(0, 500)); await audit(me.id, 'email_failed', studentId || email, String(e.message).slice(0, 500));
        out({ error: e.message }, 502);
      }
      await log('sent', ''); await audit(me.id, 'email_sent', studentId || email, 'Email sent through server SMTP');
      out({ ok: 1, status: 'sent', recipient: email });
    }
    if (a === 'email_history')
      out({ ok: 1, rows: await rows(`SELECT id,student_id,recipient,student_name,template,subject,message,provider,status,error_message,${fmt('created_at')} AS created_at FROM email_messages ORDER BY id DESC LIMIT 200`) });

    if (a === 'load') {
      const set = jparse(await col("SELECT v FROM settings WHERE k='main'"), null);
      const allCl = (await rows('SELECT * FROM classes ORDER BY LENGTH(name),name')).map(c => ({ id: c.id, name: c.name, teacherId: c.teacher_id ?? '', subjects: jparse(c.subjects, []) }));
      const ids = [...new Set([...assign.map(x => x.classId), ...allCl.filter(c => c.teacherId === me.id).map(c => c.id)])];
      const cl = manager ? allCl : allCl.filter(c => ids.includes(c.id));
      const w = manager ? '1=1' : (ids.length ? 'class_id = ANY(?)' : '1=0'), p = manager || !ids.length ? [] : [ids];
      const st = await rows(`SELECT id,name,sex,COALESCE(adm,'') AS adm,class_id AS "classId" FROM students WHERE ${w}`, p);
      const sub = `student_id IN (SELECT id FROM students WHERE ${w})`, sc = {};
      for (const r of await rows(`SELECT * FROM scores WHERE ${sub}`, p)) {
        const v = {}; if (r.class_score !== null) v.c = parseFloat(r.class_score); if (r.exam_score !== null) v.e = parseFloat(r.exam_score);
        sc[`${r.year}|${r.term}|${r.student_id}|${r.subject}`] = v;
      }
      const inf = {};
      for (const r of await rows(`SELECT * FROM info WHERE ${sub}`, p)) inf[`${r.year}|${r.term}|${r.student_id}`] = jparse(r.data, {});
      const us = manager ? (await rows("SELECT * FROM users WHERE role IN ('admin','headteacher','teacher') ORDER BY name")).map(pub) : [pub(me)];
      out({ me: me.id, DB: { settings: set, users: us, classes: cl, students: st, scores: sc, info: inf } });
    }

    if (a === 'addteacher' && adm) {
      const u = String(inp.username ?? '').trim().toLowerCase(), pw = String(inp.password ?? ''), nm = String(inp.name ?? '').trim(), role = String(inp.role ?? 'teacher');
      if (!validText(nm, 120) || !/^[a-z0-9._-]{3,60}$/.test(u) || !['teacher', 'headteacher'].includes(role) || pw.length < 8 || !/^[A-Za-z0-9._:-]{1,24}$/.test(String(inp.id ?? '')))
        out({ error: 'Enter a valid name, username, role and a password of at least 8 characters.' }, 422);
      if (await one('SELECT 1 FROM users WHERE username=?', [u])) out({ error: 'That username is taken.' }, 422);
      await q("INSERT INTO users(id,name,username,pass,role,assign,must_change) VALUES(?,?,?,?,?,'[]',1)", [inp.id, nm, u, bcrypt.hashSync(pw, 10), role]);
      await audit(me.id, 'staff_created', u, role + ' account created'); out({ ok: 1 });
    }

    if (a === 'setpw') {
      const nw = String(inp.new ?? ''); if (nw.length < 8) out({ error: 'New password must be at least 8 characters.' }, 422);
      let tid = me.id;
      if (adm && inp.id) tid = String(inp.id);
      else if (!bcrypt.compareSync(String(inp.old ?? ''), me.pass)) out({ error: 'Current password is wrong.' }, 422);
      if (!adm && tid !== me.id) out({ error: 'You may only change your own password.' }, 403);
      await q('UPDATE users SET pass=?,must_change=0 WHERE id=?', [bcrypt.hashSync(nw, 10), tid]);
      await audit(me.id, 'password_changed', tid, 'Password changed'); out({ ok: 1 });
    }

    if (a === 'backup_export' && adm) {
      const backup = { format: 'RCS-BACKUP-1', created_at: new Date().toISOString(), database: 'supabase', tables: {} };
      for (const t of BACKUP_TABLES) {
        try { backup.tables[t] = await rows(`SELECT * FROM "${t}"`); } catch (e) { console.error(e); out({ error: 'Backup failed while reading table: ' + t }, 500); }
      }
      await audit(me.id, 'backup_created', 'database', 'Full application database backup prepared'); out(backup);
    }
    if (a === 'backup_restore' && adm) {
      const backup = inp.backup;
      if (!backup || backup.format !== 'RCS-BACKUP-1' || typeof backup.tables !== 'object' || !backup.tables) out({ error: 'Invalid backup file.' }, 422);
      try {
        await begin();
        for (const t of [...BACKUP_TABLES].reverse()) await q(`DELETE FROM "${t}"`);
        for (const t of BACKUP_TABLES) {
          const rs = backup.tables[t] ?? []; if (!Array.isArray(rs)) throw new Error('Invalid backup data for ' + t);
          for (const row of rs) {
            if (!row || typeof row !== 'object' || !Object.keys(row).length) continue;
            const cols = Object.keys(row); if (cols.some(c => !/^[A-Za-z0-9_]+$/.test(c))) throw new Error('Invalid backup column.');
            await q(`INSERT INTO "${t}" (${cols.map(c => `"${c}"`).join(',')}) VALUES (${cols.map(() => '?').join(',')})`, cols.map(c => (row[c] !== null && typeof row[c] === 'object') ? JSON.stringify(row[c]) : row[c]));
          }
        }
        for (const t of ['audit_log', 'sms_messages', 'email_messages'])
          await q(`SELECT setval(pg_get_serial_sequence('${t}','id'), COALESCE((SELECT MAX(id) FROM ${t}),0)+1, false)`);
        await commit();
      } catch (e) { await rollback(); console.error(e); out({ error: 'Backup restore failed. No partial restore was committed.' }, 422); }
      await audit(me.id, 'backup_restored', 'database', 'Full application database backup restored');
      out({ ok: 1, message: 'Backup restored successfully. Please reload the application.' });
    }

    if (a === 'security' && adm) {
      let rb = [], au = []; const errors = [];
      try { rb = await rows(`SELECT id,entity_type,entity_id,label,${fmt('created_at')} AS created_at,actor_id FROM recycle_bin ORDER BY recycle_bin.created_at DESC LIMIT 500`); } catch (e) { errors.push('Recycle bin: ' + e.message); }
      try { au = await rows(`SELECT id,action,target,details,${fmt('created_at')} AS created_at,actor_id FROM audit_log ORDER BY audit_log.created_at DESC LIMIT 300`); } catch (e) { errors.push('Audit trail: ' + e.message); }
      const names = {}; for (const u of await rows('SELECT id,name FROM users')) names[u.id] = u.name;
      for (const x of rb) x.actor_name = (x.actor_id && names[x.actor_id]) || 'Administrator';
      for (const x of au) x.actor_name = (x.actor_id && names[x.actor_id]) || 'System';
      await audit(me.id, 'security_viewed', 'security', 'Security and recovery page opened');
      let rr = null; try { rr = await one(`SELECT ${fmt('created_at')} AS created_at,${fmt('used_at')} AS used_at FROM password_recovery WHERE id=1`); } catch { }
      out({ recycle: rb, audit: au, recovery: { configured: !!rr, created_at: rr?.created_at ?? null, used_at: rr?.used_at ?? null }, health: { tables: 3, rate_limit: true, recovery: true, audit: true }, errors });
    }
    if (a === 'security_health' && adm) {
      const checks = {};
      for (const t of ['login_attempts', 'audit_log', 'recycle_bin']) {
        try { checks[t] = Number(await col('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name=?', [t])) > 0; } catch { checks[t] = false; }
      }
      const ok = checks.login_attempts && checks.audit_log && checks.recycle_bin;
      await audit(me.id, 'security_check', 'security', ok ? 'All security tables exist and are ready' : 'One or more security tables are unavailable');
      out({ ok, tables: checks, message: ok ? 'Security services are working correctly.' : 'Security check found a database problem.' });
    }

    if (a === 'recycle_restore' && adm) {
      const id = String(inp.id ?? '').trim(), r = await one('SELECT * FROM recycle_bin WHERE id=?', [id]);
      if (!r) out({ error: 'Recycle item not found.' }, 404);
      const p = jparse(r.payload, {});
      try {
        await begin();
        if (r.entity_type === 'user') {
          const u = p.user; if (!u) throw new Error('Invalid user backup.');
          if (await one('SELECT 1 FROM users WHERE id=?', [u.id]) || await one('SELECT 1 FROM users WHERE username=?', [u.username])) throw new Error('That user or username already exists.');
          await q('INSERT INTO users(id,name,username,pass,role,assign,must_change) VALUES(?,?,?,?,?,?,?)', [u.id, u.name, u.username, u.pass, u.role, u.assign, u.must_change]);
        } else if (r.entity_type === 'class') {
          const c = p.class; if (!c) throw new Error('Invalid class backup.');
          if (await one('SELECT 1 FROM classes WHERE id=?', [c.id])) throw new Error('That class already exists.');
          await q('INSERT INTO classes(id,name,teacher_id,subjects) VALUES(?,?,?,?)', [c.id, c.name, c.teacher_id, c.subjects]);
        } else if (r.entity_type === 'student') {
          const st = p.student; if (!st) throw new Error('Invalid student backup.');
          if (!await one('SELECT 1 FROM classes WHERE id=?', [st.class_id])) throw new Error('Restore the original class first.');
          if (await one('SELECT 1 FROM students WHERE id=?', [st.id]) || (st.adm !== null && await one('SELECT 1 FROM students WHERE adm=?', [st.adm]))) throw new Error('That student or admission number already exists.');
          await q('INSERT INTO students(id,name,sex,adm,class_id) VALUES(?,?,?,?,?)', [st.id, st.name, st.sex, st.adm, st.class_id]);
          for (const x of p.scores ?? []) await q('INSERT INTO scores(year,term,student_id,subject,class_score,exam_score,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?)', [x.year, x.term, x.student_id, x.subject, x.class_score, x.exam_score, x.updated_by, x.updated_at]);
          for (const x of p.info ?? []) await q('INSERT INTO info(year,term,student_id,data) VALUES(?,?,?,?)', [x.year, x.term, x.student_id, x.data]);
        } else throw new Error('Unsupported recycle item.');
        await q('DELETE FROM recycle_bin WHERE id=?', [id]); await commit();
      } catch (e) { await rollback(); out({ error: e.message }, 422); }
      await audit(me.id, 'record_restored', r.entity_id, 'Restored ' + r.entity_type + ': ' + r.label); out({ ok: 1 });
    }
    if (a === 'recycle_purge' && adm) {
      const id = String(inp.id ?? '').trim(), r = await one('SELECT * FROM recycle_bin WHERE id=?', [id]);
      if (!r) out({ error: 'Recycle item not found.' }, 404);
      await q('DELETE FROM recycle_bin WHERE id=?', [id]); await audit(me.id, 'recycle_purged', r.entity_id, 'Permanently deleted ' + r.entity_type + ': ' + r.label); out({ ok: 1 });
    }

    if (a === 'sync') {
      const set = jparse(await col("SELECT v FROM settings WHERE k='main'"), {}) || {};
      const classMax = Number(set.classMax ?? 50), examMax = Number(set.examMax ?? 50);
      await begin();
      const cid = async sid => col('SELECT class_id FROM students WHERE id=?', [sid]);
      const exists = {}; const stExists = async sid => (exists[sid] ??= !!(await one('SELECT 1 FROM students WHERE id=?', [sid])));
      const mayScore = async k => {
        if (manager) return true;
        const [, , sid, sub] = k.split('|', 4).concat(['', '', '', '']).slice(0, 4);
        const c = await cid(sid); return assign.some(x => x.classId === c && x.subject === sub);
      };
      const mayInfo = async k => manager || !!(await one('SELECT 1 FROM classes c JOIN students s ON s.class_id=c.id WHERE s.id=? AND c.teacher_id=?', [k.split('|')[2] ?? '', me.id]));
      const parseKey = (k, n) => { const parts = k.split('|'); if (n === 4) return [parts[0] ?? '', parts[1] ?? '', parts[2] ?? '', parts.slice(3).join('|')]; return [parts[0] ?? '', parts[1] ?? '', parts[2] ?? '']; };
      const termOk = t => Number(t) >= 1 && Number(t) <= 3;

      if (adm) {
        if (inp.settings) {
          const ss = inp.settings;
          if (!/^\d{4}\/\d{4}$/.test(String(ss.year ?? '')) || !termOk(ss.term)) out({ error: 'Invalid academic session.' }, 422);
          await q("INSERT INTO settings(k,v) VALUES('main',?) ON CONFLICT(k) DO UPDATE SET v=EXCLUDED.v", [JSON.stringify(ss)]);
          await audit(me.id, 'settings_updated', 'main', 'School/system settings updated');
        }
        for (const id of inp.users?.del ?? []) {
          const u = await one("SELECT * FROM users WHERE id=? AND role IN ('teacher','headteacher')", [id]);
          if (u) { await recyclePut(me.id, 'user', u.id, u.name, { user: u }); await q('DELETE FROM users WHERE id=?', [id]); await audit(me.id, 'user_deleted', u.id, 'Moved to recycle bin: ' + u.name); }
        }
        for (const u of inp.users?.up ?? []) {
          if (!validText(u.name ?? '', 120)) out({ error: 'Invalid staff name.' }, 422);
          await q("UPDATE users SET name=?,assign=? WHERE id=? AND role IN ('teacher','headteacher')", [u.name, JSON.stringify(u.assign ?? []), u.id]);
        }
        for (const c of inp.classes?.up ?? []) {
          if (!validText(c.name ?? '', 60) || !/^[A-Za-z0-9 _()\/-]+$/u.test(c.name)) out({ error: 'Invalid class name.' }, 422);
          const subs = Array.isArray(c.subjects) ? c.subjects : [];
          for (const s of subs) if (!validText(s, 100)) out({ error: 'Invalid subject name.' }, 422);
          await q('INSERT INTO classes(id,name,teacher_id,subjects) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,teacher_id=EXCLUDED.teacher_id,subjects=EXCLUDED.subjects', [c.id, c.name, c.teacherId || null, JSON.stringify(subs)]);
        }
        for (const st of inp.students?.up ?? []) {
          if (!validText(st.name ?? '', 150)) out({ error: 'Invalid student name.' }, 422);
          const sex = String(st.sex ?? '').toUpperCase(); if (!['', 'M', 'F'].includes(sex)) out({ error: 'Invalid student gender.' }, 422);
          const ad = String(st.adm ?? '').trim(); if ([...ad].length > 40 || (ad !== '' && !/^[A-Za-z0-9._\/-]+$/.test(ad))) out({ error: 'Invalid admission number.' }, 422);
          if (!/^[A-Za-z0-9._:-]{1,24}$/.test(String(st.id ?? ''))) out({ error: 'Invalid student id.' }, 422);
          if (!await one('SELECT 1 FROM classes WHERE id=?', [st.classId])) out({ error: 'Student class does not exist.' }, 422);
          if (ad !== '' && await one('SELECT 1 FROM students WHERE adm=? AND id<>?', [ad, st.id])) out({ error: 'That admission number is already used by another student.' }, 422);
          await q('INSERT INTO students(id,name,sex,adm,class_id) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,sex=EXCLUDED.sex,adm=EXCLUDED.adm,class_id=EXCLUDED.class_id', [st.id, String(st.name).trim(), sex, ad || null, st.classId]);
          exists[st.id] = true;
        }
        for (const id of inp.students?.del ?? []) {
          const st = await one('SELECT * FROM students WHERE id=?', [id]);
          if (st) {
            const scores = await rows('SELECT * FROM scores WHERE student_id=?', [id]), infos = await rows('SELECT * FROM info WHERE student_id=?', [id]);
            await recyclePut(me.id, 'student', st.id, st.name, { student: st, scores, info: infos });
            await q('DELETE FROM students WHERE id=?', [id]); exists[id] = false; await audit(me.id, 'student_deleted', st.id, 'Moved to recycle bin: ' + st.name);
          }
        }
        for (const id of inp.classes?.del ?? []) {
          const c = await one('SELECT * FROM classes WHERE id=?', [id]);
          if (c) {
            if (await one('SELECT 1 FROM students WHERE class_id=? LIMIT 1', [id])) out({ error: 'Move the students out of this class before deleting it.' }, 422);
            await recyclePut(me.id, 'class', c.id, c.name, { class: c }); await q('DELETE FROM classes WHERE id=?', [id]); await audit(me.id, 'class_deleted', c.id, 'Moved to recycle bin: ' + c.name);
          }
        }
      }
      for (const [k, v] of Object.entries(inp.scores?.up ?? {})) {
        if (!await mayScore(k)) continue; const [y, t, sid, sub] = parseKey(k, 4);
        if (!/^\d{4}\/\d{4}$/.test(y) || !termOk(t) || !/^[A-Za-z0-9._:-]{1,24}$/.test(sid) || !validText(sub, 100) || !await stExists(sid)) continue;
        const f = (x, m) => (v && v[x] != null) ? Math.min(Math.max(Number(v[x]) || 0, 0), m) : null;
        await q('INSERT INTO scores(year,term,student_id,subject,class_score,exam_score,updated_by) VALUES(?,?,?,?,?,?,?) ON CONFLICT(year,term,student_id,subject) DO UPDATE SET class_score=EXCLUDED.class_score,exam_score=EXCLUDED.exam_score,updated_by=EXCLUDED.updated_by,updated_at=now()', [y, Number(t), sid, sub, f('c', classMax), f('e', examMax), me.id]);
      }
      for (const k of inp.scores?.del ?? []) {
        if (!await mayScore(k)) continue; const [y, t, sid, sub] = parseKey(k, 4);
        if (!/^\d{4}\/\d{4}$/.test(y) || !termOk(t) || !/^[A-Za-z0-9._:-]{1,24}$/.test(sid) || !validText(sub, 100)) continue;
        await q('DELETE FROM scores WHERE year=? AND term=? AND student_id=? AND subject=?', [y, Number(t), sid, sub]);
      }
      for (const [k, v0] of Object.entries(inp.info?.up ?? {})) {
        if (!await mayInfo(k)) continue; const [y, t, sid] = parseKey(k, 3);
        if (!/^\d{4}\/\d{4}$/.test(y) || !termOk(t) || !await stExists(sid)) continue;
        const v = (v0 && typeof v0 === 'object') ? { ...v0 } : {};
        if (!manager) { delete v.hm; const o = jparse(await col('SELECT data FROM info WHERE year=? AND term=? AND student_id=?', [y, Number(t), sid]) || '{}', {}); if (o.hm !== undefined) v.hm = o.hm; }
        await q('INSERT INTO info(year,term,student_id,data) VALUES(?,?,?,?) ON CONFLICT(year,term,student_id) DO UPDATE SET data=EXCLUDED.data', [y, Number(t), sid, JSON.stringify(v)]);
      }
      for (const k of inp.info?.del ?? []) {
        if (!await mayInfo(k)) continue; const [y, t, sid] = parseKey(k, 3);
        await q('DELETE FROM info WHERE year=? AND term=? AND student_id=?', [y, Number(t), sid]);
      }
      const sc = Object.keys(inp.scores?.up ?? {}).length + (inp.scores?.del ?? []).length, inf = Object.keys(inp.info?.up ?? {}).length + (inp.info?.del ?? []).length;
      if (sc) await audit(me.id, 'scores_changed', 'assessment', `${sc} score record change(s)`);
      if (inf) await audit(me.id, 'remarks_changed', 'student_records', `${inf} attendance/remark record change(s)`);
      await commit(); out({ ok: 1 });
    }
    out({ error: 'Unknown request' }, 404);
  } catch (e) {
    await rollback();
    if (e instanceof Out) return send(e.d, e.c);
    console.error(e);
    return send({ error: 'The server could not save. Try again.' }, 500);
  }
};
