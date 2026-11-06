require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const sharp = require('sharp');
const AppInfoParser = require('app-info-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { parseAab } = require('./lib/aab');

const PORT = process.env.PORT || 3000;
const BASE = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const PROD = process.env.NODE_ENV === 'production';
const bad = v => !v || v.startsWith('غيّر');
if (PROD && (bad(process.env.ADMIN_PASS) || bad(process.env.SESSION_SECRET))) {
  console.error('عيّن ADMIN_PASS و SESSION_SECRET في .env قبل التشغيل في الإنتاج'); process.exit(1);
}
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_HASH = bcrypt.hashSync(process.env.ADMIN_PASS || 'admin123', 10);

for (const d of ['data', 'uploads/apks', 'uploads/icons', 'uploads/tmp']) fs.mkdirSync(path.join(__dirname, d), { recursive: true });
const db = new Database(path.join(__dirname, 'data/store.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS apps(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, package TEXT, version_name TEXT, version_code TEXT,
  min_sdk TEXT, target_sdk TEXT, max_sdk TEXT, description TEXT, icon TEXT, apk_file TEXT,
  downloads INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS links(
  id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE, url TEXT, clicks INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); next(); });
app.get('/healthz', (req, res) => res.send('ok'));
// حماية CSRF: رفض طلبات POST القادمة من موقع آخر
app.use((req, res, next) => {
  if (req.method === 'POST' && req.headers.origin && req.headers.origin !== new URL(BASE).origin) return res.status(403).send('Forbidden');
  next();
});
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'dev-secret', resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 1000 * 60 * 60 * 8 } }));
app.use('/icons', express.static(path.join(__dirname, 'uploads/icons')));

const upload = multer({ dest: path.join(__dirname, 'uploads/tmp'), limits: { fileSize: 500 * 1024 * 1024 } });
const rm = f => { try { f && fs.unlinkSync(f); } catch (_) {} };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const needAdmin = (req, res, next) => (req.session.admin ? next() : res.redirect('/admin/login'));
const isPkg = n => /\.(apk|aab)$/i.test(n || '');

function page(req, title, body) {
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} | waleedmmh</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;700&display=swap" rel="stylesheet">
<style>body{font-family:'Tajawal',sans-serif}</style></head>
<body class="bg-slate-50 text-slate-800">
<nav class="bg-slate-900 text-white"><div class="max-w-5xl mx-auto px-4 py-3 flex flex-wrap items-center gap-4 text-sm">
<a href="/" class="font-bold text-lg text-emerald-400">waleedmmh</a>
<a href="/tools/apk">محلل APK/AAB</a><a href="/tools/image">ضغط الصور</a>
<a href="/tools/shorten">تقصير الروابط</a><a href="/tools/privacy">سياسة الخصوصية</a>
<span class="flex-1"></span>
${req.session && req.session.admin ? '<a href="/admin">لوحة التحكم</a><a href="/admin/logout">خروج</a>' : '<a href="/admin/login">دخول الأدمن</a>'}
</div></nav>
<main class="max-w-5xl mx-auto px-4 py-6">${body}</main>
<footer class="text-center text-xs text-slate-400 py-6">© waleedmmh</footer></body></html>`;
}
const card = 'bg-white rounded-xl shadow p-5';
const inp = 'w-full border rounded-lg px-3 py-2 mb-3 bg-white';
const btn = 'bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg px-4 py-2';
const iconTag = (a, cls) => (a.icon ? `<img src="/icons/${esc(a.icon)}" class="${cls}" alt="">` : `<div class="${cls} bg-slate-200"></div>`);

// ---------- تحليل APK / AAB ----------
async function parseApk(file) {
  const r = await new AppInfoParser(file).parse();
  let label = r.application && r.application.label;
  if (Array.isArray(label)) label = label[0];
  if (!label || typeof label !== 'string') label = r.package;
  const sdk = r.usesSdk || {};
  return {
    name: label, package: r.package, versionName: r.versionName, versionCode: r.versionCode,
    minSdk: sdk.minSdkVersion || 'غير محدد', targetSdk: sdk.targetSdkVersion || 'غير محدد',
    maxSdk: sdk.maxSdkVersion || 'غير محدد (وهذا هو المطلوب لجوجل بلاي)', icon: r.icon || null
  };
}
const parsePackage = (file, origName) => (/\.aab$/i.test(origName) ? parseAab(file) : parseApk(file));
const saveIcon = b64 => {
  if (!b64) return null;
  const name = crypto.randomBytes(8).toString('hex') + '.png';
  fs.writeFileSync(path.join(__dirname, 'uploads/icons', name), Buffer.from(b64.replace(/^data:image\/\w+;base64,/, ''), 'base64'));
  return name;
};

// ---------- المتجر العام ----------
app.get('/', (req, res) => {
  const apps = db.prepare('SELECT * FROM apps ORDER BY id DESC').all();
  res.send(page(req, 'المتجر', `<h1 class="text-2xl font-bold mb-4">متجر التطبيقات والأدوات</h1>
<div class="grid sm:grid-cols-2 md:grid-cols-3 gap-4">${apps.map(a => `
<a href="/app/${a.id}" class="${card} flex gap-3 items-center hover:shadow-lg">${iconTag(a, 'w-14 h-14 rounded-xl')}
<div><div class="font-bold">${esc(a.name)}</div><div class="text-xs text-slate-500">v${esc(a.version_name)} · ${a.downloads} تحميل</div></div></a>`).join('') || '<p>لا توجد تطبيقات بعد.</p>'}</div>`));
});
app.get('/app/:id', (req, res) => {
  const a = db.prepare('SELECT * FROM apps WHERE id=?').get(req.params.id);
  if (!a) return res.status(404).send(page(req, '404', '<p>التطبيق غير موجود</p>'));
  const ext = path.extname(a.apk_file).slice(1).toUpperCase();
  res.send(page(req, a.name, `<div class="${card}"><div class="flex gap-4 items-center mb-4">${iconTag(a, 'w-20 h-20 rounded-2xl')}
<div><h1 class="text-xl font-bold">${esc(a.name)}</h1><div class="text-sm text-slate-500" dir="ltr">${esc(a.package)}</div></div></div>
<p class="mb-4 whitespace-pre-line">${esc(a.description)}</p>
<ul class="text-sm mb-4"><li>الإصدار: ${esc(a.version_name)} (${esc(a.version_code)})</li><li>الحد الأدنى لأندرويد (SDK): ${esc(a.min_sdk)}</li><li>التحميلات: ${a.downloads}</li></ul>
<a class="${btn} inline-block" href="/download/${a.id}">تحميل ${ext}</a></div>`));
});
app.get('/download/:id', (req, res) => {
  const a = db.prepare('SELECT * FROM apps WHERE id=?').get(req.params.id);
  if (!a) return res.sendStatus(404);
  db.prepare('UPDATE apps SET downloads=downloads+1 WHERE id=?').run(a.id);
  res.download(path.join(__dirname, 'uploads/apks', a.apk_file), `${a.package}-${a.version_name}${path.extname(a.apk_file)}`);
});

// ---------- الأدمن ----------
const fails = {};
const clientIp = req => req.headers['cf-connecting-ip'] || req.ip;
app.get('/admin/login', (req, res) => res.send(page(req, 'دخول', `<form method="post" class="${card} max-w-sm mx-auto">
<h1 class="font-bold text-lg mb-3">تسجيل دخول الأدمن</h1>${req.query.e ? '<p class="text-red-600 text-sm mb-2">بيانات خاطئة</p>' : ''}
<input name="u" class="${inp}" placeholder="اسم المستخدم" required><input name="p" type="password" class="${inp}" placeholder="كلمة المرور" required>
<button class="${btn} w-full">دخول</button></form>`)));
app.post('/admin/login', (req, res) => {
  const ip = clientIp(req);
  if (!fails[ip] || Date.now() - fails[ip].t > 15 * 60e3) fails[ip] = { n: 0, t: Date.now() };
  if (fails[ip].n >= 5) return res.status(429).send('محاولات كثيرة، حاول لاحقاً');
  const ok = req.body.u === ADMIN_USER && bcrypt.compareSync(req.body.p || '', ADMIN_HASH);
  if (!ok) { fails[ip].n++; return res.redirect('/admin/login?e=1'); }
  delete fails[ip];
  req.session.regenerate(() => { req.session.admin = true; res.redirect('/admin'); });
});
app.get('/admin/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.get('/admin', needAdmin, (req, res) => {
  const s = db.prepare('SELECT COUNT(*) c, COALESCE(SUM(downloads),0) d FROM apps').get();
  const l = db.prepare('SELECT COUNT(*) c, COALESCE(SUM(clicks),0) k FROM links').get();
  const apps = db.prepare('SELECT * FROM apps ORDER BY id DESC').all();
  const stat = (t, v) => `<div class="${card} text-center"><div class="text-3xl font-bold text-emerald-600">${v}</div><div class="text-sm">${t}</div></div>`;
  res.send(page(req, 'لوحة التحكم', `<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
${stat('التطبيقات', s.c)}${stat('التحميلات', s.d)}${stat('الروابط المختصرة', l.c)}${stat('نقرات الروابط', l.k)}</div>
<div class="flex justify-between mb-3"><h2 class="font-bold text-lg">التطبيقات</h2><a href="/admin/apps/new" class="${btn}">+ إضافة تطبيق</a></div>
<div class="${card} overflow-x-auto"><table class="w-full text-sm"><tr class="text-right border-b"><th>الاسم</th><th>الحزمة</th><th>الإصدار</th><th>التحميلات</th><th></th></tr>
${apps.map(a => `<tr class="border-b"><td class="py-2">${esc(a.name)}</td><td dir="ltr">${esc(a.package)}</td><td>${esc(a.version_name)}</td><td>${a.downloads}</td>
<td class="whitespace-nowrap"><a class="text-blue-600" href="/admin/apps/${a.id}/edit">تعديل</a>
<form method="post" action="/admin/apps/${a.id}/delete" class="inline" onsubmit="return confirm('حذف التطبيق؟')"><button class="text-red-600 mr-3">حذف</button></form></td></tr>`).join('')}</table></div>`));
});
const newForm = (req, err) => page(req, 'إضافة تطبيق', `
<form method="post" enctype="multipart/form-data" class="${card} max-w-xl"><h1 class="font-bold mb-3">إضافة تطبيق (يُستخرج الاسم والإصدار تلقائياً)</h1>
${err ? `<p class="text-red-600 text-sm mb-3">${esc(err)}</p>` : ''}
<label>ملف APK أو AAB</label><input type="file" name="apk" accept=".apk,.aab" class="${inp}" required>
<label>الأيقونة (اختياري لـ APK، وموصى بها لـ AAB)</label><input type="file" name="icon" accept="image/*" class="${inp}">
<label>الوصف</label><textarea name="description" rows="4" class="${inp}"></textarea><button class="${btn}">رفع وحفظ</button></form>`);
app.get('/admin/apps/new', needAdmin, (req, res) => res.send(newForm(req)));
app.post('/admin/apps/new', needAdmin, upload.fields([{ name: 'apk', maxCount: 1 }, { name: 'icon', maxCount: 1 }]), wrap(async (req, res) => {
  const pk = req.files.apk && req.files.apk[0], ic = req.files.icon && req.files.icon[0];
  try {
    if (!pk || !isPkg(pk.originalname)) return res.status(400).send(newForm(req, 'ارفع ملف APK أو AAB صالحاً'));
    let info;
    try { info = await parsePackage(pk.path, pk.originalname); } catch (e) { return res.status(422).send(newForm(req, 'تعذّر تحليل الملف: ' + e.message)); }
    let iconName = saveIcon(info.icon);
    if (ic) {
      try {
        const n = crypto.randomBytes(8).toString('hex') + '.png';
        await sharp(ic.path).resize(512, 512, { fit: 'cover' }).png({ compressionLevel: 9 }).toFile(path.join(__dirname, 'uploads/icons', n));
        iconName = n;
      } catch (_) { return res.status(422).send(newForm(req, 'ملف الأيقونة ليس صورة صالحة')); }
    }
    const stored = crypto.randomBytes(10).toString('hex') + path.extname(pk.originalname).toLowerCase();
    fs.renameSync(pk.path, path.join(__dirname, 'uploads/apks', stored));
    db.prepare(`INSERT INTO apps(name,package,version_name,version_code,min_sdk,target_sdk,max_sdk,description,icon,apk_file) VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .run(info.name, info.package, info.versionName, info.versionCode, info.minSdk, info.targetSdk, info.maxSdk, req.body.description || '', iconName, stored);
    res.redirect('/admin');
  } finally { rm(ic && ic.path); rm(pk && pk.path); }
}));
app.get('/admin/apps/:id/edit', needAdmin, (req, res) => {
  const a = db.prepare('SELECT * FROM apps WHERE id=?').get(req.params.id);
  if (!a) return res.sendStatus(404);
  res.send(page(req, 'تعديل', `<form method="post" class="${card} max-w-xl"><h1 class="font-bold mb-3">تعديل ${esc(a.name)}</h1>
<label>الاسم</label><input name="name" class="${inp}" value="${esc(a.name)}" required>
<label>الوصف</label><textarea name="description" rows="5" class="${inp}">${esc(a.description)}</textarea><button class="${btn}">حفظ</button></form>`));
});
app.post('/admin/apps/:id/edit', needAdmin, (req, res) => {
  db.prepare('UPDATE apps SET name=?, description=? WHERE id=?').run(req.body.name, req.body.description, req.params.id); res.redirect('/admin');
});
app.post('/admin/apps/:id/delete', needAdmin, (req, res) => {
  const a = db.prepare('SELECT * FROM apps WHERE id=?').get(req.params.id);
  if (a) { rm(path.join(__dirname, 'uploads/apks', a.apk_file)); if (a.icon) rm(path.join(__dirname, 'uploads/icons', a.icon)); db.prepare('DELETE FROM apps WHERE id=?').run(a.id); }
  res.redirect('/admin');
});

// ---------- أداة تحليل APK/AAB ----------
const apkForm = r => `<form method="post" enctype="multipart/form-data" class="${card} max-w-xl"><h1 class="font-bold mb-3">محلل ملفات APK / AAB</h1>
<input type="file" name="apk" accept=".apk,.aab" class="${inp}" required><button class="${btn}">تحليل</button></form>${r || ''}`;
app.get('/tools/apk', (req, res) => res.send(page(req, 'محلل APK', apkForm())));
app.post('/tools/apk', upload.single('apk'), wrap(async (req, res) => {
  if (!req.file || !isPkg(req.file.originalname)) { rm(req.file && req.file.path); return res.status(400).send(page(req, 'خطأ', apkForm('<p class="text-red-600 mt-3">ارفع ملف APK أو AAB</p>'))); }
  try {
    const i = await parsePackage(req.file.path, req.file.originalname);
    const row = (k, v) => `<tr class="border-b"><td class="py-2 font-bold">${k}</td><td dir="ltr" class="text-left">${esc(v)}</td></tr>`;
    res.send(page(req, 'نتيجة التحليل', apkForm(`<div class="${card} max-w-xl mt-4">${i.icon ? `<img src="${esc(i.icon)}" class="w-16 h-16 rounded-xl mb-3" alt="">` : ''}
<table class="w-full text-sm">${row('اسم التطبيق', i.name)}${row('اسم الحزمة', i.package)}${row('Version Name', i.versionName)}${row('Version Code', i.versionCode)}
${row('minSdkVersion', i.minSdk)}${row('targetSdkVersion', i.targetSdk)}${row('maxSdkVersion', i.maxSdk)}</table></div>`)));
  } catch (e) { res.status(422).send(page(req, 'خطأ', apkForm(`<p class="text-red-600 mt-3">تعذّر تحليل الملف: ${esc(e.message)}</p>`))); }
  finally { rm(req.file.path); }
}));

// ---------- أداة الصور ----------
const PRESETS = {
  icon: { w: 512, h: 512, fit: 'cover', label: 'أيقونة Google Play (512×512 PNG)' },
  feature: { w: 1024, h: 500, fit: 'cover', label: 'Feature Graphic (1024×500 JPG)' },
  screenshot: { w: 1080, h: 1920, fit: 'inside', label: 'لقطة شاشة (حتى 1080×1920 JPG)' }
};
app.get('/tools/image', (req, res) => res.send(page(req, 'ضغط الصور', `<form method="post" enctype="multipart/form-data" class="${card} max-w-xl">
<h1 class="font-bold mb-3">ضغط وتصغير الصور</h1><input type="file" name="img" accept="image/*" class="${inp}" required>
<select name="preset" class="${inp}">${Object.entries(PRESETS).map(([k, v]) => `<option value="${k}">${v.label}</option>`).join('')}</select>
<button class="${btn}">معالجة وتحميل</button></form>`)));
app.post('/tools/image', upload.single('img'), wrap(async (req, res) => {
  if (!req.file) return res.status(400).send('ارفع صورة');
  const key = PRESETS[req.body.preset] ? req.body.preset : 'screenshot', p = PRESETS[key], isIcon = key === 'icon';
  try {
    let img = sharp(req.file.path).rotate().resize(p.w, p.h, { fit: p.fit, withoutEnlargement: p.fit === 'inside' });
    // أيقونة جوجل بلاي: PNG بـ 32 بت (مع ألفا) وليس palette؛ الباقي JPG بلا شفافية
    const out = isIcon ? await img.ensureAlpha().png({ compressionLevel: 9 }).toBuffer()
                       : await img.flatten({ background: '#ffffff' }).jpeg({ quality: 82, mozjpeg: true }).toBuffer();
    res.set({ 'Content-Type': isIcon ? 'image/png' : 'image/jpeg', 'Content-Disposition': `attachment; filename="${key}-optimized.${isIcon ? 'png' : 'jpg'}"` }).send(out);
  } catch (e) { res.status(422).send('ملف صورة غير صالح'); } finally { rm(req.file.path); }
}));

// ---------- تقصير الروابط ----------
app.get('/tools/shorten', (req, res) => {
  const mine = db.prepare('SELECT * FROM links ORDER BY id DESC LIMIT 10').all();
  const c = req.query.c && /^[\w-]{1,12}$/.test(req.query.c) ? req.query.c : '';
  res.send(page(req, 'تقصير الروابط', `<form method="post" class="${card} max-w-xl mb-4"><h1 class="font-bold mb-3">تقصير الروابط</h1>
${c ? `<p class="mb-3 p-2 bg-emerald-50 rounded text-sm" dir="ltr">${esc(BASE)}/s/${esc(c)}</p>` : ''}
<input name="url" type="url" class="${inp}" placeholder="https://..." required><button class="${btn}">تقصير</button></form>
<div class="${card} max-w-xl text-sm" dir="ltr">${mine.map(l => `<div class="border-b py-1">/s/${esc(l.code)} → ${esc(l.url.slice(0, 50))} (${l.clicks})</div>`).join('') || 'No links'}</div>`));
});
app.post('/tools/shorten', (req, res) => {
  let u; try { u = new URL(req.body.url); } catch (_) { return res.status(400).send('رابط غير صالح'); }
  if (!['http:', 'https:'].includes(u.protocol)) return res.status(400).send('بروتوكول غير مسموح');
  let code, tries = 0;
  do { code = crypto.randomBytes(5).toString('base64url').slice(0, 6); } while (db.prepare('SELECT 1 FROM links WHERE code=?').get(code) && ++tries < 10);
  db.prepare('INSERT INTO links(code,url) VALUES(?,?)').run(code, u.href);
  res.redirect('/tools/shorten?c=' + code);
});
app.get('/s/:code', (req, res) => {
  const l = db.prepare('SELECT * FROM links WHERE code=?').get(req.params.code);
  if (!l) return res.status(404).send('الرابط غير موجود');
  db.prepare('UPDATE links SET clicks=clicks+1 WHERE id=?').run(l.id); res.redirect(l.url);
});

// ---------- مولد سياسة الخصوصية (عربي / English) ----------
const PP = {
  ar: { lang: 'ar', dir: 'rtl', title: 'سياسة الخصوصية لتطبيق', upd: 'آخر تحديث',
    intro: (a, v) => `تطبيق «${a}» ("التطبيق") من تطوير ${v}. توضح هذه الصفحة كيف نتعامل مع معلوماتك.`,
    h: ['المعلومات التي نجمعها', 'كيف نستخدم المعلومات', 'مشاركة البيانات', 'حماية البيانات وحذفها', 'خصوصية الأطفال', 'التواصل'],
    items: { ads: 'خدمات الإعلانات (مثل Google AdMob) التي قد تجمع معرّف الإعلان وبيانات الاستخدام.', analytics: 'خدمات التحليلات (مثل Firebase Analytics) لفهم كيفية استخدام التطبيق.',
      location: 'بيانات الموقع الجغرافي لتقديم الميزات المعتمدة على الموقع.', camera: 'الكاميرا/الصور/الملفات عند منح الإذن لوظائف التطبيق.', account: 'معلومات الحساب مثل الاسم والبريد الإلكتروني عند التسجيل.' },
    none: 'لا يجمع التطبيق أي بيانات شخصية.', use: 'نستخدم المعلومات لتشغيل التطبيق وتحسينه وتقديم الدعم الفني.',
    share: 'لا نبيع بياناتك. قد تُشارك مع مزودي الخدمات المذكورين أعلاه وفق سياساتهم.', sec: 'نتخذ إجراءات معقولة لحماية بياناتك. يمكنك طلب حذفها بمراسلتنا.',
    kidsY: 'التطبيق موجّه للأطفال ونلتزم بالقوانين ذات الصلة (مثل COPPA).', kidsN: 'التطبيق غير موجّه للأطفال دون 13 عاماً ولا نجمع بياناتهم عن علم.', contact: 'للاستفسار:' },
  en: { lang: 'en', dir: 'ltr', title: 'Privacy Policy for', upd: 'Last updated',
    intro: (a, v) => `The app "${a}" (the "App") is developed by ${v}. This page explains how we handle your information.`,
    h: ['Information We Collect', 'How We Use Information', 'Data Sharing', 'Data Security and Deletion', "Children's Privacy", 'Contact Us'],
    items: { ads: 'Advertising services (such as Google AdMob), which may collect advertising IDs and usage data.', analytics: 'Analytics services (such as Firebase Analytics) to understand how the App is used.',
      location: 'Location data to provide location-based features.', camera: 'Camera, photos, or files when you grant permission, for App functionality.', account: 'Account information such as name and email address when you register.' },
    none: 'The App does not collect any personal data.', use: 'We use information to operate and improve the App and to provide support.',
    share: 'We do not sell your data. It may be shared with the service providers listed above, subject to their own policies.', sec: 'We take reasonable measures to protect your data. You may request deletion of your data by contacting us.',
    kidsY: 'The App is directed to children and we comply with applicable laws (such as COPPA).', kidsN: 'The App is not directed to children under 13 and we do not knowingly collect their data.', contact: 'For questions, contact:' }
};
function policy(d) {
  const t = PP[d.lang === 'en' ? 'en' : 'ar'], on = k => d[k] === 'on';
  const items = Object.keys(t.items).filter(on).map(k => t.items[k]);
  const secs = [items.length ? '<ul>' + items.map(i => `<li>${i}</li>`).join('') + '</ul>' : `<p>${t.none}</p>`, `<p>${t.use}</p>`, `<p>${t.share}</p>`, `<p>${t.sec}</p>`,
    `<p>${on('kids') ? t.kidsY : t.kidsN}</p>`, `<p>${t.contact} <a href="mailto:${esc(d.email)}">${esc(d.email)}</a></p>`];
  return `<!DOCTYPE html><html lang="${t.lang}" dir="${t.dir}"><head><meta charset="utf-8"><title>${t.title} ${esc(d.app)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:Tahoma,Arial,sans-serif;max-width:760px;margin:auto;padding:20px;line-height:1.9}</style></head><body>
<h1>${t.title} ${esc(d.app)}</h1><p>${t.upd}: ${new Date().toISOString().slice(0, 10)}</p><p>${t.intro(esc(d.app), esc(d.dev))}</p>
${secs.map((s, i) => `<h2>${t.h[i]}</h2>${s}`).join('\n')}</body></html>`;
}
app.get('/tools/privacy', (req, res) => {
  const chk = (n, t) => `<label class="block mb-1"><input type="checkbox" name="${n}"> ${t}</label>`;
  res.send(page(req, 'مولد سياسة الخصوصية', `<form method="post" class="${card} max-w-xl"><h1 class="font-bold mb-3">مولد سياسة الخصوصية</h1>
<select name="lang" class="${inp}"><option value="ar">العربية</option><option value="en">English</option></select>
<input name="app" class="${inp}" placeholder="اسم التطبيق / App name" required><input name="dev" class="${inp}" placeholder="اسم المطور / Developer" required>
<input name="email" type="email" class="${inp}" placeholder="البريد / Contact email" required>
${chk('ads', 'يعرض إعلانات')}${chk('analytics', 'يستخدم التحليلات')}${chk('location', 'يستخدم الموقع')}${chk('camera', 'يستخدم الكاميرا/الملفات')}${chk('account', 'يتطلب حساب مستخدم')}${chk('kids', 'موجّه للأطفال')}
<button class="${btn} mt-3">توليد</button></form>`));
});
app.post('/tools/privacy', (req, res) => {
  const html = policy(req.body);
  res.send(page(req, 'السياسة الجاهزة', `<div class="${card}"><p class="mb-2 text-sm">انسخ الكود وارفعه كصفحة HTML على موقعك، ثم ضع رابطها في Google Play Console.</p>
<textarea id="t" dir="ltr" rows="14" class="${inp} font-mono text-xs">${esc(html)}</textarea>
<button class="${btn}" onclick="navigator.clipboard.writeText(document.getElementById('t').value)">نسخ</button>
<a class="${btn} inline-block mr-2" download="privacy-policy.html" href="data:text/html;charset=utf-8,${encodeURIComponent(html)}">تحميل HTML</a></div>`));
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).send(page(req, 'خطأ', '<p>حجم الملف كبير جداً (الحد 500MB)</p>'));
  res.status(500).send(page(req, 'خطأ', '<p>حدث خطأ غير متوقع.</p>'));
});
app.listen(PORT, () => console.log(`waleedmmh running on ${BASE}`));
