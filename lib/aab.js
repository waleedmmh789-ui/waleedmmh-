// قارئ بسيط لـ AndroidManifest.xml داخل ملفات AAB (صيغة protobuf الخاصة بـ aapt2) بدون Java
function pbFields(buf) {
  const out = []; let i = 0;
  const varint = () => { let r = 0, s = 0, b; do { b = buf[i++]; r += (b & 0x7f) * 2 ** s; s += 7; } while (b & 0x80 && i <= buf.length); return r; };
  while (i < buf.length) {
    const tag = varint(), f = Math.floor(tag / 8), w = tag & 7;
    if (w === 0) out.push({ f, w, v: varint() });
    else if (w === 2) { const n = varint(); out.push({ f, w, v: buf.subarray(i, i + n) }); i += n; }
    else if (w === 1) i += 8; else if (w === 5) i += 4; else throw new Error('protobuf غير صالح');
  }
  return out;
}
function primValue(item) { // قيمة رقمية/منطقية من compiled_item عند غياب النص الأصلي
  try {
    const prim = pbFields(item).find(x => x.f === 7 && x.w === 2); if (!prim) return '';
    const v = pbFields(prim.v).find(x => [6, 7, 8].includes(x.f) && x.w === 0);
    return v ? String(v.v) : '';
  } catch (_) { return ''; }
}
function elem(nodeBuf) {
  const n = pbFields(nodeBuf).find(x => x.f === 1 && x.w === 2); if (!n) return null;
  const e = { name: '', attrs: {}, children: [] };
  for (const x of pbFields(n.v)) {
    if (x.f === 3) e.name = x.v.toString();
    else if (x.f === 4) {
      let k = '', val = '', item = null;
      for (const a of pbFields(x.v)) { if (a.f === 2) k = a.v.toString(); else if (a.f === 3) val = a.v.toString(); else if (a.f === 6) item = a.v; }
      e.attrs[k] = val || (item ? primValue(item) : '');
    } else if (x.f === 5) { const c = elem(x.v); if (c) e.children.push(c); }
  }
  return e;
}
function manifestFromBuffer(buf) {
  const m = elem(buf);
  if (!m || m.name !== 'manifest') throw new Error('AndroidManifest غير صالح');
  const sdk = (m.children.find(c => c.name === 'uses-sdk') || { attrs: {} }).attrs;
  const appEl = m.children.find(c => c.name === 'application');
  let label = appEl && appEl.attrs.label;
  if (!label || label.startsWith('@')) label = m.attrs.package; // الاسم مرجع لمورد؛ يمكن تعديله من لوحة التحكم
  return {
    name: label, package: m.attrs.package, versionName: m.attrs.versionName || 'غير محدد', versionCode: m.attrs.versionCode || 'غير محدد',
    minSdk: sdk.minSdkVersion || 'غير محدد', targetSdk: sdk.targetSdkVersion || 'غير محدد',
    maxSdk: sdk.maxSdkVersion || 'غير محدد (وهذا هو المطلوب لجوجل بلاي)', icon: null
  };
}
function parseAab(file) {
  const AdmZip = require('adm-zip');
  const e = new AdmZip(file).getEntry('base/manifest/AndroidManifest.xml');
  if (!e) throw new Error('ملف AAB غير صالح (لا يوجد base/manifest/AndroidManifest.xml)');
  return manifestFromBuffer(e.getData());
}
module.exports = { parseAab, manifestFromBuffer };
