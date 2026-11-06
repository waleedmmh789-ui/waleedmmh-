# waleedmmh
## تشغيل محلي
npm install && cp .env.example .env && npm start   (غيّر NODE_ENV إلى development محلياً)
## نشر عبر Cloudflare Tunnel
1. على أي سيرفر/جهاز عليه Docker: انسخ المشروع، ثم cp .env.example .env وعدّل القيم.
2. Cloudflare Zero Trust > Networks > Tunnels > Create tunnel (Cloudflared) وانسخ التوكن إلى TUNNEL_TOKEN.
3. أضف Public hostname: النطاق الخاص بك  ->  Service: HTTP  app:3000
4. docker compose up -d --build
