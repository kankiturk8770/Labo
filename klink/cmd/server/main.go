package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"klink/internal/obfuscation"
	"klink/internal/session"
	"klink/internal/transport"
)

func main() {
	// Never fall back to a hardcoded key: if KLINK_SECRET is unset, generate and
	// persist a random one so the master key is not world-known.
	secretPhrase := resolveServerSecret()
	masterKey := sha256.Sum256([]byte(secretPhrase))

	defaultDomain := os.Getenv("KLINK_MIMIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "www.aparat.com"
	}

	dbPath := os.Getenv("KLINK_DB_PATH")
	if dbPath == "" {
		dbPath = "/opt/klink/klink.db"
	}

	sm, err := session.NewSessionManager(dbPath, masterKey)
	if err != nil {
		log.Fatalf("Failed to init DB: %v", err)
	}

	// بارگذاری تنظیمات پویا از دیتابیس (قابلیت تغییر کامل از پنل)
	dynCfg := sm.LoadDynamicConfig(defaultDomain)
	obf := obfuscation.NewObfuscator(dynCfg)

	go func() {
		for {
			time.Sleep(25 * time.Second)
			sm.SyncToDB()
		}
	}()

	tcpPort := os.Getenv("KLINK_TCP_PORT")
	if tcpPort == "" {
		tcpPort = "443"
	}
	udpPort := os.Getenv("KLINK_UDP_PORT")
	if udpPort == "" {
		udpPort = "50000"
	}
	panelPort := os.Getenv("KLINK_PANEL_PORT")
	if panelPort == "" {
		panelPort = "8443"
	}

	engine := transport.NewEngine(sm, obf, "0.0.0.0:"+tcpPort, "0.0.0.0:"+udpPort)

	// Back the genuine TLS handshake gate: the shared master key authenticates
	// ClientHellos, and a self-signed certificate terminates TLS 1.3 for valid
	// clients (the cert is encrypted under TLS 1.3, so it is not observable).
	engine.MasterKey = masterKey
	dataCertFile, dataKeyFile, certErr := ensurePanelCert(panelCertDir())
	if certErr == nil {
		var cert tls.Certificate
		cert, certErr = tls.LoadX509KeyPair(dataCertFile, dataKeyFile)
		if certErr == nil {
			engine.TLSCert = cert
		}
	}
	if certErr != nil {
		log.Fatalf("data-plane TLS certificate error: %v", certErr)
	}

	go startAdminPanel(sm, obf, masterKey, ":"+panelPort, tcpPort)

	if err := engine.Start(); err != nil {
		log.Fatalf("Engine error: %v", err)
	}
}

func startAdminPanel(sm *session.SessionManager, obf *obfuscation.Obfuscator, masterKey [32]byte, listenAddr, tcpPortStr string) {
	mux := http.NewServeMux()
	tcpPort, _ := strconv.Atoi(tcpPortStr)
	if tcpPort == 0 {
		tcpPort = 443
	}

	// ۱. API دریافت و تغییر زنده تنظیمات هسته، سایت نقاب، گواهی TLS و سرور Upstream
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var req obfuscation.DynamicConfig
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if req.Profile == "" {
				req.Profile = obfuscation.ProfileTLSMimic
			}
			meta := obf.UpdateConfig(req)
			updated := obf.GetConfig()
			_ = sm.SaveDynamicConfig(updated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":    "ok",
				"config":    updated,
				"cert_info": meta,
			})
			return
		}

		cfg := obf.GetConfig()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"config":          cfg,
			"diverted_probes": obf.GetDivertedCount(),
		})
	})

	// ۲. API تست زنده گواهی TLS سایت داخلی و سلامت لوله مخفی
	mux.HandleFunc("/api/selftest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		res := obf.RunSelfTest()
		// ذخیره آخرین وضعیت گواهی در کانفیگ
		cfg := obf.GetConfig()
		cfg.CertInfo = obfuscation.ProbeTargetTLS(cfg.MimicDomain, cfg.FallbackAddr)
		obf.UpdateConfig(cfg)
		_ = sm.SaveDynamicConfig(obf.GetConfig())
		_ = json.NewEncoder(w).Encode(res)
	})

	// ۳. API مدیریت کامل کاربران (ایجاد، لیست، حذف، ریست حجم، خاموش/روشن)
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			switch action {
			case "delete":
				_ = sm.DeleteUser(r.FormValue("session_id"))
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted"})
				return
			case "toggle":
				_ = sm.ToggleUser(r.FormValue("session_id"))
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "toggled"})
				return
			case "reset_traffic":
				_ = sm.ResetTraffic(r.FormValue("session_id"))
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "reset"})
				return
			default:
				username := r.FormValue("username")
				limitGB, _ := strconv.ParseInt(r.FormValue("limit_gb"), 10, 64)
				days, _ := strconv.Atoi(r.FormValue("days"))
				u, err := sm.CreateUser(username, limitGB, days, 2)
				if err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "token": u.SubToken})
				return
			}
		}

		users := sm.GetAllUsers()
		type userDTO struct {
			Username    string `json:"username"`
			SessionID   string `json:"session_id"`
			SubToken    string `json:"sub_token"`
			UsedMB      int64  `json:"used_mb"`
			LimitGB     int64  `json:"limit_gb"`
			ExpireDate  string `json:"expire_date"`
			Enabled     bool   `json:"enabled"`
			IsConnected bool   `json:"is_connected"`
			ActiveIP    string `json:"active_ip"`
		}
		var out []userDTO
		for _, u := range users {
			ipStr := "-"
			if u.ActiveIP != nil {
				ipStr = u.ActiveIP.String()
			}
			out = append(out, userDTO{
				Username:    u.Username,
				SessionID:   hex.EncodeToString(u.SessionID[:]),
				SubToken:    u.SubToken,
				UsedMB:      u.TrafficUsed / (1024 * 1024),
				LimitGB:     u.TrafficLimit / (1024 * 1024 * 1024),
				ExpireDate:  u.ExpireTime.Format("2006-01-02"),
				Enabled:     u.Enabled,
				IsConnected: u.IsConnected,
				ActiveIP:    ipStr,
			})
		}
		_ = json.NewEncoder(w).Encode(out)
	})

	// ۴. لینک سابسکریپشن پویا (هر تغییری در پنل روی سایت نقاب بدهید، کلاینت‌ها خودکار همان را می‌گیرند)
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Path[len("/sub/"):]
		u, ok := sm.GetByToken(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		cfg := obf.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		subConfig := map[string]any{
			"protocol":         "klink-v2",
			"username":         u.Username,
			"enabled":          u.Enabled,
			"session_id":       hex.EncodeToString(u.SessionID[:]),
			"master_key":       hex.EncodeToString(userKeySlice(session.DeriveUserKey(masterKey, u.SessionID))),
			"sni_masquerade":   cfg.MimicDomain,
			"fallback_target":  cfg.FallbackAddr,
			"cert_fingerprint": cfg.CertInfo.Fingerprint,
			"tcp_port":         tcpPort,
			"udp_port_range":   "50000-60000",
			"profile":          cfg.Profile,
			"padding_max":      cfg.PaddingMax,
		}
		_ = json.NewEncoder(w).Encode(subConfig)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, panelHTML)
	})

	// Require admin authentication on everything except public /sub/ links.
	handler := requirePanelAuth(mux, resolvePanelPassword(panelCertDir()))

	// Serve the panel over HTTPS using a persisted self-signed certificate
	// (auto-generated on first run). Set KLINK_PANEL_INSECURE=true to force
	// plain HTTP instead. If the certificate cannot be prepared, fall back to
	// HTTP rather than leaving the panel unreachable.
	if os.Getenv("KLINK_PANEL_INSECURE") == "true" {
		log.Printf("[KLINK-PANEL] Full Control Web UI running on http://0.0.0.0%s (insecure mode)", listenAddr)
		_ = http.ListenAndServe(listenAddr, handler)
		return
	}

	certFile, keyFile, err := ensurePanelCert(panelCertDir())
	if err != nil {
		log.Printf("[KLINK-PANEL] TLS setup failed (%v); falling back to HTTP", err)
		log.Printf("[KLINK-PANEL] Full Control Web UI running on http://0.0.0.0%s", listenAddr)
		_ = http.ListenAndServe(listenAddr, handler)
		return
	}

	srv := &http.Server{
		Addr:      listenAddr,
		Handler:   handler,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	log.Printf("[KLINK-PANEL] Full Control Web UI running on https://0.0.0.0%s (self-signed TLS)", listenAddr)
	_ = srv.ListenAndServeTLS(certFile, keyFile)
}

const panelHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>پنل کنترل کامل KLINK v2</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 md:p-6 font-sans">
  <div class="max-w-7xl mx-auto space-y-6">

    <!-- هدر وضعیت هسته -->
    <div class="flex flex-col md:flex-row justify-between items-start md:items-center bg-slate-900 p-5 rounded-2xl border border-slate-800 gap-4">
      <div>
        <h1 class="text-2xl font-bold text-emerald-400">مرکز فرماندهی و کنترل کامل KLINK v2</h1>
        <p class="text-sm text-slate-400 mt-1">
          سایت نقاب فعال: <span id="hdrDomain" class="text-amber-300 font-mono font-bold">...</span> |
          پروب‌های فریب‌خورده (هدایت‌شده به سایت داخلی): <span id="hdrProbes" class="text-rose-400 font-bold">0</span>
        </p>
      </div>
      <div class="flex items-center gap-3">
        <button onclick="runSelfTest()" class="bg-sky-600 hover:bg-sky-500 text-white text-sm font-bold px-4 py-2 rounded-xl transition">
          🔍 تست زنده گواهی و لوله مخفی
        </button>
        <span class="bg-emerald-500/20 text-emerald-300 px-4 py-2 rounded-xl text-xs border border-emerald-500/40 font-mono">
          ONLINE (TCP/UDP)
        </span>
      </div>
    </div>

    <!-- بخش ۱: کنترل کامل دامنه نقاب، گواهی TLS آپارات/آنتن و لوله‌کشی سرور آلمان -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      
      <!-- فرم تنظیمات زنده هسته -->
      <div class="bg-slate-900 p-5 rounded-2xl border border-slate-800">
        <h2 class="text-lg font-bold text-amber-400 mb-4">⚙️ تنظیمات زنده نقاب داخلی و لوله نامرئی (بدون نیاز به ریستارت)</h2>
        <form id="cfgForm" class="space-y-4 text-sm">
          <div>
            <label class="block text-slate-300 mb-1">انتخاب سریع سایت داخلی (یا تایپ دستی در کادر زیر):</label>
            <div class="flex flex-wrap gap-2 mb-2">
              <button type="button" onclick="setPreset('www.aparat.com')" class="bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded-lg border border-slate-700 text-xs">آپارات (aparat.com)</button>
              <button type="button" onclick="setPreset('www.anten.ir')" class="bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded-lg border border-slate-700 text-xs">آنتن (anten.ir)</button>
              <button type="button" onclick="setPreset('www.telewebion.com')" class="bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded-lg border border-slate-700 text-xs">تلوبیون (telewebion.com)</button>
              <button type="button" onclick="setPreset('www.filimo.com')" class="bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded-lg border border-slate-700 text-xs">فیلیمو (filimo.com)</button>
            </div>
            <input id="mimic_domain" required placeholder="مثلاً www.aparat.com" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 font-mono text-amber-300">
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label class="block text-slate-300 mb-1">آدرس Fallback واقعی (مقصد فیلترچی):</label>
              <input id="fallback_addr" required placeholder="www.aparat.com:443" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 font-mono">
            </div>
            <div>
              <label class="block text-slate-300 mb-1">حداکثر پدینگ تصادفی (بایت):</label>
              <input id="padding_max" type="number" min="16" max="250" value="64" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 font-mono">
            </div>
          </div>

          <div>
            <label class="block text-slate-300 mb-1">آدرس سرور مقصد پنهان (Upstream Tunnel - مثلاً آی‌پی:پورت آلمان):</label>
            <input id="upstream_tunnel" placeholder="خالی = همین سرور مستقیم | یا مثلاً 185.x.x.x:443 برای لوله‌کشی" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 font-mono text-sky-300">
            <p class="text-xs text-slate-400 mt-1">اگر این سرور داخل ایران است و می‌خواهید به آلمان لوله شود، آدرس سرور آلمان را اینجا بنویسید تا آلمان ۱۰۰٪ نامرئی بماند.</p>
          </div>

          <button class="w-full bg-emerald-600 hover:bg-emerald-500 font-bold rounded-xl py-2.5 transition">
            💾 ذخیره آنی و دریافت گواهی TLS جدید از سایت داخلی
          </button>
        </form>
      </div>

      <!-- کارت وضعیت گواهی TLS و بازرسی امنیتی -->
      <div class="bg-slate-900 p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
        <div>
          <h2 class="text-lg font-bold text-sky-400 mb-4">🛡️ وضعیت گواهی TLS و تطابق دوطرفه (Certificate Mirror)</h2>
          <div id="certBox" class="space-y-2.5 text-sm bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono">
            <div>وضعیت گواهی سایت داخلی: <span id="c_status" class="font-bold">در حال بررسی...</span></div>
            <div>دامنه گواهی (Subject): <span id="c_subject" class="text-emerald-300">-</span></div>
            <div>صادرکننده (Issuer): <span id="c_issuer" class="text-slate-300">-</span></div>
            <div>آی‌پی واقعی سایت داخلی: <span id="c_ip" class="text-amber-300">-</span></div>
            <div>نسخه TLS و سایفر: <span id="c_tls" class="text-sky-300">-</span></div>
            <div>فینگرپینت SHA256 گواهی: <span id="c_fp" class="text-xs text-purple-300 break-all">-</span></div>
            <div>اعتبار گواهی: <span id="c_exp" class="text-slate-400">-</span></div>
          </div>
        </div>
        <div id="selfTestBanner" class="mt-4 hidden p-3 rounded-xl bg-slate-800 border border-slate-700 text-xs text-slate-200"></div>
      </div>

    </div>

    <!-- بخش ۲: ساخت کاربر جدید -->
    <div class="bg-slate-900 p-5 rounded-2xl border border-slate-800">
      <h2 class="text-lg font-semibold mb-4 text-emerald-400">➕ ساخت کاربر و تونل اختصاصی جدید</h2>
      <form id="addForm" class="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
        <input name="username" placeholder="نام کاربری (مثلاً ali)" required class="bg-slate-950 border border-slate-700 rounded-xl px-3 py-2.5">
        <input name="limit_gb" type="number" placeholder="حجم مجاز (گیگابایت)" required class="bg-slate-950 border border-slate-700 rounded-xl px-3 py-2.5">
        <input name="days" type="number" placeholder="مدت اعتبار (روز)" required class="bg-slate-950 border border-slate-700 rounded-xl px-3 py-2.5">
        <button class="bg-emerald-600 hover:bg-emerald-500 font-bold rounded-xl px-4 py-2.5 transition">ایجاد کاربر جدید</button>
      </form>
    </div>

    <!-- بخش ۳: لیست کاربران و کنترل کامل نشست‌ها -->
    <div class="bg-slate-900 p-5 rounded-2xl border border-slate-800 overflow-x-auto">
      <h2 class="text-lg font-semibold mb-4">👥 مدیریت کاربران، نشست‌های زنده و لینک‌های سابسکریپشن هوشمند</h2>
      <table class="w-full text-right text-sm">
        <thead class="text-slate-400 border-b border-slate-800">
          <tr>
            <th class="pb-3">کاربر</th>
            <th class="pb-3">وضعیت اکانت</th>
            <th class="pb-3">اتصال زنده</th>
            <th class="pb-3">آخرین IP کاربر</th>
            <th class="pb-3">مصرف شده</th>
            <th class="pb-3">انقضا</th>
            <th class="pb-3">لینک سابسکریپشن (کلاینت)</th>
            <th class="pb-3">عملیات مدیریت</th>
          </tr>
        </thead>
        <tbody id="userRows" class="divide-y divide-slate-800/70"></tbody>
      </table>
    </div>

  </div>

  <script>
    function setPreset(domain) {
      document.getElementById('mimic_domain').value = domain;
      document.getElementById('fallback_addr').value = domain + ':443';
    }

    async function loadConfig() {
      const res = await fetch('/api/config');
      const data = await res.json();
      const cfg = data.config || {};
      const cert = cfg.cert_info || {};

      document.getElementById('hdrDomain').innerText = cfg.mimic_domain || '-';
      document.getElementById('hdrProbes').innerText = data.diverted_probes || 0;

      document.getElementById('mimic_domain').value = cfg.mimic_domain || '';
      document.getElementById('fallback_addr').value = cfg.fallback_addr || '';
      document.getElementById('padding_max').value = cfg.padding_max || 64;
      document.getElementById('upstream_tunnel').value = cfg.upstream_tunnel || '';

      renderCert(cert);
    }

    function renderCert(cert) {
      document.getElementById('c_status').innerHTML = cert.status_healthy
        ? '<span class="text-emerald-400">✔ متصل و تایید شده (گواهی واقعی دریافت شد)</span>'
        : '<span class="text-rose-400">✖ عدم دسترسی به دامنه</span>';
      document.getElementById('c_subject').innerText = cert.subject || '-';
      document.getElementById('c_issuer').innerText = cert.issuer || '-';
      document.getElementById('c_ip').innerText = cert.remote_real_ip || '-';
      document.getElementById('c_tls').innerText = (cert.tls_version || '-') + ' / ' + (cert.cipher_suite || '-');
      document.getElementById('c_fp').innerText = cert.fingerprint || '-';
      document.getElementById('c_exp').innerText = (cert.not_before || '') + ' تا ' + (cert.not_after || '');
    }

    document.getElementById('cfgForm').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        profile: 'tls-mimic',
        mimic_domain: document.getElementById('mimic_domain').value.trim(),
        fallback_addr: document.getElementById('fallback_addr').value.trim(),
        padding_max: parseInt(document.getElementById('padding_max').value || '64', 10),
        upstream_tunnel: document.getElementById('upstream_tunnel').value.trim()
      };
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const out = await res.json();
      if (out.cert_info) renderCert(out.cert_info);
      loadConfig();
      alert('تنظیمات هسته و سایت نقاب به صورت زنده اعمال شد!');
    };

    async function runSelfTest() {
      const banner = document.getElementById('selfTestBanner');
      banner.classList.remove('hidden');
      banner.innerText = 'در حال تست اتصال به سایت داخلی و بررسی گواهی SSL...';
      const res = await fetch('/api/selftest');
      const d = await res.json();
      banner.innerHTML = '<b>نتیجه تست زنده:</b> گواهی دامنه <code>' + d.mimic_domain + '</code>: ' +
        (d.tls_cert_verified ? '✅ سالم (IP: ' + d.remote_real_ip + ')' : '❌ خطا') +
        (d.upstream_configured ? ' | تانل آلمان: ' + (d.upstream_reachable ? '✅ متصل (' + d.upstream_latency + ')' : '❌ قطع') : ' | حالت: سرور مستقیم');
      loadConfig();
    }

    async function userAction(action, sid) {
      const fd = new FormData();
      fd.append('action', action);
      fd.append('session_id', sid);
      await fetch('/api/users', { method: 'POST', body: fd });
      loadUsers();
    }

    async function loadUsers() {
      const res = await fetch('/api/users');
      const users = await res.json() || [];
      const tbody = document.getElementById('userRows');
      tbody.innerHTML = users.map(u => ` + "`" + `
        <tr class="hover:bg-slate-800/40">
          <td class="py-3 font-bold">${u.username}</td>
          <td class="py-3">${u.enabled ? '<span class="text-emerald-400 text-xs">فعال</span>' : '<span class="text-rose-400 text-xs">مسدود</span>'}</td>
          <td class="py-3">${u.is_connected ? '<span class="text-emerald-400">● آنلاین</span>' : '<span class="text-slate-500">○ آفلاین</span>'}</td>
          <td class="py-3 font-mono text-xs text-amber-300">${u.active_ip}</td>
          <td class="py-3">${u.used_mb} MB / ${u.limit_gb} GB</td>
          <td class="py-3">${u.expire_date}</td>
          <td class="py-3"><a href="/sub/${u.sub_token}" target="_blank" class="text-sky-400 underline font-mono text-xs">/sub/${u.sub_token}</a></td>
          <td class="py-3 space-x-1 space-x-reverse">
            <button onclick="userAction('toggle','${u.session_id}')" class="bg-slate-800 hover:bg-slate-700 px-2.5 py-1 rounded text-xs border border-slate-700">${u.enabled ? 'توقف' : 'فعال‌سازی'}</button>
            <button onclick="userAction('reset_traffic','${u.session_id}')" class="bg-sky-900/50 hover:bg-sky-800 px-2.5 py-1 rounded text-xs border border-sky-700/50">ریست حجم</button>
            <button onclick="userAction('delete','${u.session_id}')" class="bg-rose-900/50 hover:bg-rose-800 px-2.5 py-1 rounded text-xs border border-rose-700/50">حذف</button>
          </td>
        </tr>
      ` + "`" + `).join('');
    }

    document.getElementById('addForm').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      await fetch('/api/users', { method: 'POST', body: fd });
      e.target.reset();
      loadUsers();
    };

    loadConfig();
    loadUsers();
    setInterval(loadUsers, 5000);
  </script>
</body>
</html>`
