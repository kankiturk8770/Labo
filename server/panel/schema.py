"""The single panel schema. All gateway environment settings are enumerated."""
import ipaddress
import re
from urllib.parse import urlsplit

FIELDS = [
 ('EDGE_ADDR', ':8443', 'network', 'آدرس و پورت شنود', 'برای همهٔ رابط‌ها :8443؛ برای IPv6 از [::]:8443 استفاده کنید.', 'text'),
 ('EDGE_INTERNAL_BACKENDS', 'http://127.0.0.1:8081,http://127.0.0.1:8082', 'network', 'سرورهای داخلی', 'هر خط یک آدرس؛ ترتیب، ترتیب انتخاب نوبتی است. http / https / ws / wss', 'backends'),
 ('EDGE_DECOY_ORIGIN', '', 'network', 'مقصد درخواست‌های نامعتبر', 'آدرس HTTPS مقصد جایگزین؛ مسیر و query پشتیبانی می‌شوند.', 'url'),
 ('EDGE_ALLOW_INSECURE_DECOY', 'false', 'network', 'اجازهٔ HTTP برای مقصد جایگزین', 'فقط برای تست محلی؛ پیش‌فرض false است.', 'bool'),
 ('EDGE_HMAC_SECRET', '', 'security', 'کلید مشترک HMAC', 'حداقل ۳۲ بایت؛ با تغییر این کلید باید کلاینت‌ها را نیز به‌روز کنید. خالی = حفظ کلید فعلی.', 'secret'),
 ('EDGE_SIGNATURE_MAX_SKEW', '5m', 'security', 'بازهٔ اعتبار زمانی امضا', 'قالب Go مثل 30s یا 5m. این بازه مانع تکرار درخواست درون بازه نمی‌شود.', 'duration'),
 ('EDGE_CERT_FILE', '/etc/edge-gateway/certs/tls.crt', 'security', 'مسیر گواهی TLS', 'گواهی زنجیره‌ای PEM؛ از بخش گواهی‌ها وارد کنید.', 'text'),
 ('EDGE_KEY_FILE', '/etc/edge-gateway/certs/tls.key', 'security', 'مسیر کلید خصوصی TLS', 'کلید PEM بدون گذرواژه؛ باید با گواهی مطابقت داشته باشد.', 'text'),
 ('EDGE_TLS_MIN_VERSION', '1.2', 'security', 'حداقل نسخهٔ TLS', 'هم برای اتصال ورودی و هم خروجی؛ پیش‌فرض اصلی 1.2 است.', 'tls'),
 ('EDGE_SHUTDOWN_TIMEOUT', '30s', 'limits', 'مهلت خاموش‌شدن', 'برای درخواست‌های معمولی؛ WebSocketهای ارتقایافته در هستهٔ اصلی drain نمی‌شوند.', 'duration'),
 ('EDGE_READ_HEADER_TIMEOUT', '10s', 'limits', 'مهلت خواندن هدر', 'فقط هدر؛ برای بدنه و جریان WebSocket محدودیت زمانی جدیدی اضافه نمی‌شود.', 'duration'),
 ('EDGE_SERVER_IDLE_TIMEOUT', '120s', 'limits', 'زمان بیکاری اتصال ورودی', 'مقدار پیش‌فرض هسته: 120s', 'duration'),
 ('EDGE_MAX_HEADER_BYTES', '65536', 'limits', 'حد اندازهٔ هدر (بایت)', 'از ۱۰۲۴ تا ۱۶۷۷۷۲۱۶؛ همان MaxHeaderBytes در Go، همراه با سربار داخلی parser.', 'number'),
 ('EDGE_MAX_IDLE_CONNS', '256', 'limits', 'سقف اتصال‌های بیکار خروجی', 'برای هر transport؛ هسته برای مقصد جایگزین و سرورها transport مجزا دارد.', 'number'),
 ('EDGE_MAX_IDLE_CONNS_PER_HOST', '64', 'limits', 'سقف اتصال بیکار به هر میزبان', 'محدودیت تعداد کاربران یا اتصال‌های فعال نیست.', 'number'),
 ('EDGE_UPSTREAM_IDLE_TIMEOUT', '90s', 'limits', 'زمان بیکاری اتصال خروجی', 'مقدار پیش‌فرض هسته: 90s', 'duration'),
 ('EDGE_TLS_HANDSHAKE_TIMEOUT', '10s', 'limits', 'مهلت TLS خروجی', 'مقدار پیش‌فرض هسته: 10s', 'duration'),
 ('EDGE_EXPECT_CONTINUE_TIMEOUT', '1s', 'limits', 'مهلت Expect Continue', 'مقدار پیش‌فرض هسته: 1s', 'duration'),
]
DEFAULTS = {f[0]:f[1] for f in FIELDS}
SCHEMA = [dict(zip(('key','default','group','label','hint','type'), f)) for f in FIELDS]
UNITS = {'ns':1,'us':1000,'µs':1000,'μs':1000,'ms':1000000,'s':10**9,'m':60*10**9,'h':3600*10**9}

def duration(s):
 from decimal import Decimal
 raw=s.removeprefix('+'); parts=list(re.finditer(r'(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)',raw))
 if not parts or ''.join(m[0] for m in parts)!=raw: raise ValueError('مدت زمان نامعتبر است: '+s)
 n=sum(Decimal(m[1])*UNITS[m[2]] for m in parts)
 if not 0<n<=2**63-1: raise ValueError('مدت زمان خارج از محدوده است')
 return float(n/10**9)

def address(s):
 m=re.fullmatch(r'(\[[0-9a-fA-F:.%a-zA-Z0-9_-]+\]|[^:\s]*):(\d+)',s)
 if not m or not 1<=int(m[2])<=65535: raise ValueError('آدرس شنود باید host:port یا :port باشد')
 host=m[1].strip('[]')
 if host and any(c in host for c in '/?#@'): raise ValueError('میزبان شنود نامعتبر است')
 return host,int(m[2])

def target(s):
 if any(c.isspace() for c in s) or '\\' in s: raise ValueError('آدرس مقصد نامعتبر است')
 u=urlsplit(s)
 if u.scheme not in ('http','https','ws','wss') or not u.hostname or u.username is not None or u.password is not None or '#' in s: raise ValueError('آدرس مقصد باید HTTP(S) یا WS(S)، بدون نام کاربری و fragment باشد')
 try:
  if u.port is not None and not 1<=u.port<=65535: raise ValueError()
 except ValueError: raise ValueError('پورت مقصد نامعتبر است')
 return u

def validate(cfg):
 if set(cfg)!=set(DEFAULTS): raise ValueError('کلیدهای تنظیمات ناقص یا ناشناخته‌اند')
 for k,v in cfg.items():
  if not isinstance(v,str) or len(v)>16384 or any(ord(c)<32 or ord(c)==127 for c in v): raise ValueError('مقدار نامعتبر: '+k)
  if v!=v.strip(): raise ValueError('فاصلهٔ ابتدا/انتهای مقدار مجاز نیست: '+k)
 for f in SCHEMA:
  k=f['key']; v=cfg[k]
  if f['type']=='duration': duration(v)
  if f['type']=='number':
   lo,hi=(1024,16777216) if k=='EDGE_MAX_HEADER_BYTES' else (1,1000000)
   if not v.isascii() or not v.isdecimal() or not lo<=int(v)<=hi: raise ValueError(k+': مقدار خارج از محدوده')
 address(cfg['EDGE_ADDR'])
 if len(cfg['EDGE_HMAC_SECRET'].encode())<32: raise ValueError('کلید HMAC باید حداقل ۳۲ بایت باشد')
 if cfg['EDGE_TLS_MIN_VERSION'] not in ('1.2','1.3'): raise ValueError('نسخهٔ TLS نامعتبر است')
 if cfg['EDGE_ALLOW_INSECURE_DECOY'] not in ('true','false'): raise ValueError('مقدار boolean نامعتبر است')
 u=target(cfg['EDGE_DECOY_ORIGIN'])
 if u.scheme in ('http','ws') and cfg['EDGE_ALLOW_INSECURE_DECOY']!='true': raise ValueError('مقصد جایگزین باید HTTPS باشد')
 backends=cfg['EDGE_INTERNAL_BACKENDS'].split(',')
 if not 1<=len(backends)<=128: raise ValueError('تعداد سرورهای داخلی باید بین ۱ و ۱۲۸ باشد')
 for b in backends: target(b)
 for k in ('EDGE_CERT_FILE','EDGE_KEY_FILE'):
  from pathlib import Path
  p=Path(cfg[k])
  if not p.is_absolute() or '..' in p.parts or not p.is_relative_to('/etc/edge-gateway/certs'): raise ValueError('مسیر گواهی باید داخل /etc/edge-gateway/certs باشد؛ از واردکردن گواهی استفاده کنید')
 return cfg

def encode_env(cfg):
 return ''.join(k+'="'+v.replace('\\','\\\\').replace('"','\\"').replace('$','\\$').replace('`','\\`')+'"\n' for k,v in sorted(cfg.items()))

def decode_env(text):
 out={}
 for line in text.splitlines():
  if not line.strip() or line.lstrip().startswith('#'): continue
  k,sep,v=line.partition('=')
  if not sep or k not in DEFAULTS: raise ValueError('فایل تنظیمات ناشناخته؛ ابتدا مهاجرت کنید')
  if v.startswith('"') and v.endswith('"'):
   raw=v[1:-1]; v=re.sub(r'\\([\\"$`])',r'\1',raw)
  elif v.startswith("'") and v.endswith("'"):v=v[1:-1]
  out[k]=v
 return DEFAULTS|out
