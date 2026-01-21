// Fragment Subscription Worker (FINAL – Importable)

const subLinks = [
  'https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/ws_tls/proxies/wstls',
  'https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt',
  'https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/refs/heads/main/protocols/trojan',
  'https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/refs/heads/main/protocols/vmess',
  'https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt',
  'https://raw.githubusercontent.com/hans-thomas/v2ray-subscription/refs/heads/master/servers.txt'
];

export default {
  async fetch(request) {
    const url = new URL(request.url);

    /* ================= UI ================= */
    if (url.pathname === '/') {
      return new Response(ui(), {
        headers: { 'Content-Type': 'text/html' }
      });
    }

    /* ================= FRAGMENT ================= */
    if (url.pathname.startsWith('/fragment/')) {
      const fakeSNI = url.searchParams.get('sni') || 'chatgpt.com';
      const length = url.searchParams.get('length') || '10-30';
      const interval = url.searchParams.get('interval') || '1-10';

      let fragments = [];
      let seen = new Set();

      for (const link of subLinks) {
        try {
          const r = await fetch(link);
          if (!r.ok) continue;

          let text = await r.text();
          if (isBase64(text)) text = atob(text);

          for (let line of text.split(/\r?\n/)) {
            line = line.trim();
            if (!line) continue;

            try {
              /* ========== VMESS ========== */
              if (line.startsWith('vmess://')) {
                const cfg = JSON.parse(atob(line.replace('vmess://', '')));
                if (!['ws', 'grpc'].includes(cfg.net)) continue;
                if (!cfg.id || !cfg.sni) continue;

                const key = cfg.id + cfg.sni + cfg.path;
                if (seen.has(key)) continue;
                seen.add(key);

                fragments.push(
                  buildFragment({
                    uuid: cfg.id,
                    network: cfg.net,
                    path: cfg.path || '/',
                    realHost: cfg.sni,
                    fakeSNI,
                    length,
                    interval
                  })
                );
              }

              /* ========== VLESS ========== */
              if (line.startsWith('vless://')) {
                const u = new URL(line);
                const net = u.searchParams.get('type');
                if (!['ws', 'grpc'].includes(net)) continue;

                const uuid = u.username;
                const realHost = u.searchParams.get('sni');
                const path = decodeURIComponent(
                  u.searchParams.get('path') || '/'
                );

                if (!uuid || !realHost) continue;

                const key = uuid + realHost + path;
                if (seen.has(key)) continue;
                seen.add(key);

                fragments.push(
                  buildFragment({
                    uuid,
                    network: net,
                    path,
                    realHost,
                    fakeSNI,
                    length,
                    interval
                  })
                );
              }
            } catch {}
          }
        } catch {}
      }

      return new Response(JSON.stringify(fragments, null, 2), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};

/* ================= Fragment Builder ================= */
function buildFragment({
  uuid,
  network,
  path,
  realHost,
  fakeSNI,
  length,
  interval
}) {
  return {
    remarks: `Node-${realHost} (Fragment-VLESS)`,

    log: {
      loglevel: "warning"
    },

    inbounds: [
      {
        tag: "socks",
        port: 10808,
        listen: "127.0.0.1",
        protocol: "socks",
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls"]
        },
        settings: {
          auth: "noauth",
          udp: true
        }
      },
      {
        tag: "http",
        port: 10809,
        listen: "127.0.0.1",
        protocol: "http",
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls"]
        },
        settings: {
          auth: "noauth",
          udp: true
        }
      }
    ],

    outbounds: [
      {
        tag: "proxy",
        protocol: "vless",
        settings: {
          vnext: [
            {
              address: fakeSNI,
              port: 443,
              users: [
                {
                  id: uuid,
                  encryption: "none",
                  level: 8
                }
              ]
            }
          ]
        },
        streamSettings: {
          network,
          security: "tls",
          tlsSettings: {
            serverName: realHost,
            alpn: ["h2", "http/1.1"],
            fingerprint: "chrome"
          },
          ...(network === "ws"
            ? {
                wsSettings: {
                  path,
                  headers: { Host: realHost }
                }
              }
            : {
                grpcSettings: {
                  serviceName: path.replace("/", "")
                }
              }),
          sockopt: {
            dialerProxy: "fragment",
            tcpNoDelay: true,
            tcpKeepAliveIdle: 100
          }
        }
      },
      {
        tag: "fragment",
        protocol: "freedom",
        settings: {
          domainStrategy: "AsIs",
          fragment: {
            packets: "tlshello",
            length,
            interval
          },
          noises: [
            {
              delay: "10-16",
              packet: "10-20",
              type: "rand"
            }
          ]
        }
      },
      {
        tag: "direct",
        protocol: "freedom",
        settings: {}
      },
      {
        tag: "block",
        protocol: "blackhole",
        settings: {
          response: { type: "http" }
        }
      }
    ],

    routing: {
      domainStrategy: "AsIs",
      rules: [
        {
          type: "field",
          port: "0-65535",
          outboundTag: "proxy"
        }
      ]
    }
  };
}

/* ================= UI ================= */
function ui() {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Fragment Generator</title>
<style>
body{font-family:Arial;background:#f4f6fb;padding:40px}
.card{background:#fff;padding:20px;border-radius:12px;max-width:420px;margin:auto}
input,select,button{width:100%;padding:10px;margin-top:10px}
button{background:#2563eb;color:#fff;border:none;border-radius:6px}
</style>
</head>
<body>
<div class="card">
<h2>Fragment Subscription</h2>

<select id="sni">
<option value="chatgpt.com">chatgpt.com</option>
<option value="deepseek.com">deepseek.com</option>
</select>

<input id="custom" placeholder="Custom SNI (optional)">
<input id="length" value="10-30">
<input id="interval" value="1-10">

<button onclick="go()">Generate</button>
</div>

<script>
function go(){
  const sni =
    document.getElementById('custom').value ||
    document.getElementById('sni').value;

  const length = document.getElementById('length').value;
  const interval = document.getElementById('interval').value;

  location.href =
    '/fragment/0.0.0.0?sni=' + sni +
    '&length=' + length +
    '&interval=' + interval;
}
</script>
</body>
</html>
`;
}

/* ================= Utils ================= */
function isBase64(str) {
  try {
    atob(str);
    return true;
  } catch {
    return false;
  }
}
