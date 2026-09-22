FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    NODE_ENV=production \
    EVERSMARTNODE_DATA_DIR=/var/lib/eversmartnode \
    EVERSMARTNODE_SECRET_DIR=/var/lib/eversmartnode/secrets \
    EVERSMARTNODE_SUPERVISOR_CONF=/etc/eversmartnode/supervisord.conf

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod +x /usr/sbin/policy-rc.d \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg bash openssl \
      libssl3 libstdc++6 libsqlite3-0 libfuse3-3 supervisor \
 && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
      > /etc/apt/sources.list.d/nodesource.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /usr/local/bin/hotpocket /opt/eversmartnode /etc/eversmartnode \
      /var/lib/eversmartnode/secrets /var/log/supervisor

COPY runtime/hotpocket/ /usr/local/bin/hotpocket/
COPY runtime/lib/libblake3.so /usr/local/lib/libblake3.so
COPY runtime/lib/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1
COPY runtime/lib/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1

RUN chmod 0755 /usr/local/bin/hotpocket/hpcore /usr/local/bin/hotpocket/hpfs /usr/local/bin/hotpocket/hpws \
 && chmod 0644 /usr/local/bin/hotpocket/evernode-license.pdf \
 && ldconfig

WORKDIR /opt/eversmartnode
COPY package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund \
 && node -e 'const fs=require("fs"),path=require("path");const one=(root,name)=>{const a=[];(function w(d){for(const e of fs.readdirSync(d,{withFileTypes:true})){const q=path.join(d,e.name);e.isDirectory()?w(q):e.name===name&&a.push(q)}})(root);if(a.length!==1)throw new Error(`Expected one ${name} under ${root}, found ${a.length}`);return a[0]};const ep=one(path.resolve("node_modules/everpocket-nodejs-contract"),"EvernodeContext.js");let s=fs.readFileSync(ep,"utf8"),n=s;s=s.replace(/((?:const|let|var)\s+ACQUIRE_ABANDON_LCL_THRESHOLD\s*=\s*)10;/,"$1Number.MAX_SAFE_INTEGER;");if(s===n&&!/ACQUIRE_ABANDON_LCL_THRESHOLD\s*=\s*Number\.MAX_SAFE_INTEGER/.test(s))throw new Error("Acquire abandon threshold signature not found");n=s;const call=/(const|let|var)\s+res\s*=\s*(await|yield)\s+tenantClient\.extractEvernodeEvent\(t\.tx\);/;s=s.replace(call,(m,decl,op)=>`const __esEventType = t.tx?.HookParameters?.find(p => p.name === evernode.HookParamKeys.PARAM_EVENT_TYPE_KEY)?.value;\n                const __esEventData = t.tx?.HookParameters?.find(p => p.name === evernode.HookParamKeys.PARAM_EVENT_DATA_KEY)?.value;\n                if ((__esEventType === evernode.EventTypes.ACQUIRE_SUCCESS || __esEventType === evernode.EventTypes.ACQUIRE_ERROR) && __esEventData && __esEventData !== item.refId) continue;\n                ${decl} res = ${op} tenantClient.extractEvernodeEvent(t.tx);`);if(s===n&&!/__esEventData !== item\.refId/.test(s))throw new Error("EverPocket acquire pre-decrypt correlation signature not found");fs.writeFileSync(ep,s);console.log(`Patched EverPocket acquire pre-decrypt correlation: ${ep}`);' \
 && EP_CTX="$(find node_modules/everpocket-nodejs-contract -type f -name EvernodeContext.js -print -quit)" \
 && test -n "$EP_CTX" \
 && node --check "$EP_CTX" \
 && npm cache clean --force

COPY server.js ./server.js
COPY contract/ ./contract/

# HotPocket executes the contract from consensus state, where /opt/node_modules
# is intentionally unavailable. Bundle controller dependencies into one JS file
# at build time instead of copying an npm node_modules tree into HotPocket state.
RUN ./node_modules/.bin/esbuild /opt/eversmartnode/contract/cluster-controller.js \
      --bundle \
      --platform=node \
      --format=cjs \
      --target=node20 \
      --outfile=/tmp/cluster-controller.js \
 && mv /tmp/cluster-controller.js /opt/eversmartnode/contract/cluster-controller.js \
 && WASM_SRC="$(find /opt/eversmartnode/node_modules -type f -path '*/nodejs/blake3_js_bg.wasm' -print -quit)" \
 && test -n "$WASM_SRC" \
 && cp "$WASM_SRC" /opt/eversmartnode/contract/blake3_js_bg.wasm \
 && test -s /opt/eversmartnode/contract/blake3_js_bg.wasm \
 && node --check /opt/eversmartnode/contract/cluster-controller.js \
 && node -e "const fs=require('fs'),crypto=require('crypto'),path=require('path'); const root='/opt/eversmartnode/contract'; const mf=path.join(root,'everadmin.package.json'); const m=JSON.parse(fs.readFileSync(mf,'utf8')); const info=(name,role)=>{const b=fs.readFileSync(path.join(root,name)); return {path:name,role,sha256:crypto.createHash('sha256').update(b).digest('hex'),size:b.length};}; const next=[]; let controllerDone=false,wasmDone=false; for(const f of m.files||[]){ if(f.path==='cluster-controller.js'){next.push(info('cluster-controller.js','contract')); controllerDone=true;} else if(f.path==='blake3_js_bg.wasm'){next.push(info('blake3_js_bg.wasm','contract')); wasmDone=true;} else next.push(f); } if(!controllerDone) next.push(info('cluster-controller.js','contract')); if(!wasmDone) next.push(info('blake3_js_bg.wasm','contract')); m.files=next; fs.writeFileSync(mf,JSON.stringify(m,null,2)+'\n');"
COPY supervisord.conf /etc/eversmartnode/supervisord.conf
COPY supervisorctl /usr/local/bin/eversmartnode-supervisorctl
COPY start.sh /start.sh

RUN chmod 0755 /start.sh /usr/local/bin/eversmartnode-supervisorctl \
 && chmod 0700 /var/lib/eversmartnode/secrets \
 && node --check /opt/eversmartnode/server.js \
 && node --version \
 && (/usr/local/bin/hotpocket/hpcore --help >/dev/null 2>&1 || true)

ENV NODE_PATH=/opt/eversmartnode/node_modules \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu

LABEL org.opencontainers.image.title="EverSmartNode" \
      org.opencontainers.image.version="1.7.0-alpha.53.95-purity-fence-handover" \
      org.opencontainers.image.description="EverSmartNode autonomous Evernode cluster bootstrap on Ubuntu 24.04; native Node.js HTTPS control plane"

ENTRYPOINT ["/start.sh"]
