#!/bin/sh
# Synthetic transport/privacy smoke. Does not assert CCF commitment or attestation.
set -eu
umask 077
: "${AGENTDNS_GRAFANA_PASSWORD_FILE:?Provide the private runtime password file}"
output=${1:?Provide a new private output directory}
[ ! -e "$output" ] || { echo 'Output already exists' >&2; exit 1; }
mkdir -m 700 "$output"
for port in "${OTEL_HTTP_PORT:-14318}" "${TEMPO_HTTP_PORT:-13200}" "${GRAFANA_HTTP_PORT:-13000}"; do
  case "$port" in ''|*[!0-9]*) echo 'Invalid port' >&2; exit 1;; esac
  [ "$port" -gt 0 ] && [ "$port" -le 65535 ]
done
otlp="http://127.0.0.1:${OTEL_HTTP_PORT:-14318}"
tempo="http://127.0.0.1:${TEMPO_HTTP_PORT:-13200}"
grafana="http://127.0.0.1:${GRAFANA_HTTP_PORT:-13000}"
# A running container can precede receiver readiness; probe without posting spans.
deadline=$(( $(date +%s) + 30 ))
while :; do
  if code=$(curl --silent --show-error --max-time 2 -o "$output/receiver-ready.body" -w '%{http_code}' "$otlp/v1/traces" 2>"$output/receiver-ready.stderr"); then
    [ "$code" = 405 ] && break
  fi
  [ "$(date +%s)" -lt "$deadline" ] || { echo 'OTLP receiver readiness deadline exceeded' >&2; exit 1; }
  sleep 1
done
trace=$(openssl rand -hex 16); linked=$(openssl rand -hex 16)
span=$(openssl rand -hex 8); following=$(openssl rand -hex 8)
sentinel="ADNS_SCRUB_TEST_$(openssl rand -hex 12)"
start="$(date +%s)000000000"; end="$(( $(date +%s) + 1 ))000000000"
jq -n --arg t "$trace" --arg l "$linked" --arg s "$span" --arg f "$following" --arg x "$sentinel" --arg start "$start" --arg end "$end" '
 def attrs: [{key:"http.response.status_code",value:{intValue:"200"}},{key:"evidence",value:{stringValue:$x}},{key:"nonce",value:{stringValue:$x}},{key:"authorization",value:{stringValue:$x}},{key:"http.route",value:{stringValue:$x}},{key:"agentdns.queue.depth",value:{stringValue:$x}},{key:"agentdns.work.kind",value:{stringValue:$x}},{key:"ccf.transaction_id",value:{stringValue:$x}},{key:"agentdns.transfer.frames",value:{intValue:"10"}},{key:"agentdns.committed",value:{boolValue:true}}];
 def record($t;$s;$name): {traceId:$t,spanId:$s,name:$name,kind:1,startTimeUnixNano:$start,endTimeUnixNano:$end,attributes:attrs,status:{code:1,message:$x},traceState:("private="+$x),events:[{timeUnixNano:$start,name:$x}]};
 {resourceSpans:[{resource:{attributes:[{key:"service.name",value:{stringValue:"agentdns-otel-smoke"}},{key:"deployment.environment",value:{stringValue:"local-validation"}},{key:"service.namespace",value:{stringValue:"agentdns"}},{key:"service.instance.id",value:{stringValue:"collector-smoke"}},{key:"password",value:{stringValue:$x}}]},scopeSpans:[{scope:{name:$x,version:$x,attributes:[{key:"secret",value:{stringValue:$x}}]},spans:[record($t;$s;"agentdns.otel.smoke"),(record($l;$f;"agentdns.otel.followup")+{links:[{traceId:$t,spanId:$s}]})]}]}]}' > "$output/input.json"
[ "$(curl --silent --show-error --max-time 5 -o "$output/post.json" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @"$output/input.json" "$otlp/v1/traces")" = 200 ]
for id in "$trace" "$linked"; do
  deadline=$(( $(date +%s) + 60 ))
  while :; do
    code=$(curl --silent --show-error --max-time 5 -H 'Accept: application/json' -o "$output/trace-$id.json" -w '%{http_code}' "$tempo/api/traces/$id")
    [ "$code" = 200 ] && break
    [ "$(date +%s)" -lt "$deadline" ] || { echo 'Tempo trace deadline exceeded' >&2; exit 1; }
    sleep 1
  done
  ! rg -q "$sentinel" "$output/trace-$id.json"
  jq -e '.batches[].resource.attributes[] | select(.key=="service.version" and .value.stringValue=="0.1.0")' "$output/trace-$id.json" >/dev/null
done
jq -e '[.batches[].resource.attributes[] | select((.key=="deployment.environment" and .value.stringValue=="local-validation") or (.key=="service.namespace" and .value.stringValue=="agentdns") or (.key=="service.instance.id" and .value.stringValue=="collector-smoke"))] | length==3' "$output/trace-$trace.json" >/dev/null
trace_b64=$(printf '%s' "$trace" | xxd -r -p | openssl base64 -A)
jq -e --arg id "$trace_b64" --arg hex "$trace" '[.batches[].scopeSpans[].spans[].links[] | select(.traceId==$id or .traceId==$hex)] | length==1' "$output/trace-$linked.json" >/dev/null
# Password remains in a protected stdin body; never command-line args or stdout.
jq -n --rawfile password "$AGENTDNS_GRAFANA_PASSWORD_FILE" '{user:"agentdns",password:($password|rtrimstr("\n"))}' |
  curl --silent --show-error --max-time 5 -H 'Content-Type: application/json' --data-binary @- -c "$output/cookies" "$grafana/login" > "$output/login.json"
jq -e '.message=="Logged in"' "$output/login.json" >/dev/null
for route in user datasources/uid/agentdns-tempo dashboards/uid/agentdns-architecture; do
  filename=$(printf '%s' "$route" | tr / _)
  [ "$(curl --silent --show-error --max-time 5 -b "$output/cookies" -o "$output/$filename.json" -w '%{http_code}' "$grafana/api/$route")" = 200 ]
done
[ "$(curl --silent --show-error --max-time 5 -b "$output/cookies" -H 'Accept: application/json' -o "$output/grafana-trace.json" -w '%{http_code}' "$grafana/api/datasources/proxy/uid/agentdns-tempo/api/traces/$trace")" = 200 ]
! rg -q "$sentinel" "$output/grafana-trace.json"
rm "$output/cookies"
jq -n --arg trace "$trace" --arg linked "$linked" '{status:"passed",scope:"synthetic transport/privacy smoke only; no native CCF assertion",trace_id:$trace,linked_trace_id:$linked,checks:["OTLP HTTP accepted","Tempo exact trace retrieved","async link preserved","private fields scrubbed","Grafana login","authenticated datasource/dashboard/trace resource access"]}' | tee "$output/result.json"
