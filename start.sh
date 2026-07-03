#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

CONFIG="${CONFIG:-config/default.yaml}"
PROFILE="${PROFILE:-}"
CONFIG_FROM_CLI=0
MODE="${MODE:-}"
SERVE_SPA="${SERVE_SPA:-0}"
RELEASE="${RELEASE:-0}"
NO_BUILD="${NO_BUILD:-0}"
BIN="${BIN:-}"
RUST_LOG="${RUST_LOG:-info}"
KILL_EXISTING="${KILL_EXISTING:-0}"
LLM_PROVIDER="${LLM_PROVIDER:-}"
LLM_URL="${LLM_URL:-}"
LLM_API_KEY="${LLM_API_KEY:-}"
LLM_MODEL="${LLM_MODEL:-}"
EMAIL_PROVIDER="${EMAIL_PROVIDER:-}"
EMAIL_FROM_EMAIL="${EMAIL_FROM_EMAIL:-}"
EMAIL_FROM_NAME="${EMAIL_FROM_NAME:-}"
EMAIL_SANDBOX_MODE="${EMAIL_SANDBOX_MODE:-}"
MAILJET_FROM_EMAIL="${MAILJET_FROM_EMAIL:-}"
MAILJET_FROM_NAME="${MAILJET_FROM_NAME:-}"
MAILJET_ENDPOINT="${MAILJET_ENDPOINT:-}"
MAILJET_SANDBOX_MODE="${MAILJET_SANDBOX_MODE:-}"
POSTMARK_ENDPOINT="${POSTMARK_ENDPOINT:-}"
POSTMARK_MESSAGE_STREAM="${POSTMARK_MESSAGE_STREAM:-}"
ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-}"
K8S_CONTEXT="${K8S_CONTEXT:-}"
ES_TUNNEL="${ES_TUNNEL:-0}"
ES_TUNNEL_NAMESPACE="${ES_TUNNEL_NAMESPACE:-}"
ES_TUNNEL_RESOURCE="${ES_TUNNEL_RESOURCE:-}"
ES_TUNNEL_LOCAL_PORT="${ES_TUNNEL_LOCAL_PORT:-9200}"
ES_TUNNEL_REMOTE_PORT="${ES_TUNNEL_REMOTE_PORT:-9200}"
ES_TUNNEL_LOG="${ES_TUNNEL_LOG:-}"
ES_TUNNEL_PID=""
ES_AUTO_CREDENTIALS="${ES_AUTO_CREDENTIALS:-1}"
ES_CREDENTIALS_SECRET="${ES_CREDENTIALS_SECRET:-}"
ES_CREDENTIALS_USERNAME="${ES_CREDENTIALS_USERNAME:-elastic}"

usage() {
  cat <<'EOF'
Usage: ./start.sh [options] [-- extra devops-agent args]

Common options:
  --serve, --serve-spa          Serve the SPA dashboard
  --analyze                     Run scheduled incident detection
  --mode MODE                   Explicit mode: analyze or serve-spa
  --profile NAME                Use config/NAME.yaml (for example: staging)
  --config FILE                 Config path (default: config/default.yaml)
  --release                     Run with cargo --release
  --no-build                    Run an existing target binary instead of cargo run
  --bin PATH                    Run a specific devops-agent binary
  --rust-log FILTER             RUST_LOG filter (default: info)
  --kill-existing               Stop an existing local devops-agent on the SPA port before starting
  --llm-provider PROVIDER       ollama, openai, anthropic, deepseek, groq, openrouter
  --llm-url URL                 LLM base URL, for example http://127.0.0.1:8080/v1
  --llm-api-key KEY             LLM API key; local OpenAI-compatible servers often accept "local"
  --llm-model MODEL             LLM model name (default: config value)
  --email-provider PROVIDER     Abuse-report provider: mailjet or postmark
  --email-from-email EMAIL      Abuse-report sender email (default: config value)
  --email-from-name NAME        Abuse-report sender display name (default: config value)
  --email-sandbox               Validate provider requests without delivering email
  --email-live                  Deliver provider requests
  --postmark-endpoint URL       Postmark send endpoint (default: https://api.postmarkapp.com/email)
  --postmark-message-stream ID  Postmark message stream (default: outbound)
  --mailjet-from-email EMAIL    Abuse-report sender email (default: config value)
  --mailjet-from-name NAME      Abuse-report sender display name (default: config value)
  --mailjet-endpoint URL        Mailjet send endpoint (default: https://api.mailjet.com/v3.1/send)
  --mailjet-sandbox             Validate Mailjet requests without delivering email
  --mailjet-live                Deliver Mailjet requests
  --k8s-context CONTEXT         Switch kube context before discovery/startup
  --enforce                     Apply approved blocks to the cluster
  --dry-run                     Record approvals only; do not apply cluster blocks
  --es-tunnel                   Start a kubectl port-forward to Elasticsearch first
  --es-namespace NAMESPACE      ES tunnel namespace (default: auto-discover)
  --es-resource RESOURCE        ES tunnel resource (default: auto-discover)
  --es-local-port PORT          ES tunnel local port (default: 9200)
  --es-remote-port PORT         ES tunnel remote port (default: 9200)
  --es-tunnel-log FILE          Port-forward log file (default: temp file)
  --no-es-credentials           Do not auto-load ES credentials from Kubernetes secrets
  --es-credentials-secret NAME  ES credentials secret (default: auto-discover ECK secret)
  --es-username USER            ES username for auto-loaded secret (default: elastic)
  -h, --help                    Show this help

Environment overrides:
  CONFIG, PROFILE, MODE, SERVE_SPA, RELEASE, NO_BUILD, BIN, RUST_LOG, KILL_EXISTING
  LLM_PROVIDER, LLM_URL, LLM_API_KEY, LLM_MODEL, ENFORCEMENT_MODE
  ES_USERNAME, ES_PASSWORD, ES_API_KEY
  EMAIL_PROVIDER, EMAIL_FROM_EMAIL, EMAIL_FROM_NAME, EMAIL_SANDBOX_MODE
  MAILJET_API_KEY, MAILJET_API_SECRET, MAILJET_FROM_EMAIL, MAILJET_FROM_NAME
  MAILJET_ENDPOINT, MAILJET_SANDBOX_MODE
  POSTMARK_SERVER_TOKEN, POSTMARK_ENDPOINT, POSTMARK_MESSAGE_STREAM
  K8S_CONTEXT, K8S_KUBECONFIG, K8S_SERVICE_ACCOUNT_TOKEN
  ES_TUNNEL, ES_TUNNEL_NAMESPACE, ES_TUNNEL_RESOURCE
  ES_TUNNEL_LOCAL_PORT, ES_TUNNEL_REMOTE_PORT, ES_TUNNEL_LOG
  ES_AUTO_CREDENTIALS, ES_CREDENTIALS_SECRET, ES_CREDENTIALS_USERNAME

Examples:
  ./start.sh --serve
  ./start.sh --profile staging --serve --es-tunnel
  ./start.sh --serve --es-tunnel
  ./start.sh --serve --es-tunnel --dry-run
  ./start.sh --analyze --es-tunnel
  ./start.sh --analyze --rust-log devops_agent=debug,tower_http=info
  ./start.sh --serve --llm-provider openai --llm-url http://127.0.0.1:8080/v1 --llm-api-key local --llm-model local-model
  ./start.sh --release --serve
EOF
}

local_port_open() {
  local port="$1"
  (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
}

web_port_from_config() {
  awk '
    /^[[:space:]]*web:[[:space:]]*$/ { in_web = 1; next }
    in_web && /^[^[:space:]]/ { in_web = 0 }
    in_web && /^[[:space:]]*port:[[:space:]]*/ {
      value = $0
      sub(/^[[:space:]]*port:[[:space:]]*/, "", value)
      sub(/[[:space:]]+#.*$/, "", value)
      gsub(/["'\'' ]/, "", value)
      print value
      exit
    }
  ' "$CONFIG"
}

resolve_profile_config() {
  if [[ -z "$PROFILE" || "$CONFIG_FROM_CLI" == "1" ]]; then
    return
  fi

  local candidate
  for candidate in \
    "config/${PROFILE}.yaml" \
    "config/${PROFILE}.yml" \
    "config/profiles/${PROFILE}.yaml" \
    "config/profiles/${PROFILE}.yml"; do
    if [[ -f "$candidate" ]]; then
      CONFIG="$candidate"
      return
    fi
  done

  echo "Config profile not found: ${PROFILE}" >&2
  echo "Looked for config/${PROFILE}.yaml, config/${PROFILE}.yml, config/profiles/${PROFILE}.yaml, and config/profiles/${PROFILE}.yml" >&2
  exit 1
}

kube_context_from_config() {
  awk '
    /^[[:space:]]*kubernetes:[[:space:]]*$/ { in_kube = 1; next }
    in_kube && /^[^[:space:]]/ { in_kube = 0 }
    in_kube && /^[[:space:]]*context:[[:space:]]*/ {
      value = $0
      sub(/^[[:space:]]*context:[[:space:]]*/, "", value)
      sub(/[[:space:]]+#.*$/, "", value)
      gsub(/["'\'' ]/, "", value)
      if (value ~ /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/) {
        env_name = substr(value, 3, length(value) - 3)
        value = ENVIRON[env_name]
      }
      print value
      exit
    }
  ' "$CONFIG"
}

select_kube_context() {
  local desired_context
  desired_context="${K8S_CONTEXT:-}"
  if [[ -z "$desired_context" ]]; then
    desired_context="$(kube_context_from_config)"
  fi

  if [[ -z "$desired_context" ]]; then
    return
  fi

  if ! command -v kubectl >/dev/null 2>&1; then
    echo "Config requested Kubernetes context ${desired_context}, but kubectl is not in PATH" >&2
    exit 1
  fi

  local current_context
  current_context="$(kubectl config current-context 2>/dev/null || true)"
  if [[ "$current_context" != "$desired_context" ]]; then
    kubectl config use-context "$desired_context"
  else
    echo "Using Kubernetes context ${desired_context}"
  fi

  export K8S_CONTEXT="$desired_context"
}

port_holder_pids() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
    return
  fi

  ss -ltnp "sport = :${port}" 2>/dev/null \
    | awk 'match($0, /pid=[0-9]+/) { print substr($0, RSTART + 4, RLENGTH - 4) }' \
    | sort -u
}

show_port_holders() {
  local port="$1"
  local pids="$2"
  if [[ -z "$pids" ]]; then
    ss -ltnp "sport = :${port}" >&2 || true
    return
  fi

  while read -r pid; do
    [[ -z "$pid" ]] && continue
    ps -fp "$pid" >&2 || true
  done <<<"$pids"
}

kill_existing_devops_agent_on_port() {
  local port="$1"
  local pids="$2"
  local killed=0

  while read -r pid; do
    [[ -z "$pid" ]] && continue
    local cmdline
    cmdline="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    if [[ "$cmdline" == *"devops-agent"* || "$cmdline" == *"start.sh"* || "$cmdline" == *"cargo run -- --config"* ]]; then
      echo "Stopping existing devops-agent holder on port ${port}: pid ${pid}"
      kill "$pid" >/dev/null 2>&1 || true
      killed=1
    else
      echo "Port ${port} is held by a non-devops-agent process; refusing to kill it:" >&2
      ps -fp "$pid" >&2 || true
      return 1
    fi
  done <<<"$pids"

  if [[ "$killed" == "1" ]]; then
    sleep 1
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    done <<<"$pids"
  fi
}

preflight_web_port() {
  if [[ "$SERVE_SPA" != "1" && "$MODE" != "serve-spa" ]]; then
    return
  fi

  local web_port
  web_port="$(web_port_from_config)"
  web_port="${web_port:-8080}"

  local pids
  pids="$(port_holder_pids "$web_port")"
  if [[ -z "$pids" ]]; then
    return
  fi

  if [[ "$KILL_EXISTING" == "1" ]]; then
    kill_existing_devops_agent_on_port "$web_port" "$pids"
    pids="$(port_holder_pids "$web_port")"
    if [[ -z "$pids" ]]; then
      return
    fi
  fi

  echo "SPA port ${web_port} is already in use. Existing listener(s):" >&2
  show_port_holders "$web_port" "$pids"
  echo "Stop the existing process or rerun with --kill-existing if it is devops-agent." >&2
  exit 1
}

cleanup_es_tunnel() {
  if [[ -n "$ES_TUNNEL_PID" ]] && kill -0 "$ES_TUNNEL_PID" >/dev/null 2>&1; then
    kill "$ES_TUNNEL_PID" >/dev/null 2>&1 || true
    wait "$ES_TUNNEL_PID" >/dev/null 2>&1 || true
  fi
}

discover_es_tunnel_target() {
  local services resource_name candidate
  resource_name="${ES_TUNNEL_RESOURCE#svc/}"
  resource_name="${resource_name#service/}"

  services="$(kubectl get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.clusterIP}{"\t"}{range .spec.ports[*]}{.name}{":"}{.port}{","}{end}{"\n"}{end}')"

  if [[ -n "$resource_name" ]]; then
    candidate="$(
      printf '%s\n' "$services" | awk -F '\t' \
        -v ns="$ES_TUNNEL_NAMESPACE" \
        -v name="$resource_name" \
        '($2 == name) && (ns == "" || $1 == ns) { print; exit }'
    )"
  else
    candidate="$(
      printf '%s\n' "$services" | awk -F '\t' \
        -v ns="$ES_TUNNEL_NAMESPACE" \
        -v port="$ES_TUNNEL_REMOTE_PORT" '
        function has_port(ports, port) {
          return ports ~ (":" port ",")
        }
        {
          if (ns != "" && $1 != ns) next
          if (!has_port($4, port)) next

          name = tolower($2)
          namespace = tolower($1)
          cluster_ip = $3
          score = 0

          if (name ~ /(^|-)es-http$/) score += 120
          if (name ~ /elasticsearch/) score += 90
          if (name ~ /elastic/ && name ~ /http/) score += 80
          if (name ~ /(^|-)es($|-)/ && name ~ /http/) score += 70
          if (namespace ~ /log/) score += 20
          if (cluster_ip == "None") score -= 15
          if (name ~ /internal/) score -= 50
          if (name ~ /default/) score -= 30
          if (name ~ /transport|webhook|kibana|kb/) score -= 100

          print score "\t" $0
        }' | sort -rn | head -n 1 | cut -f2-
    )"
  fi

  if [[ -z "$candidate" ]]; then
    echo "Could not auto-discover an Elasticsearch service for port ${ES_TUNNEL_REMOTE_PORT}." >&2
    echo "Services with '${ES_TUNNEL_REMOTE_PORT}' in their port list:" >&2
    printf '%s\n' "$services" | awk -F '\t' -v port="$ES_TUNNEL_REMOTE_PORT" \
      '$4 ~ (":" port ",") { printf "  %s/%s ports=%s\n", $1, $2, $4 }' >&2
    echo "Pass --es-namespace and --es-resource explicitly." >&2
    exit 1
  fi

  IFS=$'\t' read -r ES_TUNNEL_NAMESPACE resource_name _ <<<"$candidate"
  ES_TUNNEL_RESOURCE="svc/${resource_name}"
  echo "Auto-discovered ES service: ${ES_TUNNEL_NAMESPACE}/${ES_TUNNEL_RESOURCE}"
}

load_es_credentials() {
  local resource_name cluster_name secret password_b64

  if [[ "$ES_AUTO_CREDENTIALS" != "1" ]]; then
    return
  fi

  if [[ -n "${ES_API_KEY:-}" ]]; then
    echo "ES API key is already set; skipping ES basic-auth secret discovery"
    return
  fi

  if [[ -n "${ES_USERNAME:-}" && -n "${ES_PASSWORD:-}" ]]; then
    echo "ES_USERNAME and ES_PASSWORD are already set; skipping ES secret discovery"
    return
  fi

  resource_name="${ES_TUNNEL_RESOURCE#svc/}"
  resource_name="${resource_name#service/}"

  if [[ -z "$ES_CREDENTIALS_SECRET" ]]; then
    cluster_name="$resource_name"
    cluster_name="${cluster_name%-es-http}"
    cluster_name="${cluster_name%-es-internal-http}"
    cluster_name="${cluster_name%-es-default}"

    if kubectl get secret -n "$ES_TUNNEL_NAMESPACE" "${cluster_name}-es-elastic-user" >/dev/null 2>&1; then
      ES_CREDENTIALS_SECRET="${cluster_name}-es-elastic-user"
    else
      ES_CREDENTIALS_SECRET="$(
        kubectl get secrets -n "$ES_TUNNEL_NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
          | awk '/-es-elastic-user$/ { print; exit }'
      )"
    fi
  fi

  if [[ -z "$ES_CREDENTIALS_SECRET" ]]; then
    echo "No ECK elastic-user secret found in namespace ${ES_TUNNEL_NAMESPACE}; using existing .env/config credentials" >&2
    return
  fi

  password_b64="$(kubectl get secret -n "$ES_TUNNEL_NAMESPACE" "$ES_CREDENTIALS_SECRET" -o jsonpath='{.data.elastic}')"
  if [[ -z "$password_b64" ]]; then
    echo "Secret ${ES_TUNNEL_NAMESPACE}/${ES_CREDENTIALS_SECRET} does not contain key 'elastic'" >&2
    return
  fi

  export ES_USERNAME="${ES_USERNAME:-$ES_CREDENTIALS_USERNAME}"
  export ES_PASSWORD
  ES_PASSWORD="$(printf '%s' "$password_b64" | base64 -d)"
  echo "Loaded ES credentials from ${ES_TUNNEL_NAMESPACE}/${ES_CREDENTIALS_SECRET} as user ${ES_USERNAME}"
}

start_es_tunnel() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "--es-tunnel requires kubectl in PATH" >&2
    exit 1
  fi

  if [[ -z "$ES_TUNNEL_NAMESPACE" || -z "$ES_TUNNEL_RESOURCE" ]]; then
    discover_es_tunnel_target
  fi

  if local_port_open "$ES_TUNNEL_LOCAL_PORT"; then
    echo "ES tunnel skipped: 127.0.0.1:${ES_TUNNEL_LOCAL_PORT} is already accepting connections"
    return
  fi

  if [[ -z "$ES_TUNNEL_LOG" ]]; then
    ES_TUNNEL_LOG="$(mktemp -t devops-agent-es-tunnel.XXXXXX.log)"
  fi

  echo "Starting ES tunnel: kubectl -n ${ES_TUNNEL_NAMESPACE} port-forward ${ES_TUNNEL_RESOURCE} ${ES_TUNNEL_LOCAL_PORT}:${ES_TUNNEL_REMOTE_PORT}"
  echo "  tunnel log: $ES_TUNNEL_LOG"
  kubectl -n "$ES_TUNNEL_NAMESPACE" port-forward \
    "$ES_TUNNEL_RESOURCE" \
    "${ES_TUNNEL_LOCAL_PORT}:${ES_TUNNEL_REMOTE_PORT}" \
    >"$ES_TUNNEL_LOG" 2>&1 &
  ES_TUNNEL_PID="$!"

  for _ in {1..50}; do
    if ! kill -0 "$ES_TUNNEL_PID" >/dev/null 2>&1; then
      echo "ES tunnel failed to start. Log follows:" >&2
      sed 's/^/  /' "$ES_TUNNEL_LOG" >&2 || true
      exit 1
    fi

    if local_port_open "$ES_TUNNEL_LOCAL_PORT"; then
      echo "ES tunnel ready on http://127.0.0.1:${ES_TUNNEL_LOCAL_PORT}"
      return
    fi

    sleep 0.2
  done

  echo "Timed out waiting for ES tunnel on 127.0.0.1:${ES_TUNNEL_LOCAL_PORT}. Log follows:" >&2
  sed 's/^/  /' "$ES_TUNNEL_LOG" >&2 || true
  cleanup_es_tunnel
  exit 1
}

extra_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --serve|--serve-spa)
      SERVE_SPA=1
      MODE="serve-spa"
      shift
      ;;
    --analyze)
      SERVE_SPA=0
      MODE="analyze"
      shift
      ;;
    --mode|-m)
      MODE="${2:?missing value for $1}"
      [[ "$MODE" == "serve-spa" ]] && SERVE_SPA=1
      shift 2
      ;;
    --profile)
      PROFILE="${2:?missing value for $1}"
      shift 2
      ;;
    --config|-c)
      CONFIG="${2:?missing value for $1}"
      CONFIG_FROM_CLI=1
      shift 2
      ;;
    --release)
      RELEASE=1
      shift
      ;;
    --no-build)
      NO_BUILD=1
      shift
      ;;
    --bin)
      BIN="${2:?missing value for $1}"
      shift 2
      ;;
    --rust-log)
      RUST_LOG="${2:?missing value for $1}"
      shift 2
      ;;
    --kill-existing)
      KILL_EXISTING=1
      shift
      ;;
    --llm-provider)
      LLM_PROVIDER="${2:?missing value for $1}"
      shift 2
      ;;
    --llm-url)
      LLM_URL="${2:?missing value for $1}"
      shift 2
      ;;
    --llm-api-key)
      LLM_API_KEY="${2:?missing value for $1}"
      shift 2
      ;;
    --llm-model)
      LLM_MODEL="${2:?missing value for $1}"
      shift 2
      ;;
    --email-provider)
      EMAIL_PROVIDER="${2:?missing value for $1}"
      shift 2
      ;;
    --email-from-email)
      EMAIL_FROM_EMAIL="${2:?missing value for $1}"
      shift 2
      ;;
    --email-from-name)
      EMAIL_FROM_NAME="${2:?missing value for $1}"
      shift 2
      ;;
    --email-sandbox)
      EMAIL_SANDBOX_MODE=true
      shift
      ;;
    --email-live)
      EMAIL_SANDBOX_MODE=false
      shift
      ;;
    --postmark-endpoint)
      POSTMARK_ENDPOINT="${2:?missing value for $1}"
      shift 2
      ;;
    --postmark-message-stream)
      POSTMARK_MESSAGE_STREAM="${2:?missing value for $1}"
      shift 2
      ;;
    --mailjet-from-email)
      MAILJET_FROM_EMAIL="${2:?missing value for $1}"
      shift 2
      ;;
    --mailjet-from-name)
      MAILJET_FROM_NAME="${2:?missing value for $1}"
      shift 2
      ;;
    --mailjet-endpoint)
      MAILJET_ENDPOINT="${2:?missing value for $1}"
      shift 2
      ;;
    --mailjet-sandbox)
      MAILJET_SANDBOX_MODE=true
      shift
      ;;
    --mailjet-live)
      MAILJET_SANDBOX_MODE=false
      shift
      ;;
    --k8s-context)
      K8S_CONTEXT="${2:?missing value for $1}"
      shift 2
      ;;
    --enforce)
      ENFORCEMENT_MODE="enforce"
      shift
      ;;
    --dry-run)
      ENFORCEMENT_MODE="dry-run"
      shift
      ;;
    --es-tunnel)
      ES_TUNNEL=1
      shift
      ;;
    --es-namespace)
      ES_TUNNEL_NAMESPACE="${2:?missing value for $1}"
      shift 2
      ;;
    --es-resource)
      ES_TUNNEL_RESOURCE="${2:?missing value for $1}"
      shift 2
      ;;
    --es-local-port)
      ES_TUNNEL_LOCAL_PORT="${2:?missing value for $1}"
      shift 2
      ;;
    --es-remote-port)
      ES_TUNNEL_REMOTE_PORT="${2:?missing value for $1}"
      shift 2
      ;;
    --es-tunnel-log)
      ES_TUNNEL_LOG="${2:?missing value for $1}"
      shift 2
      ;;
    --no-es-credentials)
      ES_AUTO_CREDENTIALS=0
      shift
      ;;
    --es-credentials-secret)
      ES_CREDENTIALS_SECRET="${2:?missing value for $1}"
      shift 2
      ;;
    --es-username)
      ES_CREDENTIALS_USERNAME="${2:?missing value for $1}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      extra_args+=("$@")
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Run ./start.sh --help for usage." >&2
      exit 2
      ;;
  esac
done

resolve_profile_config

if [[ ! -f "$CONFIG" ]]; then
  echo "Config file not found: $CONFIG" >&2
  exit 1
fi

select_kube_context

app_args=(--config "$CONFIG")
if [[ "$SERVE_SPA" == "1" ]]; then
  app_args+=(--serve-spa)
elif [[ -n "$MODE" ]]; then
  app_args+=(--mode "$MODE")
fi

[[ -n "$LLM_PROVIDER" ]] && app_args+=(--llm-provider "$LLM_PROVIDER")
[[ -n "$LLM_URL" ]] && app_args+=(--llm-url "$LLM_URL")
[[ -n "$LLM_API_KEY" ]] && app_args+=(--llm-api-key "$LLM_API_KEY")
[[ -n "$LLM_MODEL" ]] && app_args+=(--llm-model "$LLM_MODEL")
case "$ENFORCEMENT_MODE" in
  enforce)
    app_args+=(--enforce)
    ;;
  dry-run)
    app_args+=(--dry-run)
    ;;
  "")
    ;;
  *)
    echo "Invalid ENFORCEMENT_MODE: $ENFORCEMENT_MODE (expected enforce or dry-run)" >&2
    exit 2
    ;;
esac
app_args+=("${extra_args[@]}")

export RUST_LOG
[[ -n "$EMAIL_PROVIDER" ]] && export EMAIL_PROVIDER
[[ -n "$EMAIL_FROM_EMAIL" ]] && export EMAIL_FROM_EMAIL
[[ -n "$EMAIL_FROM_NAME" ]] && export EMAIL_FROM_NAME
[[ -n "$EMAIL_SANDBOX_MODE" ]] && export EMAIL_SANDBOX_MODE
[[ -n "$MAILJET_FROM_EMAIL" ]] && export MAILJET_FROM_EMAIL
[[ -n "$MAILJET_FROM_NAME" ]] && export MAILJET_FROM_NAME
[[ -n "$MAILJET_ENDPOINT" ]] && export MAILJET_ENDPOINT
[[ -n "$MAILJET_SANDBOX_MODE" ]] && export MAILJET_SANDBOX_MODE
[[ -n "$POSTMARK_ENDPOINT" ]] && export POSTMARK_ENDPOINT
[[ -n "$POSTMARK_MESSAGE_STREAM" ]] && export POSTMARK_MESSAGE_STREAM

if [[ -n "$BIN" ]]; then
  cmd=("$BIN")
elif [[ "$NO_BUILD" == "1" ]]; then
  if [[ "$RELEASE" == "1" ]]; then
    cmd=("target/release/devops-agent")
  else
    cmd=("target/debug/devops-agent")
  fi
else
  cmd=(cargo run)
  [[ "$RELEASE" == "1" ]] && cmd+=(--release)
  cmd+=(--)
fi

if [[ "$NO_BUILD" == "1" || -n "$BIN" ]]; then
  if [[ ! -x "${cmd[0]}" ]]; then
    echo "Binary is not executable or does not exist: ${cmd[0]}" >&2
    echo "Build it first, or omit --no-build to use cargo run." >&2
    exit 1
  fi
fi

echo "Starting devops-agent"
[[ -n "$PROFILE" ]] && echo "  profile: $PROFILE"
echo "  config: $CONFIG"
echo "  command: ${cmd[*]} ${app_args[*]}"
echo "  RUST_LOG: $RUST_LOG"

preflight_web_port

if [[ "$ES_TUNNEL" == "1" ]]; then
  start_es_tunnel
  load_es_credentials
  trap cleanup_es_tunnel EXIT INT TERM
  "${cmd[@]}" "${app_args[@]}"
  exit $?
fi

exec "${cmd[@]}" "${app_args[@]}"
