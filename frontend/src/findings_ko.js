// findings_ko.js — Korean localization for scanner findings (title / description
// / reproduction). Scanner output is generated per scan, so we translate by
// matching the scanner's templates (with capture groups) plus an id map for the
// fixed sample findings. Falls back to the original English on no match / non-ko.
import { getLang } from "./i18n.js";
import { ruleDesc } from "./ruleset_ko.js";

// ── Fixed sample findings (offline / demo) keyed by id ───────────────────────
const BY_ID = {
  "st-r5-set-value": {
    title: "도구 'set'의 제약 없는 문자열 파라미터 'value'",
    description: "'value' 파라미터가 maxLength·pattern·format 제약 없이 임의 문자열을 받습니다. 제한 없는 입력은 퍼징 표면을 넓히고 과도한 크기의 페이로드를 백엔드로 그대로 전달할 수 있습니다.",
  },
  "st-r5-key-pattern": {
    title: "도구 'list'의 'pattern' 파라미터가 검증되지 않은 glob 허용",
    description: "'pattern' 파라미터가 검증 없이 Redis KEYS/SCAN glob로 전달됩니다. 넓은 패턴(예: '*')은 전체 키스페이스를 열거할 수 있습니다 — 동적으로 확인할 가치가 있는 약한 데이터 노출 신호입니다.",
  },
  "st-r1-delete-scope": {
    title: "파괴적 도구 'delete'가 제한 없는 키 접근을 노출",
    description: "'delete' 도구는 네임스페이스 접두사나 허용 목록 없이 이름으로 어떤 키든 삭제합니다. 'list'와 결합하면 에이전트가 키를 열거한 뒤 임의로 삭제할 수 있습니다. 신뢰도 낮은 설계 신호이며, 배포 환경이 연결 범위를 제한하는지 확인하세요.",
  },
  "st-r6-manifest-pin": {
    title: "매니페스트에 의존성 버전이 고정되지 않음",
    description: "package.json이 고정되지 않은 '-y @modelcontextprotocol/server-redis'(latest)로 서버를 실행합니다. 버전이 고정되지 않으면 점검한 빌드와 배포된 빌드가 달라질 수 있습니다. 참고용 — 재현 가능한 스캔을 위해 버전을 고정하세요.",
  },
  "pp-r2-eval": {
    title: "도구 'evaluate'에서 도구가 제어하는 표현식의 동적 eval",
    description: "'evaluate' 도구가 'script' 인자를 브라우저 컨텍스트에서 코드로 실행되는 page.evaluate()에 그대로 넘깁니다. 허용 목록이나 샌드박싱이 없어 도구 입력만으로 임의 코드 실행이 가능합니다.",
  },
  "pp-r1-screenshot": {
    title: "내비게이션 도구가 내부 네트워크 주소에 접근 가능",
    description: "'navigate' 도구가 호스트 허용 목록 없이 임의 URL을 받습니다. 에이전트가 헤드리스 브라우저를 169.254.169.254나 내부 서비스로 향하게 할 수 있습니다 — SSRF·데이터 노출 경로(R1).",
  },
  "pp-r5-path": {
    title: "스크린샷 경로를 정규화 없이 기록",
    description: "'screenshot' 도구가 호출자가 준 경로에 path.normalize/resolve 차단 없이 fs.writeFileSync로 기록합니다 — 경로 탐색 쓰기(R5).",
  },
  "gh-r5-search": {
    title: "도구 'search_issues'의 제약 없는 쿼리 문자열",
    description: "'q' 파라미터가 maxLength 없이 임의 문자열을 받아 GitHub 검색 API로 바로 전달됩니다 — 제한할 가치가 있는 약한 입력 검증 신호입니다.",
  },
  "gh-r1-token": {
    title: "환경변수에서 GITHUB_TOKEN 읽기",
    description: "서버가 비밀번호성 환경변수(GITHUB_TOKEN)를 읽습니다. 이 서버에는 정상이지만, 유출 스캐너가 연관 지을 수 있도록 INFO/낮음으로 표시합니다(R1).",
  },
  "wx-r1-key": {
    title: "명령줄로 전달되는 API 키",
    description: "weather-mcp가 '--api-key env:WEATHER_KEY'로 실행됩니다. 비밀을 CLI 인자로 넘기면 프로세스 목록을 통해 같은 로컬 사용자에게 노출됩니다(R1).",
  },
  "wx-r6-timeout": {
    title: "타임아웃 없는 아웃바운드 HTTP 요청",
    description: "상위 날씨 API로의 requests.get()에 타임아웃이 없습니다. 상위 서버가 멈추면 우리 서버가 무한정 블록됩니다 — 안정성·가용성 위험(R6).",
  },
  "fs-r5-read": {
    title: "포함 검사 없이 결합되는 읽기 경로",
    description: "'read_file' 도구가 요청 경로를 루트 아래로 결합하지만, 결합된 경로를 루트 접두사와 다시 대조하지 않습니다 — 신뢰도 낮은 경로 탐색 신호입니다.",
  },
};

// ── Title templates ──────────────────────────────────────────────────────────
const TITLE = [
  [/^Sequence timeout: '(.+?)'$/, (m) => `시퀀스 타임아웃: '${m[1]}'`],
  [/^Server crashed during sequence '(.+?)'$/, (m) => `시퀀스 '${m[1]}' 실행 중 서버 크래시`],
  [/^Server crash triggered by '(.+?)' payload to tool '(.+?)'$/, (m) => `도구 '${m[2]}'에 보낸 '${m[1]}' 페이로드로 서버 크래시`],
  [/^Tool '(.+?)' stalled after '(.+?)' input \(cascading timeouts on (\d+) subsequent requests?\)$/,
    (m) => `도구 '${m[1]}'가 '${m[2]}' 입력 후 멈춤 (이후 요청 ${m[3]}건 연쇄 타임아웃)`],
  [/^Timeout \/ hang on category '(.+?)' for tool '(.+?)'$/, (m) => `도구 '${m[2]}'에서 '${m[1]}' 범주 타임아웃/멈춤`],
  [/^Server returns -32603 'Internal error' for (\d+)\/(\d+) malformed inputs \(should be -32602 Invalid Params\)$/,
    (m) => `잘못된 입력 ${m[1]}/${m[2]}건에 서버가 -32603 'Internal error' 반환 (-32602 Invalid Params가 맞음)`],
];

// ── Description templates ────────────────────────────────────────────────────
const DESC = [
  [/^The MCP server process terminated unexpectedly while running test sequence '(.+?)'\. This indicates fragile error handling that could be exploited for DoS\.$/,
    (m) => `테스트 시퀀스 '${m[1]}'를 실행하던 중 MCP 서버 프로세스가 예기치 않게 종료됐습니다. 오류 처리가 취약하다는 신호이며 DoS로 악용될 수 있습니다.`],
  [/^Test sequence '(.+?)' did not complete within its timeout\..*$/,
    (m) => `테스트 시퀀스 '${m[1]}'가 제한 시간 안에 끝나지 않았습니다. 서버 멈춤, 느린 외부 호출(검색·API 래핑 도구), 또는 부족한 스캔 예산을 의미할 수 있습니다. 도구별 client_timeout 발견이 있으면 원인을 좁힐 수 있습니다.`],
  [/^Sending a '(.+?)'-class payload to '(.+?)' terminated the MCP server process \(sequence '(.+?)'\)\..*$/,
    (m) => `'${m[1]}' 계열 페이로드를 '${m[2]}'에 보내자 MCP 서버 프로세스가 종료됐습니다(시퀀스 '${m[3]}'). 잘못된 요청 한 번으로 서버가 죽습니다 — 손쉽게 악용 가능한 DoS입니다.`],
  [/^A payload in category '(.+?)' put '(.+?)' into an unresponsive state; the following (\d+) subsequent fuzz inputs \((.+?)\) were also queued behind the stall and hit the client timeout.*$/,
    (m) => `'${m[1]}' 범주의 페이로드가 '${m[2]}'를 응답 불능 상태로 만들었습니다. 뒤이은 퍼즈 입력 ${m[3]}건(${m[4]})도 멈춤 뒤에 밀려 클라이언트 타임아웃에 걸렸습니다 — 독립적인 멈춤이 아니라 하나의 근본 멈춤입니다. 첫 입력이 원인이며, 연쇄 발생은 멈춤이 지속적(테스트 시간 동안 서버가 회복하지 못함)임을 뜻합니다.`],
  [/^Payload in category '(.+?)' caused the server to time out\.$/,
    (m) => `'${m[1]}' 범주의 페이로드 때문에 서버가 타임아웃됐습니다.`],
  [/^Of (\d+) JSON-RPC error responses across the scan, (\d+) \((\d+)%\) used code -32603.*Sample message: "(.+)"$/,
    (m) => `스캔 동안의 JSON-RPC 오류 응답 ${m[1]}건 중 ${m[2]}건(${m[3]}%)이 -32603(Internal Error) 코드를 사용했고 -32602(Invalid Params)는 거의 쓰이지 않았습니다. MCP 서버는 -32603을 예기치 못한 내부 오류에만 써야 하며, 검증에 실패한 사용자 입력은 -32602에 해당합니다. -32603 오용은 스키마 검증 전에 입력이 예외를 일으키는 코드 경로에 도달한다는 뜻이며, message 필드는 보통 가장 깊은 실패 계층(라이브러리/백엔드/의존성)의 스택 트레이스를 노출합니다. CWE-20(부적절한 입력 검증) + CWE-209(오류 메시지를 통한 정보 노출)에 해당합니다. 예시 메시지: "${m[4]}"`],
];

// ── Reproduction templates ───────────────────────────────────────────────────
const REPRO = [
  [/^Run sequence '(.+?)' and observe server process$/, (m) => `시퀀스 '${m[1]}'를 실행하고 서버 프로세스를 관찰하세요`],
  [/^Run sequence '(.+?)' with its specific inputs$/, (m) => `시퀀스 '${m[1]}'를 해당 입력으로 실행하세요`],
  [/^Send a? ?'(.+?)' payload to tool '(.+?)'$/, (m) => `도구 '${m[2]}'에 '${m[1]}' 페이로드를 보내세요`],
  [/^Send malformed input.*$/, () => `아무 도구에나 잘못된 입력(잘못된 타입, 누락된 필수 필드, 범위 초과 값)을 보내고, -32602 'Invalid Params'가 맞는 자리에 스택 트레이스가 담긴 -32603 응답이 오는지 관찰하세요.`],
];

function apply(rules, text) {
  if (!text) return text;
  for (const [re, fn] of rules) {
    const m = text.match(re);
    if (m) return fn(m);
  }
  return text;
}

/** Returns {title, description, reproduction} — Korean when lang is ko, else original. */
export function localizeFinding(f) {
  const out = { title: f.title, description: f.description, reproduction: f.reproduction };
  if (getLang() !== "ko") return out;
  const byId = BY_ID[f.finding_id];
  out.title = (byId && byId.title) || apply(TITLE, f.title);
  out.description = (byId && byId.description) || apply(DESC, f.description);
  out.reproduction = apply(REPRO, f.reproduction);
  // Static semgrep findings carry the rule id as their title — translate the
  // description from the ruleset map (title stays the id, like a CVE).
  if (/^mcp-r\d/i.test(f.title || "")) {
    out.description = ruleDesc(f.title, out.description);
  }
  return out;
}
