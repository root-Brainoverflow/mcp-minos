// ruleset_ko.js — Korean labels for the (fixed) static ruleset + risk taxonomy.
//
// The ruleset is stable bundled content, so we localize it by id/code on the
// client. Each helper returns Korean when the language is ko, otherwise the
// English fallback passed in (the original backend text).
import { getLang } from "./i18n.js";

const RISK_NAME = {
  R1: "데이터 접근", R2: "코드 실행", R3: "LLM 조작",
  R4: "동작 변화", R5: "입력 검증", R6: "서비스 안정성",
};
const RISK_FULL = {
  R1: "무단 데이터 접근 / 유출",
  R2: "무단 코드 / 명령 실행",
  R3: "LLM 동작 조작",
  R4: "동작 불일치 / 기만",
  R5: "입력 처리 취약점",
  R6: "서비스 안정성 위협",
};
const SCANNER = {
  code_patterns: { name: "Semgrep 패턴", desc: "추출된 소스에 R1–R6 패턴 팩과 테인트 분석을 실행합니다." },
  manifest_security: { name: "매니페스트 보안", desc: "매니페스트의 미고정 의존성·설치 스크립트·비밀값 인자를 점검합니다." },
  schema_audit: { name: "스키마 점검", desc: "도구 입력 스키마의 제약 없는 문자열과 과도한 기본값을 검사합니다." },
  descriptions: { name: "설명 점검", desc: "도구 설명의 프롬프트 인젝션 문구와 과장된 기능 주장을 살핍니다." },
  metadata_divergence: { name: "메타데이터 불일치", desc: "선언된 도구 메타데이터와 소스 시그니처의 불일치를 찾습니다." },
};
const PACK_SUMMARY = {
  "r1-data-access.yaml": "비밀번호성 환경변수 읽기와 광범위한 파일시스템 탐색 — 유출 신호와 연관됩니다.",
  "r2-dangerous-exec.yaml": "직접 명령 실행, 동적 eval, 런타임 패키지 설치.",
  "r4-env-conditional.yaml": "안티 샌드박스 기만과 시간 기반 로직 폭탄.",
  "r5-input-validation.yaml": "보간·연결한 문자열로 만든 인젝션성 싱크.",
  "r5-taint.yaml": "테인트 모드: 도구 핸들러 입력이 정제 없이 위험한 싱크로 흘러가는 경우.",
  "r6-stability.yaml": "가용성 위험 — 제한 없는 읽기와 타임아웃 없는 네트워크 호출.",
};
const RULE = {
  "mcp-r1-env-secret-access": "비밀번호성 환경변수(secret/token/api_key/password)를 읽습니다.",
  "mcp-r1-env-secret-access-node": "process.env의 비밀번호성 속성을 읽습니다.",
  "mcp-r1-broad-file-read": "시스템 루트에서 시작하는 광범위한 파일시스템 탐색(os.walk('/'), glob '/**').",
  "mcp-r2-python-command-exec": "os.system / subprocess.* 프로세스 실행.",
  "mcp-r2-node-command-exec": "child_process exec / spawn 실행.",
  "mcp-r2-python-dynamic-eval": "리터럴이 아닌 표현식의 eval/exec.",
  "mcp-r2-node-dynamic-eval": "계산된 값의 eval / new Function.",
  "mcp-r2-runtime-package-install": "서버 코드에서 런타임에 pip/npm/pnpm/yarn 설치.",
  "mcp-r4-sandbox-detection-python": "샌드박스/CI/디버그/컨테이너 환경변수로 분기합니다.",
  "mcp-r4-sandbox-detection-node": "샌드박스/CI/디버그 환경변수를 읽어 동작을 바꿉니다.",
  "mcp-r4-time-conditional-python": "현재 날짜/시간으로 분기합니다(로직 폭탄 가능).",
  "mcp-r4-time-conditional-node": "Date.now()로 분기해 지연된 페이로드를 작동시킵니다.",
  "mcp-r5-python-sql-fstring": "f-string/문자열 연결로 SQL을 실행합니다.",
  "mcp-r5-python-path-traversal": "정규화 없이 보간된 경로로 open()을 호출합니다.",
  "mcp-r5-node-path-traversal": "보간된 경로로 fs 읽기/쓰기를 합니다.",
  "mcp-r5-node-shell-interpolation": "템플릿 문자열로 셸 명령을 만듭니다.",
  "mcp-r5-python-command-injection-taint": "도구 입력 → 셸 실행 (정제: shlex.quote/split).",
  "mcp-r5-python-path-traversal-taint": "도구 입력 → fs 경로 (정제: realpath/resolve).",
  "mcp-r5-python-sql-injection-taint": "도구 입력 → SQL 실행 문자열.",
  "mcp-r5-node-command-injection-taint": "핸들러 입력 → child_process 명령 문자열.",
  "mcp-r5-node-path-traversal-taint": "핸들러 입력 → fs.* 경로 (정제: path.normalize/resolve).",
  "mcp-r6-python-http-no-timeout": "타임아웃 없는 requests.* 호출.",
  "mcp-r6-python-unbounded-read": "크기 제한 없이 파일 전체를 메모리로 읽습니다.",
};
const CONF = { low: "낮음", medium: "중간", med: "중간", high: "높음" };

const isKo = () => getLang() === "ko";

export const riskName = (code, fallback) => (isKo() ? (RISK_NAME[code] || fallback || code) : (fallback || code));
export const riskFull = (code, fallback) => (isKo() ? (RISK_FULL[code] || fallback || "") : (fallback || ""));
export const scannerName = (id, fallback) => (isKo() ? (SCANNER[id]?.name || fallback) : fallback);
export const scannerDesc = (id, fallback) => (isKo() ? (SCANNER[id]?.desc || fallback) : fallback);
export const packSummary = (file, fallback) => (isKo() ? (PACK_SUMMARY[file] || fallback) : fallback);
export const ruleDesc = (id, fallback) => (isKo() ? (RULE[id] || fallback) : fallback);
export const confLabel = (c) => (isKo() ? (CONF[c] || c) : c);
