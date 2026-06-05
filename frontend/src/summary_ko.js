// summary_ko.js — natural-language Korean report summary.
//
// Instead of restating counts, this looks at the actual findings: it clusters
// them (by static rule / dynamic behaviour), describes the dominant cluster
// with specifics (what the code does, which files / tools, how many), frames the
// severity, and gives a concrete next step. Reads like an analyst's note.
import { MINOS_DATA } from "./data.js";

const VERDICT = {
  REJECT: "배포 부적합(REJECT)", CONDITIONAL: "조건부 통과(CONDITIONAL)",
  APPROVE: "통과(APPROVE)", UNSCANNED: "미스캔",
};

// What the code/finding actually does — noun-modifier phrase ("…하는").
const STATIC_NARR = {
  "mcp-r1-env-secret-access": "환경변수에서 토큰·API 키 같은 비밀값을 읽는",
  "mcp-r1-env-secret-access-node": "process.env에서 토큰·API 키 같은 비밀값을 읽는",
  "mcp-r1-broad-file-read": "시스템 루트부터 광범위하게 파일을 읽는",
  "mcp-r2-python-command-exec": "OS 명령을 직접 실행하는",
  "mcp-r2-node-command-exec": "child_process로 외부 명령을 실행하는",
  "mcp-r2-python-dynamic-eval": "문자열을 동적으로 eval/exec 하는",
  "mcp-r2-node-dynamic-eval": "값을 eval / new Function으로 실행하는",
  "mcp-r2-runtime-package-install": "런타임에 패키지를 설치하는",
  "mcp-r4-sandbox-detection-python": "샌드박스·CI 환경을 감지해 동작을 바꾸는",
  "mcp-r4-sandbox-detection-node": "샌드박스·CI 환경을 감지해 동작을 바꾸는",
  "mcp-r4-time-conditional-python": "현재 시간에 따라 분기하는",
  "mcp-r4-time-conditional-node": "현재 시간에 따라 분기하는",
  "mcp-r5-python-sql-fstring": "문자열로 SQL을 조립해 실행하는",
  "mcp-r5-python-path-traversal": "정규화 없이 경로를 열어 접근하는",
  "mcp-r5-node-path-traversal": "정규화 없이 경로로 파일에 접근하는",
  "mcp-r5-node-shell-interpolation": "문자열 보간으로 셸 명령을 만드는",
  "mcp-r5-python-command-injection-taint": "도구 입력을 정제 없이 셸로 넘기는",
  "mcp-r5-python-path-traversal-taint": "도구 입력을 정제 없이 파일 경로로 쓰는",
  "mcp-r5-python-sql-injection-taint": "도구 입력을 정제 없이 SQL로 넘기는",
  "mcp-r5-node-command-injection-taint": "도구 입력을 정제 없이 명령으로 넘기는",
  "mcp-r5-node-path-traversal-taint": "도구 입력을 정제 없이 파일 경로로 쓰는",
  "mcp-r6-python-http-no-timeout": "타임아웃 없이 외부 HTTP를 호출하는",
  "mcp-r6-python-unbounded-read": "크기 제한 없이 파일 전체를 읽는",
};
const NARR_BY_RISK = {
  R1: "민감한 데이터에 접근하는", R2: "코드·명령을 실행하는", R3: "에이전트를 조종할 수 있는",
  R4: "환경·시간에 따라 동작을 바꾸는", R5: "입력을 검증 없이 위험한 지점으로 넘기는", R6: "자원을 무제한으로 쓰는",
};
const ACTION_BY_RISK = {
  R1: "이 비밀값들이 실제로 외부로 빠져나가지 않는지 확인",
  R2: "도구 입력을 실행 지점에 닿기 전에 정제",
  R3: "도구 설명·출력에서 신뢰할 수 없는 지시를 제거",
  R4: "환경·시간에 따른 분기를 제거",
  R5: "모든 도구 입력을 검증·제한",
  R6: "크래시·행이 나는 핸들러를 보강하고 타임아웃을 적용",
};

const sevWorst = (items) => MINOS_DATA.SEVERITY_ORDER.find((s) => items.some((f) => f.severity === s));
const isStatic = (f) => (f.phase || "dynamic") === "static";

function fmtList(arr, max = 2) {
  const u = [...new Set(arr)];
  const head = u.slice(0, max).join(", ");
  const more = u.length - Math.min(max, u.length);
  return more > 0 ? `${head} 외 ${more}곳` : head;
}
function toolsOf(items) {
  const set = new Set();
  for (const f of items) {
    if (f.tool_name) set.add(f.tool_name);
    else { const m = (f.title || "").match(/tool '([^']+)'/); if (m) set.add(m[1]); }
  }
  return [...set];
}

// Cluster key: static rules group by rule id; dynamic findings by behaviour.
function clusterKey(f) {
  if (isStatic(f)) return "S:" + (f.title || f.risk_type);
  const t = (f.title || "").toLowerCase();
  if (/crash/.test(t)) return "D:crash";
  if (/timeout|stall|hang/.test(t)) return "D:timeout";
  if (/-32603|internal error/.test(t)) return "D:errorcode";
  return "D:" + (f.risk_type || "other");
}

function clusterSentence(items) {
  const f0 = items[0];
  const n = items.length;
  if (isStatic(f0)) {
    const narr = STATIC_NARR[f0.title] || NARR_BY_RISK[f0.risk_type] || "보안상 주의가 필요한";
    const locs = items.map((x) => x.location).filter(Boolean);
    const where = locs.length ? `(${fmtList(locs, 2)})` : "";
    return `정적 분석이 ${narr} 코드 ${n}곳을 짚었습니다${where}.`;
  }
  const tools = toolsOf(items);
  const who = tools.length ? `${fmtList(tools, 2)} 도구` : "일부 도구";
  const t = (f0.title || "").toLowerCase();
  if (/crash/.test(t)) return `샌드박스 퍼징 중 ${who}가 비정상 입력에 서버 프로세스를 중단시키는 경우가 ${n}건 확인됐습니다.`;
  if (/timeout|stall|hang/.test(t)) return `${who}가 특정 입력에서 응답 없이 멈추는 경우가 ${n}건 확인됐습니다.`;
  if (/-32603|internal error/.test(t)) return "잘못된 입력 대부분에 서버가 표준과 다른 오류 코드(-32603)로 응답하며 스택 트레이스를 노출합니다.";
  const rn = (MINOS_DATA.RISK_META[f0.risk_type] || {}).name || f0.risk_type;
  return `동적 분석에서 ${rn} 관련 발견이 ${n}건 확인됐습니다.`;
}

export function koSummary(server, verdict, score, findings, scores, toolsTested) {
  const n = findings.length;
  const fixed = (score || 0).toFixed(2);
  const V = VERDICT[verdict] || "스캔 완료";
  const statics = findings.filter(isStatic);
  const dynamics = findings.filter((f) => !isStatic(f));
  const phaseWord = statics.length && dynamics.length ? "정적·동적 분석"
    : statics.length ? "정적 분석" : "동적 분석";

  if (n === 0) {
    return `${server} 서버는 ${phaseWord} 결과 ${V} 판정을 받았습니다(위험 점수 ${fixed} / 1.00). 여섯 가지 위험 유형(R1–R6) 어디에서도 걸린 항목이 없어, 현재로서는 배포를 막을 신호가 없습니다. 버전을 올릴 때마다 다시 스캔하기를 권합니다.`;
  }

  // Cluster, then rank by worst severity → size.
  const groups = new Map();
  for (const f of findings) {
    const k = clusterKey(f);
    (groups.get(k) || groups.set(k, []).get(k)).push(f);
  }
  const clusters = [...groups.values()].sort((a, b) => {
    const sa = MINOS_DATA.SEVERITY_ORDER.indexOf(sevWorst(a));
    const sb = MINOS_DATA.SEVERITY_ORDER.indexOf(sevWorst(b));
    return sa !== sb ? sa - sb : b.length - a.length;
  });
  const top = clusters[0];
  const worst = top[0].risk_type;

  // S1 — verdict.
  const s1 = `${server} 서버는 ${phaseWord} 결과 ${V} 판정을 받았습니다(위험 점수 ${fixed} / 1.00).`;

  // S2 — what was actually found (top one or two clusters).
  let s2 = clusterSentence(top);
  if (clusters[1] && clusters.length === 2) s2 += " " + clusterSentence(clusters[1]);
  else if (clusters.length > 2) s2 += ` 그 밖에 다른 유형의 발견도 ${clusters.length - 1}종 있습니다.`;

  // S3 — severity framing.
  const hasCrit = findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
  const allLow = findings.every((f) => f.severity === "LOW" || f.severity === "INFO");
  const isEnvSecret = (top[0].title || "").startsWith("mcp-r1-env-secret");
  let s3;
  if (hasCrit && /crash/.test((top[0].title || "").toLowerCase())) {
    s3 = "잘못된 요청 한 번으로 서버가 멈출 수 있어, 서비스 안정성(R6) 측면에서 DoS로 악용될 여지가 있습니다.";
  } else if (hasCrit) {
    s3 = "도구 입력만으로 도달할 수 있어 실제 악용으로 이어질 위험이 있습니다.";
  } else if (allLow && isEnvSecret) {
    s3 = "심각도는 모두 낮은 정보성 신호입니다. 대부분의 서버에서 정상적인 동작이며, 유출 스캐너가 상관 분석할 수 있도록 표시된 것입니다.";
  } else if (allLow) {
    s3 = "심각도는 모두 낮은 편으로, 당장 배포를 막을 수준은 아닙니다.";
  } else {
    s3 = "심각한 문제는 아니지만 중간 수준의 신호가 남아 있어 주의가 필요합니다.";
  }

  // S4 — action.
  const act = ACTION_BY_RISK[worst] || "표시된 지점을 점검";
  let s4;
  if (verdict === "REJECT") s4 = `배포 전에 ${act}한 뒤 다시 스캔해 깨끗한지 확인하세요.`;
  else if (verdict === "APPROVE") s4 = "배포를 막을 문제는 없으니, 버전을 올릴 때마다 계속 스캔하세요.";
  else if (allLow) s4 = `다만 ${act}하는 것은 권합니다.`;
  else s4 = `${act}한 뒤 배포하고, 해결되면 다시 스캔하세요.`;

  return `${s1} ${s2} ${s3} ${s4}`;
}
