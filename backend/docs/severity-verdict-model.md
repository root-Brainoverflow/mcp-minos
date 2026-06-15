# 심각도 산정 로직 (Severity Scoring & Verdict)

> **상태: 구현됨 (v1).** `Finding`/`StaticFinding`에 `kind`/`impact`/`evidence` 필드가 추가됐고,
> [output/policy.py](../src/mcp_security_analyzer/dynamic/output/policy.py)(카탈로그) ·
> [output/confidence.py](../src/mcp_security_analyzer/dynamic/output/confidence.py) ·
> [output/verdict.py](../src/mcp_security_analyzer/dynamic/output/verdict.py)가 구현됐으며, 모든 스캐너
> (동적 7 + 정적 5)가 `kind`를 태깅한다. `verdict.evaluate()`가 orchestrator/CLI에 배선되어 REJECT/PASS/ERROR를 산출한다.
> 테스트: `tests/test_verdict_model.py`(코어) + `tests/test_scan_demo.py`(실제 스캐너 end-to-end).
> **상태 갱신:** §8.3 메모리손상 크래시 분류는 **구현됨** — `verdict.is_memory_corruption_signal()`이 크래시 프로세스의
> 음수 returncode(=-signum, SIGSEGV/SIGABRT/SIGBUS)로 식별하고 orchestrator `_collect`가 이를 모아 `evaluate(..., memory_corruption_crash=…)`로 넘긴다.
> §4.4 비가시 유니코드 2분할도 **구현됨**(`descriptions._find_invisible` → `r3.invisible_unicode_bidi`/`r3.invisible_unicode_zw`).
> **미완:** 레거시 [scorer.py](../src/mcp_security_analyzer/dynamic/output/scorer.py)(per-risk 점수 표)는 표시용으로 병존 중이다.

이 문서는 `mcp-security-analyzer`가 하나의 finding에 **심각도(severity)** 를 부여하고,
finding 집합으로부터 서버 단위 **최종 판정(verdict)** 을 도출하는 로직을 절차 단위로 기술한다.

---

## 1. 산정 파이프라인 개요

심각도는 **두 개의 독립 축**으로 결정된다.

```
Finding  (스캐너가 1건씩 생성)
  │
  ├─ Impact 분류      (피해 크기 · CIA · §3)
  ├─ Evidence 분류    (관찰 직접성 · §4)
  │     └─▶ 두 축을 룩업표에 넣어  Severity = LUT(Impact, Evidence)   (§5)
  │
  ├─ Confidence 산정  (탐지 정밀도 · §6)   ─▶  표시 전용 (판정에 안 씀)
  │
  └─ Coverage 확인    (검사 유효성 · §8.4)
        ├─ 검사 불가  ─▶  ERROR(검사 불가) 반환     (위험 판정 안 함)
        └─ 검사 가능  ─▶  Verdict = REJECT / PASS   (§8 · Severity로 결정)
```

- **Impact** — "현실화되면 얼마나 나쁜가" (CIA: 기밀성/무결성/가용성).
- **Evidence** — "이 finding이 얼마나 직접적으로 관찰되었는가" (런타임 실측 ↔ 정적 추정).
- 이 둘의 **2차원 룩업**으로 severity가 결정된다. 가중합·정규화·임계값 같은 연속 산술은 쓰지 않는다.
- **Confidence** 는 별도로 계산되어 **표시(설명)에만** 쓰이고, severity·verdict 산정에는 들어가지 않는다.
- **Coverage** (검사가 유효했는지)는 위험 판정과 별개 축이다 — 검사를 아예 못 한 서버는 PASS/REJECT를 내지 않고 **ERROR(검사 불가)** 를 반환한다(§8.4).

핵심 원칙: **심각도는 계산값이 아니라 `(Impact, Evidence)` 좌표에 대한 결정론적 룩업이다.**
같은 좌표는 R-type과 무관하게 항상 같은 severity를 낸다.

> **용어 미리보기:** R1–R6은 위험 유형(§9에서 열거) · *corroboration*(증거 보강, §7) · *kind*(finding 종류 식별자, §2).

---

## 2. 입력 — Finding

각 finding은 스캐너가 생성하는 **단위 레코드**다(의심 행위/신호 1건당 1개). 산정에 직접 쓰이는 핵심 필드는 아래 요약과 같고,
**전체 필드·타입·설정 주체·생애주기·예시는 §2.1–§2.4** 에서 자세히 다룬다
([models.py](../src/mcp_security_analyzer/dynamic/models.py)의 `Finding` + 신규 필드 `kind`/`impact`/`evidence`).


| 필드                  | 용도                                                             |
| ------------------- | -------------------------------------------------------------- |
| `risk_type` (R1–R6) | 집계·표시 키                                                        |
| `kind`              | finding 종류 식별자(머신 ID, 예: `r6.server_crash`) — 정책 카탈로그(§9) 룩업 키 |
| `impact`            | §3에서 부여되는 CIA 영향 등급                                            |
| `evidence`          | §4에서 부여되는 증거 등급                                                |
| `severity`          | §5에서 **파생**되는 값(직접 입력하지 않음)                                    |
| `confidence`        | §6에서 부여되는 표시용 정밀도                                              |
| `related_events`    | Evidence 분류·그룹화의 근거 이벤트                                        |
| `tool_name`         | tool 단위 그룹화/표시                                                 |


`kind`만 정해지면 카탈로그(§9)가 `(impact, evidence)`의 기본값을 주고, 런타임 관찰이 그 `evidence`를
확정(REALIZED)한다. `severity`는 항상 §5의 함수로 계산한다.
**카탈로그에 없는 `kind`** 는 fail-closed 기본값(`impact=LIMITED, evidence=POTENTIAL`)으로 두고 검토 대상으로 표시한다(§8.5).

### 2.1 필드 전체 — 누가/언제 채우나

Finding은 스캐너가 만들지만, **분류 좌표와 severity는 파이프라인이 채운다.** 필드는 역할로 셋으로 나뉜다.

**(A) 스캐너가 채우는 식별·증거·표시 메타데이터**


| 필드                                       | 타입                          | 설정    | 설명                                                                                                      |
| ---------------------------------------- | --------------------------- | ----- | ------------------------------------------------------------------------------------------------------- |
| `finding_id`                             | `str` `fnd-<uuid>`          | 자동    | 고유 ID. 리포트·이벤트 상호참조                                                                                     |
| `risk_type`                              | enum `R1`–`R6`              | 스캐너   | 위험 버킷(집계·표시)                                                                                            |
| `kind`                                   | `str` `<scanner>.<finding>` | 스캐너   | **카탈로그(§9) 룩업 키**. 예: `r1.sensitive_read`, `static.malicious_package`, `chain.readonly_mismatch` *(신규)* |
| `tool_name`                              | `str                        | None` | 스캐너                                                                                                     |
| `title` / `description` / `reproduction` | `str`                       | 스캐너   | 사람용 제목·상세·재현 방법                                                                                         |
| `related_events`                         | `list[str]` `evt-<uuid>`    | 스캐너   | **근거 이벤트 ID 목록**. evidence 확정(§4.2)과 표시 그룹화의 입력                                                         |
| `detected_at`                            | `datetime`                  | 자동    | 탐지 시각(UTC)                                                                                              |


**(B) `kind`에서 카탈로그가 부여 + 런타임 확정되는 분류 좌표** *(둘 다 신규)*


| 필드         | 타입                                                    | 설정               | 설명                                                                         |
| ---------- | ----------------------------------------------------- | ---------------- | -------------------------------------------------------------------------- |
| `impact`   | enum `TAKEOVER`/`PARTIAL_CI`/`AVAILABILITY`/`LIMITED` | 카탈로그(`kind`)     | 피해 크기(§3). 작성 시점에 `kind`별로 1회 배정됨                                          |
| `evidence` | enum `REALIZED`/`DETERMINISTIC`/`POTENTIAL`           | 카탈로그 기본 + 런타임 확정 | 증거 직접성(§4). 카탈로그가 기본값을 주고, `related_events`에 실측 이벤트가 있으면 `REALIZED`로 확정/승격 |


**(C) 파이프라인이 계산하는 파생값**


| 필드           | 타입                                    | 설정  | 설명                                              |
| ------------ | ------------------------------------- | --- | ----------------------------------------------- |
| `severity`   | enum `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` | 파생  | `LUT(impact, evidence)`(§5). **스캐너가 직접 넣지 않는다** |
| `confidence` | `float` `[0,1]`                       | 파생  | 탐지 방법별 정밀도(§6). **표시 전용**(판정 비관여)               |


### 2.2 필드 생애주기 (한 finding이 채워지는 순서)

```
1) 스캐너        : 의심 1건 → Finding 생성, (A) 채움 (kind·risk_type·related_events·tool_name·title…)
2) policy.py     : kind 로 카탈로그(§9) 조회 → impact, evidence 기본값 부여
3) evidence 확정 : related_events 에 실측 이벤트(§4.2) 있으면 evidence=REALIZED 로 확정/승격
                   (없으면 카탈로그 기본값 POTENTIAL/DETERMINISTIC 유지)
4) confidence.py : 탐지 방법(이벤트 소스)으로 confidence 부여 (표시용)
5) verdict.py    : severity = LUT(impact, evidence) 계산 (§5)
6) verdict.py    : 전체 finding 풀에 §8 규칙 적용 → 서버 verdict
```

> **핵심:** 스캐너는 `kind`만 정확히 달면 되고, `impact`/`evidence`/`severity`/`confidence`는 전부 결정론적으로 채워진다.
> 스캐너마다 severity를 손으로 매겨 생기던 불일치(현재 코드)가 사라진다.

### 2.3 구체 예시 (vulnerable 서버의 민감 경로 read)

```jsonc
{
  // ── 스캐너가 채움 (A) ──
  "finding_id": "fnd-1a2b3c…",
  "risk_type": "R1",
  "kind": "r1.sensitive_read",
  "tool_name": "read_file",
  "title": "Sensitive path read: /etc/shadow",
  "description": "read_file 가 경로 검증 없이 /etc/shadow 를 반환함",
  "reproduction": "call read_file with path=/etc/shadow",
  "related_events": ["evt-9f…"],   // file_read 실측 이벤트 → evidence 확정 근거
  "detected_at": "2026-06-04T12:00:00Z",

  // ── 파이프라인이 채움 (B)(C) ──
  "impact":     "PARTIAL_CI",      // (B) 카탈로그[r1.sensitive_read]
  "evidence":   "REALIZED",        // (B) related_events 에 file_read 있음 → 확정
  "confidence": 0.85,              // (C) syscall 관찰 (표시용)
  "severity":   "HIGH"             // (C) LUT(PARTIAL_CI, REALIZED)
}
// → §8.1 적용: (PARTIAL_CI ∧ REALIZED) 성립 → 서버 verdict = REJECT (사유 data-access)
```

### 2.4 모델 필드 현황 (models.py)

현재 `Finding`([models.py:108-129](../src/mcp_security_analyzer/dynamic/models.py#L108-L129))은
`finding_id, risk_type, severity, confidence, title, description, related_events, tool_name, reproduction, detected_at`에
더해 분류 좌표 필드 `kind`, `impact`, `evidence`를 **이미 갖는다**(셋 다 `| None` 옵션). 의미 정리:

- **분류 필드 3개**: `kind`, `impact`, `evidence` — `Impact`/`Evidence` enum도 models.py에 정의됨.
- `**severity` 의미**: `impact`/`evidence`가 채워지면 verdict 엔진이 스캐너가 넣은 `severity`를 무시하고 §5 LUT로 재계산한다.
- `**confidence` 의미**: 판정 입력이 아니라 **표시 전용**(§6).

마이그레이션 범위(스캐너 12개 + correlation 엔진)는 §11 참조.

---

## 3. Impact 분류 (CIA 기반)

finding이 **현실화될 때의 최악 영향**을 CIA로 평가하여 4등급 중 하나로 매핑한다.
CIA 어휘·등급 앵커는 CVSS v4.0을 **정성 기준**으로 차용한다(수치 vector→score 공식은 쓰지 않음).

### 3.1 등급 정의


| Impact         | 정의 (판정 기준)                                                     | CIA             |
| -------------- | -------------------------------------------------------------- | --------------- |
| `TAKEOVER`     | 단일 finding으로 호스트 장악 — 임의 코드/명령 실행, 임의 파일 read+write, 시크릿 외부 반출 | C:High + I:High |
| `PARTIAL_CI`   | 부분적 기밀(C) 또는 무결성(I) 침해 — 범위 제한 또는 추가 조건 필요                     | C 또는 I 부분       |
| `AVAILABILITY` | 프로세스가 **중단**됨 — 크래시/OOM 등. 로컬·재시작 가능, C/I 무관                   | A:High          |
| `LIMITED`      | C/I/A 모두 경미 — 성능 저하, 정보 단편 노출, 메타데이터 신호 등 참고 수준                | 미미              |


> `AVAILABILITY`(프로세스 다운)와 `LIMITED`의 가용성 신호(예: 지연·높은 에러율 — 서버는 살아있음)를 구분한다.
> 후자는 `LIMITED`로 둔다.

### 3.2 분류 결정 절차 (작성 시점의 1회 기준)

> 이 절차는 §9 카탈로그에 각 `kind`의 `impact`를 **배정할 때 1회** 적용하는 기준이다.
> **런타임에는 스캐너가 이 절차를 재실행하지 않는다** — impact는 `kind`로 카탈로그에서 읽는다(§2).

finding이 노출/허용하는 **능력(capability)** 을 기준으로 상위 우선 순으로 판정한다.

1. **임의 실행·임의 read+write·시크릿 반출이 가능한가?** → `TAKEOVER`
  (shell/인터프리터 실행, command injection→exec, RCE, path traversal 임의 파일 접근, SSRF 내부 도달, 시크릿 외부 전송)
2. **특정 기밀 데이터 read 또는 무결성/행위 조작에 그치는가?** → `PARTIAL_CI`
  (지정 민감 파일 read, 툴 응답 인젝션, rug-pull, 숨은 툴 유도)
3. **프로세스가 중단되는가?** → `AVAILABILITY`
  (크래시, OOM, stack overflow)
4. **위 어느 것도 아니고 경미한가?** → `LIMITED`
  (verbose 에러 누출, 지연/높은 에러율, 과허용 스키마, 메타데이터 차이, capability 선언 불일치)

> **런타임 승격 규칙(별도):** §3.2 절차로 `PARTIAL_CI`로 분류된 무결성 조작(인젝션 등)이, 런타임에서
> 임의 실행으로 이어지는 것이 관찰되면(예: `process_exec` 이벤트 동반) 그 finding의 `impact`는 `TAKEOVER`가 된다.

---

## 4. Evidence 분류 (관찰 직접성)

finding이 **얼마나 직접적으로 확인되었는가**를 3등급으로 매핑한다. severity와 verdict를 실제로 가르는 축이다.

### 4.1 등급 정의


| Evidence        | 정의                            | 판정 근거                      |
| --------------- | ----------------------------- | -------------------------- |
| `REALIZED`      | 런타임에서 **실제 행위로 관찰**됨          | §4.2의 실측 이벤트               |
| `DETERMINISTIC` | 정적이지만 **양성 오탐률 ≈ 0** 인 결정적 지표 | §4.3의 한정 목록                |
| `POTENTIAL`     | 단독 **정적·휴리스틱** 신호 — 행위 미확인    | 그 외 모든 정적/텍스트/스키마/메타데이터 신호 |


> severity 계산(§5)에서 `REALIZED`와 `DETERMINISTIC`는 "강한 증거"로 동급 취급한다.
> verdict(§8)에서도 둘 다 차단 자격을 가진다(§8.1).

### 4.2 REALIZED 판정 — 이벤트 소스 기준

finding의 `related_events` 소스가 **실제 동작 관찰**이면 `REALIZED`다.


| 관찰 종류                                        | 이벤트 타입                                                                   |
| -------------------------------------------- | ------------------------------------------------------------------------ |
| Honeypot/Canary 트랩 **발동**(런타임에 트랩이 실제로 건드려짐) | `honeypot_access`, `canary_detected`                                     |
| 시스템 콜 실측                                     | `process_exec`, `file_open` / `file_read` / `file_write`, `server_crash` |
| 네트워크 연결 실측                                   | network events                                                           |
| MCP 프로토콜 실측                                  | `mcp_response`, `sequence_timeout`                                       |
| 퍼징 응답에서 익스플로잇 성공 확인                          | `test_result`                                                            |


> Honeypot/Canary는 분석기가 **심어둔 트랩이 런타임에 발동된 것을 관찰**한 결과이므로(정적 신호가 아님)
> `REALIZED`다([honeypot.py](../src/mcp_security_analyzer/dynamic/infrastructure/honeypot.py),
> [r1_data_access.py:112-140](../src/mcp_security_analyzer/dynamic/scanners/r1_data_access.py#L112-L140)).

### 4.3 DETERMINISTIC 한정 목록

정적 신호 중 **우연히 양성에 맞을 이유가 사실상 없는** 3가지만 `REALIZED`와 동급으로 본다.

1. **알려진 악성 의존성** — 악성 패키지 denylist 적중
  ([manifest_security.py:196](../src/mcp_security_analyzer/static/scanners/manifest_security.py#L196)).
2. **인코딩 페이로드를 디코드+실행하는 install hook** (단순 base64 데이터는 제외).
3. **툴 description의 실행형 비가시 유니코드** — **bidi override / tag block** 문자.
  (단순 zero-width 1개는 i18n·이모지에 정상 출현 → §4.4로 `POTENTIAL` 강등)

### 4.4 비가시 유니코드 세부 규칙 (구현됨)

**배경:** MCP tool의 설명문(description)은 그대로 LLM 컨텍스트로 들어간다. 공격자는 사람 눈에는 안 보이지만 LLM은
읽는 **비가시 유니코드**에 악성 지시를 숨길 수 있다(R3 tool poisoning). 그런데 비가시 문자는 **오탐 위험이 정반대인 두 종류**다:

- **bidi override / tag block** (U+202A–E "Trojan Source", U+E0000–E007F 태그 은닉) — tool 설명문에 **정상적으로 쓸 이유가
사실상 없음** → 오탐 ≈ 0 → `DETERMINISTIC`(빼박 증거) → 단독 REJECT.
- **단순 zero-width 1개** (U+200B, U+200D 등) — **이모지(👨‍👩‍👧 ZWJ 시퀀스)·다국어 정렬·복붙**에 정상적으로 흔히 섞임
→ 오탐 큼 → `POTENTIAL`(의심) → 경고만.

둘 다 Impact는 `TAKEOVER`(숨은 지시가 먹히면 에이전트를 통해 임의 행동 유도)지만, **evidence가 갈려** 결과가 달라진다.

> **구현됨:** `_find_invisible`([descriptions.py:408-427](../src/mcp_security_analyzer/static/scanners/descriptions.py#L408-L427))이
> `(deterministic, zero_width)` 두 목록을 반환하고, 발화 시 deterministic 문자가 있으면 `kind=r3.invisible_unicode_bidi`(DETERMINISTIC),
> 없고 zero-width만이면 `kind=r3.invisible_unicode_zw`(POTENTIAL)로 태깅한다([descriptions.py:308](../src/mcp_security_analyzer/static/scanners/descriptions.py#L308)).
> bidi/tag/기타 format·control 문자(`Cf`/`Cc`)는 deterministic, `_ZW_CHARS`는 zero-width로 분류된다.
> (스캐너가 다는 `Severity.CRITICAL`은 표시용일 뿐 — verdict는 `kind`→카탈로그 `(impact, evidence)`로 재산출하므로 zw는 PASS+warn으로 떨어진다.)


| 패턴                              | Impact   | Evidence      |
| ------------------------------- | -------- | ------------- |
| bidi override / tag block (실행형) | TAKEOVER | DETERMINISTIC |
| 단순 zero-width 1개                | TAKEOVER | POTENTIAL     |


---

## 5. Severity 산정 함수

severity는 `(Impact, Evidence)`의 **전(全)함수**다. (LUT은 8칸 모두 채워진 총함수다.)

```
severity = SEVERITY_LUT[impact][evidence_is_strong]
  where evidence_is_strong = (evidence ∈ {REALIZED, DETERMINISTIC})
```


| Impact ＼ Evidence | `REALIZED` / `DETERMINISTIC` (강) | `POTENTIAL` (약) |
| ----------------- | -------------------------------- | --------------- |
| `TAKEOVER`        | **CRITICAL**                     | **HIGH**        |
| `PARTIAL_CI`      | **HIGH**                         | **MEDIUM**      |
| `AVAILABILITY`    | **HIGH (A)**                     | **MEDIUM**      |
| `LIMITED`         | **MEDIUM**                       | **LOW**         |


> **표기:** `HIGH (A)` = severity는 HIGH이고 영향축이 `AVAILABILITY`임을 나타내는 표시 태그. 별도 enum이 아니라
> `Severity.HIGH`에 매핑되며, `(A)`는 verdict가 차단하지 않음(§8.1)을 한눈에 보이기 위한 주석이다.
> LUT은 `CRITICAL/HIGH/MEDIUM/LOW`만 생성한다 — `INFO`는 본 모델에서 쓰지 않는다.

### 5.1 각 칸의 의미

- **TAKEOVER × 강 = CRITICAL** — 머신 장악이 실제로 가능함이 확인/결정적.
- **TAKEOVER × 약 = HIGH** — 장악 가능성을 정적으로만 시사(미확인). 단독으로는 차단하지 않음(§8.2).
- **PARTIAL_CI × 강 = HIGH** — 부분 C/I 침해가 실측/결정적으로 확인됨.
- **AVAILABILITY × 강 = HIGH(A)** — 크래시/DoS 실제 발생. severity는 높되 가용성 한정 → 차단 안 함.
- **LIMITED × 강 = MEDIUM** — 경미하나 실제 발생(예: verbose 에러, 지연).
- 약(POTENTIAL) 열은 한 등급 낮다 — 동일 영향이라도 "행위 미확인"이면 severity를 내린다.

### 5.2 파생 예시

- 퍼징 path traversal 성공 → (TAKEOVER, REALIZED) → **CRITICAL**.
- malformed 입력에 크래시 → (AVAILABILITY, REALIZED) → **HIGH(A)**.
- description "ignore previous instructions"만 발견 → (PARTIAL_CI, POTENTIAL) → **MEDIUM**.
- 악성 패키지 denylist 적중 → (TAKEOVER, DETERMINISTIC) → **CRITICAL**.

---

## 6. Confidence 산정 (표시 전용)

confidence는 **탐지기 정밀도 추정치** `P(참 | 탐지 발화)` 이며 **공격 가능성과 무관**하다.
severity·verdict에 들어가지 않고, "이 finding이 진짜일 확신도"로 **사용자 표시에만** 쓴다.
관찰이 직접적일수록 오탐이 낮다는 단조 순서를 인코딩한다.


| 탐지 방법             | 이벤트 타입(예)                                | Confidence |
| ----------------- | ---------------------------------------- | ---------- |
| Honeypot / Canary | `honeypot_access`, `canary_detected`     | 0.95       |
| Syscall 직접 관찰     | `process_exec`, `file`_*, `server_crash` | 0.85       |
| 네트워크 직접 관찰        | network events                           | 0.80       |
| MCP 프로토콜 관찰       | `mcp_response`, `sequence_timeout`       | 0.80       |
| 퍼징 응답 분석          | `test_result`                            | 0.70       |
| 툴 메타데이터 텍스트       | `ctx.tools`                              | 0.65       |
| 정적 소스 분석          | (정적 스캐너)                                 | 0.55       |


> 위 값은 방법별 **기준치(floor)** 다. 스캐너가 finding별로 더 세밀한 값을 이미 산정하면(예: R1 network는
> 목적지 등급별 0.70–0.95, R5 fuzz는 path/cmd 0.9·SSRF 0.85·SQL 0.75 등) 그 값을 표시에 유지하고,
> 방법별 기준치는 누락 시 fallback으로 쓴다. 어차피 판정에는 안 쓰이므로 표시 정책일 뿐이다.

---

## 7. Correlation / Grouping (표시 전용, 판정 비관여)

서로 다른 계층이 같은 위험을 가리키면 증거를 묶어 **보고서 가독성·신뢰 표현**을 높인다.
**판정에는 관여하지 않는다.**

- **판정에서 corroboration을 쓰지 않는 이유:** 정적 의심(`POTENTIAL`)이 실제로 위험하면, 동적 단계가 그것을
실측으로 확인하고 그때 생기는 **동적 finding 자체가 `REALIZED`로 독립 차단**한다(§8.1). 따라서 "정적+동적이
같은 위험을 가리키면 차단으로 승격"하는 별도 규칙은 verdict에 거의 기여하지 않으며, 오히려 위험하다 —
같은 `risk_type`이라는 이유만으로 무해한 실측 신호(예: SQL 에러 누출, LIMITED)가 미검증 정적 의심(예: taint, TAKEOVER)을
차단으로 끌어올리는 **과승격**이 생긴다.
- 따라서 evidence 승격은 **§3.2 런타임 규칙(같은 finding이 임의 실행으로 이어짐을 직접 관찰)**으로만 일어나고,
계층 간 "상관"은 표시용 그룹화에 한정한다.
- **구현 주의:** 기존 correlation 엔진의 쌍 매칭(`_overlaps`,
[engine.py:130-131](../src/mcp_security_analyzer/dynamic/correlation/engine.py#L130-L131))은 **공유 `related_events` ID**로
매칭하므로 정적↔동적 finding을 절대 묶지 못한다(정적 finding엔 런타임 이벤트가 없음). 표시용 그룹화가 필요하면
`(risk_type, tool_name)` 기준의 **새 매칭**을 써야 하며, [engine.py:144](../src/mcp_security_analyzer/dynamic/correlation/engine.py#L144)의
`+0.05` 가산은 **판정과 무관**하므로 verdict 경로에서 제거한다(표시 신뢰도로만 유지 가능).

---

## 8. Verdict 집계

위험 판정은 **이진(REJECT / PASS)** 이다. 단, **검사 자체가 불가능했던 경우**(서버를 못 띄움 등)는 위험을 판정하지
않고 **ERROR(검사 불가)** 를 반환한다(§8.4) — "검사를 못 한 것"은 위험 등급이 아니라 실행 오류이기 때문이다.
정적+동적 finding을 하나의 풀로 union하여 평가하며, 우선순위는 **REJECT > ERROR > PASS** 다.

### 8.1 차단(REJECT) 규칙

```
REJECT  ⇔  ∃ finding f:  f.impact ∈ {TAKEOVER, PARTIAL_CI}
                       ∧ f.evidence ∈ {REALIZED, DETERMINISTIC}
```

즉, **부분 이상의 C/I 침해(또는 머신 장악)가 강한 증거(실측 또는 결정적 정적)로 확인된** finding이 하나라도 있으면 차단.
REJECT는 최우선 — coverage가 부분적이어도 확정된 REJECT는 유지된다(§8.4).

### 8.2 단독으로 차단되지 않는 것 (→ PASS + 경고)

- `AVAILABILITY` **전부** — 크래시/OOM/timeout/에러율은 실측이어도 차단 트리거가 아니다(가용성, 로컬·재시작 가능).
단, **메모리 손상 의심 크래시는 §8.3 경고 플래그**(검사가 중단됐으면 §8.4 ERROR).
- **단독 `POTENTIAL`** — description 패턴, 과허용 스키마, 메타데이터 차이, 타이포스쿼팅, 이름 기반 semgrep,
단순 install hook, 정적 taint, 인코딩 페이로드 인라인 등. (동적으로 확인되면 그 동적 finding이 §8.1로 차단.)
- `LIMITED` **realized** — verbose 에러 누출, 지연 등(MEDIUM).

이들은 차단하지 않되 **warnings** 로 보존한다.

### 8.3 메모리 손상 의심 크래시 (경고 플래그)

`server_crash`가 **SIGSEGV / SIGABRT / SIGBUS**(메모리 안전 결함)로 발생하면 RCE로 이어질 수 있는 신호다.
깨끗한 예외/handled OOM과 구분하여 `potential-memory-corruption` **경고 플래그**를 달아 사람이 보게 한다.
식별은 크래시한 프로세스의 **음수 returncode(=-signum)**로 한다 — orchestrator `_collect`가 종료한 프로세스의 returncode가 음수면
`crash_signals`에 모으고, `verdict.is_memory_corruption_signal()`([verdict.py:134](../src/mcp_security_analyzer/dynamic/output/verdict.py#L134), `{6,7,10,11}` = SIGABRT/SIGBUS/SIGSEGV)로 판정해 `evaluate(..., memory_corruption_crash=…)`에 넘긴다. (Docker 경로에서는 returncode가 **컨테이너**의 것이라 내부 서버 시그널을 반영하지 못하므로 주로 `--no-docker`에서 동작한다.) 단독으로 REJECT하지는 않으며, 위험 판정은 §8.1대로
이진(REJECT/PASS)을 유지한다. 다만 그 크래시 때문에 **검사가 완료되지 못했다면** §8.4의 ERROR(검사 불가)가 된다.
정밀한 exploitable-crash 판별(ASAN 등)은 v2(§12).

### 8.4 검사 불가 (ERROR)

REJECT 조건(§8.1)이 성립하지 않으면서 **동적 검사가 의미 있는 커버리지를 확보하지 못한** 경우, 깨끗한 PASS를 내지 않고
**ERROR(검사 불가)** 를 반환한다. 위험 판정(REJECT/PASS)을 내리지 않고, **왜 검사를 못 했는지 진단 메시지**를 함께 돌려준다
— 실행/디버깅 과정에서 ERROR로 노출된다. ("침해 증거 없음"과 "안전하다는 증거"는 다르므로, 검사를 못 한 서버를 PASS로 읽지 않는다.)

트리거 — `coverage_ok = (툴 수 > 0) and scan_completed`:

- 서버가 부팅/handshake 전에 종료 (orchestrator가 예외를 던짐 → ERROR로 표면화),
- 노출 툴 0개,
- **시퀀스 완주 실패** — 회복 불가 크래시(재시작 한도 `_MAX_CRASH_RESTARTS` 초과) 또는 stdout EOF(`ConnectionError`)로
  검사가 중간에 끊김 (`scan_completed=False`),
- "coverage incomplete / 전제조건 미충족" 주의(caveat) finding 존재
  ([r6_stability.py:292](../src/mcp_security_analyzer/dynamic/scanners/r6_stability.py#L292)).

> **전역 timeout은 ERROR가 아니다(구현됨).** 툴을 enumerate한 뒤의 sandbox/sequence timeout은 "시간 예산까지
> 다 돌린 정상 종료"이지 검사 불가가 아니다 — 툴이 노출됐고 퍼징이 진행됐으며 그 안의 per-tool/sequence timeout은
> 각각 `r6.sequence_timeout` finding으로 보고된다. 따라서 `asyncio.TimeoutError` 핸들러는 `completed=True`로 두어
> **PASS + 안정성 경고**가 되게 한다([orchestrator.py](../src/mcp_security_analyzer/dynamic/orchestrator.py)). 툴을 하나도
> enumerate하기 전에 timeout 난 경우만 `len(tools)>0` 가드로 ERROR로 남는다. (느린 서버를 "검사 불가"로 오판하던 버그 수정 — sqlite 등.)

**외부 백엔드 필수 서버 → `error_code = needs_live_backend`:** 격리 샌드박스가 제공할 수 없는 라이브 백엔드
(쿠버네티스 클러스터 · Docker 소켓 · github/notion/tavily 등 토큰+인터넷)가 있어야만 툴이 노출되는 서버가 위 트리거로
커버리지가 비면, ERROR의 `error_code`를 `untestable` 대신 **`needs_live_backend`** 로 바꾸고 "무엇이 필요한지 +
`minos dynamic --no-docker`로 실환경에서 스캔하라"는 caveat 메시지를 단다
([orchestrator._external_backend_caveat](../src/mcp_security_analyzer/dynamic/orchestrator.py)). 스캐너 실패가 아니라
환경 부재임을 사용자에게 명확히 알리기 위함이다(raw ERROR/hang 금지).

#### 서버 크래시 — 경고냐 ERROR냐 (판별자 = 크래시가 아니라 커버리지)

`r6.server_crash`(AVAILABILITY)는 그 자체로 REJECT도 ERROR도 아니다. 갈림은 **크래시가 검사를 끊었는지**다.

| 상황 | `scan_completed` | 결과 |
|---|---|---|
| **회복된 크래시** — 서버 재시작 후 남은 시퀀스 완주 | True | AVAILABILITY **경고** (PASS+warn) |
| **전역 timeout** — 툴 enumerate 후 시간 예산 초과 (timeout 핸들러가 `completed=True`) | True | 안정성 **경고** (PASS+warn) |
| **회복 못한 크래시 / stdout EOF** — 재시작 한도 초과로 시퀀스 미완 | False | **ERROR**(검사 불가) |

`_collect`가 정상 완주에만 `scan_completed=True`를 반환하고 `run_analysis`가 이를 `coverage_ok`에 반영한다(구현됨).
**REJECT는 아니다** — 가용성 DoS를 차단하면 malformed 입력에 죽는 정상 서버 다수가 reject되어 변별력이 사라진다(§8.2). 다만
메모리손상 시그널(SIGSEGV/SIGABRT/SIGBUS)은 **이미 식별되어**(§8.3) `potential-memory-corruption` 경고 플래그가 붙는다(여전히 PASS — REJECT 승격은 v2, §12).

> 구 `scorer.py`가 'coverage incomplete'를 APPROVE→CONDITIONAL로 강등하던 의도([scorer.py:27-34,69](../src/mcp_security_analyzer/dynamic/output/scorer.py#L27-L34))를
> 계승하되, 본 모델에선 위험 등급이 아닌 **별도 ERROR**로 분리한다.

우선순위:

```
1. REJECT  if §8.1 성립 (coverage 무관, 최우선 — 부분 수집 중 확인된 침해는 유지)
2. ERROR   else if §8.4 트리거 (검사 불가)
3. PASS    otherwise  (+ warnings)
```

### 8.5 출력 구성

`Verdict { decision, reasons[], warnings[], max_residual_severity, coverage }`
(검사 불가 시에는 verdict 대신 `Error { code, message, diagnostics }` 를 반환 — `code` 는 일반 검사 불가면 `"untestable"`, 외부 백엔드(클러스터/소켓/토큰) 부재면 `"needs_live_backend"` (§8.4). 둘 다 decision=ERROR.)
> **영속화·노출(구현됨):** verdict는 출력될 뿐 아니라 저장된다. `exporter.export`가 `metadata.verdict`(decision 문자열 REJECT/PASS/ERROR), `metadata.verdict_detail`(reasons/warnings/coverage_ok/error 포함 전체 result), `metadata.legacy_verdict`(구 scorer의 APPROVE/CONDITIONAL/REJECT 문자열)를 함께 `findings.json`에 쓴다 — 더 이상 레거시 scorer가 verdict를 덮어쓰지 않는다. read-API(`api/store.read_session_detail`)는 `session.verdict_detail`로 이를 노출하고, **정적 단독 스캔**은 `_static_verdict()`가 같은 `verdict.evaluate(coverage_ok=True)`로 REJECT/PASS를 산출한다(정적은 항상 커버리지가 있어 ERROR는 안 남).

- **decision:** `REJECT` / `PASS` (검사 불가는 decision을 내지 않고 별도 ERROR 반환, §8.4)
- **REJECT 사유 분류** (우선순위순·상호배타): `known-malware`(DETERMINISTIC denylist/패키지 적중에 한정) → `machine-takeover`(그 외 TAKEOVER-강) → `data-access`(PARTIAL_CI, C) → `integrity-manipulation`(PARTIAL_CI, I)
- **warnings:** `availability/stability` · `static-only-suspicion` · `limited-info-leak` · `potential-memory-corruption` — 각 카테고리 건수 포함
- **max_residual_severity:** 차단되지 않은 finding 중 최고 severity(자동 게이트가 깨끗한 PASS와 경고 많은 PASS를 구분하도록)
- **표시:** R1–R6별 **최고 severity finding**을 막대로, 각 막대에 탐지 방법·confidence 부기.
- **fail-closed:** 카탈로그에 없는 `kind`는 `(LIMITED, POTENTIAL)`로 두고 `static-only-suspicion` 경고에 포함(검토 필요).

---

## 9. Finding 카탈로그 (정책 룩업 — 유지보수의 단일 소스)

각 `kind`에 `(Impact, Evidence)`를 배정하면 §5로 severity가, §8로 verdict가 **자동 도출**된다.
verdict 칸은 손으로 채우지 않고 규칙에서 생성한다.

### R1 — 데이터 접근


| kind id                               | 탐지       | Impact     | Evidence | Severity | Verdict |
| ------------------------------------- | -------- | ---------- | -------- | -------- | ------- |
| `r1.honeypot_access`                  | Honeypot | TAKEOVER   | REALIZED | CRITICAL | REJECT  |
| `r1.canary_leak`                      | Canary   | PARTIAL_CI | REALIZED | HIGH     | REJECT  |
| `r1.cloud_metadata`                   | 네트워크     | TAKEOVER   | REALIZED | CRITICAL | REJECT  |
| `r1.sensitive_read`                   | Syscall  | PARTIAL_CI | REALIZED | HIGH     | REJECT  |
| `r1.network_egress` (외부/내부망/메타데이터 버킷) | 네트워크     | PARTIAL_CI | REALIZED | HIGH     | REJECT  |


> SSRF는 R1 network(loopback/link-local/metadata 버킷)와 R5 fuzz 양쪽에서 발화할 수 있다
> ([r5:521](../src/mcp_security_analyzer/dynamic/scanners/r5_input_validation.py#L521), R1 network). 표시 시 중복 제거(dedup) 필요.
> 차단된 외부 연결(loopback 등)은 PARTIAL_CI보다 약하면 LIMITED로 강등 가능.
>
> **r1.sensitive_read 정제(구현됨):** syscall 민감-읽기 목록은 "어떤 MCP 서버도 열 이유 없는" 경로만 둔다 —
> SSH 개인키(`.ssh/id_rsa`/…) · `/etc/shadow` · `/proc/self/environ` · `.git-credentials` · `*.pem`. **클라이언트 config**
> (`.kube/config` · `.aws/credentials` · `.docker/config.json`)는 **제외**한다: 인프라 서버(k8s/aws/docker)가 자기 config를
> 시작 시 읽는 정상 동작을 false REJECT하던 문제(쿠버네티스 caveat까지 가렸음) 때문 — 실제 *내용* 유출은 honeypot
> canary가 잡는다. `.pem`은 확장자(경로 끝)로만 매칭해 `8549dc65.PemqE2`(node V8 컴파일 캐시) 같은 오탐을 막고,
> node-compile-cache/uv 빌드 경로는 런타임 노이즈로 스킵.

### R2 — 코드 실행


| kind id                                                         | 탐지      | Impact   | Evidence  | Severity | Verdict   |
| --------------------------------------------------------------- | ------- | -------- | --------- | -------- | --------- |
| `r2.shell_exec`                                                 | Syscall | TAKEOVER | REALIZED  | CRITICAL | REJECT    |
| `r2.installer_exec`                                             | Syscall | TAKEOVER | REALIZED  | CRITICAL | REJECT    |
| `r2.cmd_injection_exec`                                         | Syscall | TAKEOVER | REALIZED  | CRITICAL | REJECT    |
| `r2.rce_indicator`                                              | 퍼징      | TAKEOVER | REALIZED  | CRITICAL | REJECT    |
| `static.eval` / `static.runtime_install` / `static.secret_read` | semgrep | TAKEOVER | POTENTIAL | HIGH     | PASS+warn |


### R3 — LLM 조작


| kind id                                       | 탐지       | Impact     | Evidence      | Severity | Verdict   |
| --------------------------------------------- | -------- | ---------- | ------------- | -------- | --------- |
| `r3.invisible_unicode_bidi`                   | 메타데이터    | TAKEOVER   | DETERMINISTIC | CRITICAL | REJECT    |
| `r3.invisible_unicode_zw`                     | 메타데이터    | TAKEOVER   | POTENTIAL     | HIGH     | PASS+warn |
| `r3.response_injection`                       | MCP 프로토콜 | PARTIAL_CI | REALIZED      | HIGH     | REJECT    |
| `r3.resource_indirect_injection`              | MCP 프로토콜 | PARTIAL_CI | REALIZED      | HIGH     | REJECT    |
| `r3.resource_anomaly`                         | MCP 프로토콜 | LIMITED    | REALIZED      | MEDIUM   | PASS+warn |
| `static.tool_desc_suspicious` (역할 가로채기·숨은 지시) | 메타데이터    | PARTIAL_CI | POTENTIAL     | MEDIUM   | PASS+warn |


### R3 계열 — 체인 공격 ([chain_attack.py](../src/mcp_security_analyzer/dynamic/scanners/chain_attack.py))


| kind id                       | 탐지    | Impact     | Evidence  | Severity | Verdict   |
| ----------------------------- | ----- | ---------- | --------- | -------- | --------- |
| `chain.readonly_mismatch`     | 메타데이터 | PARTIAL_CI | POTENTIAL | MEDIUM   | PASS+warn |
| `chain.guided_chain` (A→B 유도) | 메타데이터 | PARTIAL_CI | POTENTIAL | MEDIUM   | PASS+warn |


> `chain.readonly_mismatch`는 현재 코드가 HIGH/0.85로 내지만, severity는 카탈로그 파생이므로 목표는 `LUT(PARTIAL_CI, POTENTIAL)=MEDIUM`으로 재산출한다(R4 `capability_mismatch`와 동일한 코드↔목표 정렬 케이스).

### R4 — 행동 불일치


| kind id                             | 탐지           | Impact     | Evidence  | Severity | Verdict   |
| ----------------------------------- | ------------ | ---------- | --------- | -------- | --------- |
| `r4.rug_pull` (tools/list 변경)       | MCP 프로토콜     | PARTIAL_CI | REALIZED  | HIGH     | REJECT    |
| `r4.env_tool_divergence`            | MCP 프로토콜     | PARTIAL_CI | REALIZED  | HIGH     | REJECT    |
| `r4.capability_mismatch` (file/net) | Syscall/네트워크 | LIMITED    | REALIZED  | MEDIUM   | PASS+warn |
| `static.env_time_branch`            | semgrep      | PARTIAL_CI | POTENTIAL | MEDIUM   | PASS+warn |


> `r4.capability_mismatch`는 "선언과 다른 행위"라는 **기만 신호**일 뿐, 그 자체가 침해는 아니다(실제 외부 유출이면
> R1 network가 PARTIAL_CI로 별도 차단). 따라서 LIMITED. (현재 코드는 MEDIUM/0.7 — 본 분류와 일치
> [r4_behavior_drift.py:143,156](../src/mcp_security_analyzer/dynamic/scanners/r4_behavior_drift.py#L143).)

### R5 — 입력 검증


| kind id                                     | 탐지      | Impact       | Evidence  | Severity | Verdict   |
| ------------------------------------------- | ------- | ------------ | --------- | -------- | --------- |
| `r5.path_traversal`                         | 퍼징      | TAKEOVER     | REALIZED  | CRITICAL | REJECT    |
| `r5.cmd_injection`                          | 퍼징      | TAKEOVER     | REALIZED  | CRITICAL | REJECT    |
| `r5.ssrf`                                   | 퍼징      | TAKEOVER     | REALIZED  | CRITICAL | REJECT    |
| `r5.nosql_exfil`                            | 퍼징      | TAKEOVER     | REALIZED  | CRITICAL | REJECT    |
| `r5.sql_error_leak` / `r5.nosql_error_leak` | 퍼징      | LIMITED      | REALIZED  | MEDIUM   | PASS+warn |
| `r5.type_confusion` (크래시 형태)                | 퍼징      | AVAILABILITY | REALIZED  | HIGH(A)  | PASS+warn |
| `static.taint_flow`                         | semgrep | TAKEOVER     | POTENTIAL | HIGH     | PASS+warn |


> `r5.type_confusion`이 크래시가 아니라 **데이터 노출/분기 변조**로 나타나면 PARTIAL_CI로 분류한다(관찰된 결과에 따름).

### R6 — 안정성 (모두 AVAILABILITY/LIMITED → 단독 차단 없음)


| kind id                                      | 탐지       | Impact       | Evidence | Severity | Verdict                                            |
| -------------------------------------------- | -------- | ------------ | -------- | -------- | -------------------------------------------------- |
| `r6.server_crash` (미처리)                      | Syscall  | AVAILABILITY | REALIZED | HIGH(A)  | PASS+warn (SIGSEGV류 §8.3 플래그 / 검사 중단 시 §8.4 ERROR) |
| `r6.oom` / `r6.stack_overflow` (미처리)         | 퍼징       | AVAILABILITY | REALIZED | HIGH(A)  | PASS+warn                                          |
| `r6.high_error_rate` / `r6.sequence_timeout` | MCP 프로토콜 | LIMITED      | REALIZED | MEDIUM   | PASS+warn                                          |
| `r6.error_info_leak` (-32603 + **실제 누출**: 스택/경로/타입예외) | MCP 프로토콜 | LIMITED      | REALIZED | MEDIUM   | PASS+warn                                          |
| `r6.error_code_misuse` (-32603, 누출 없음 → CWE-20만) | MCP 프로토콜 | LIMITED      | REALIZED | MEDIUM   | PASS+warn                                          |
| `r6.parser_failure`                          | 퍼징       | LIMITED      | REALIZED | MEDIUM   | PASS+warn                                          |
| `r6.coverage_incomplete` (전제조건 미충족)          | —        | LIMITED      | —        | (케비엇)    | → §8.4 ERROR(검사 불가) 유발                             |
| ~~`r6.*_handled` (처리된 OOM/크래시/파서)~~          | —        | —            | —        | —        | **미발화** (gracefully 처리된 에러 = 정상 방어, finding 아님)    |


> `r6.coverage_incomplete`은 위험 finding이 아니라 **커버리지 주의(caveat) 신호**다 — Evidence가 없어 §5 severity 도출에서 **제외**되며(그래서 severity 칸이 `(케비엇)`), §8.4 ERROR(검사 불가) 경로만 트리거한다.
>
> **오탐 정제(구현됨, 2026-06):** 퍼징 특성을 반영해 r6 신호를 좁혔다 — (1) `*_handled`(처리된 크래시/OOM/재귀)는
> **미발화**: 에러를 잡고 생존한 건 정상 방어이지 결함이 아니다(미처리 크래시만 보고). (2) `high_error_rate`는 에러가
> 대부분 **정상 검증 거부**(-32602/-32601/-32600/-32700)면 **억제** — 퍼징 garbage를 올바르게 거부하는 건 좋은 검증이지
> 불안정이 아니다. (3) `error_info_leak`은 메시지가 **실제로 스택/경로/타입예외를 누출할 때만** CWE-209로 보고하고,
> 일반 런타임 문자열("Cannot read properties of undefined")뿐이면 `error_code_misuse`(CWE-20 입력검증)로 강등.
> (4) 의도적 장시간 툴(`*long-running*`/sleep/poll/stream/subscribe)의 timeout은 그 툴의 계약이므로 제외.

### 정적 스캐너 (해당 R-type으로 합류)


| kind id                                         | Impact   | Evidence      | Severity | Verdict   |
| ----------------------------------------------- | -------- | ------------- | -------- | --------- |
| `static.malicious_package` (R2)                 | TAKEOVER | DETERMINISTIC | CRITICAL | REJECT    |
| `static.decode_exec_hook` (R2)                  | TAKEOVER | DETERMINISTIC | CRITICAL | REJECT    |
| `static.encoded_payload_inline` (R2)            | TAKEOVER | POTENTIAL     | HIGH     | PASS+warn |
| `static.install_hook` / `static.typosquat` (R2) | LIMITED  | POTENTIAL     | LOW      | PASS+warn |
| `static.schema_permissive` (R5)                 | LIMITED  | POTENTIAL     | LOW      | PASS+warn |
| `static.metadata_divergence` (R4)               | LIMITED  | POTENTIAL     | LOW      | PASS+warn |


---

## 10. Worked Examples

### 10.0 finding 하나의 전체 흐름 (end-to-end)

vulnerable 서버의 "민감 경로 파일 read" 1건을 단계별로:

1. **스캐너** — [r1_data_access.py](../src/mcp_security_analyzer/dynamic/scanners/r1_data_access.py)가 `file_read`(민감 경로) 이벤트를 보고 `kind=r1.sensitive_read` finding 생성.
2. **policy.py** — 카탈로그(§9 R1)에서 `r1.sensitive_read → (impact=PARTIAL_CI, evidence=REALIZED 기본)`.
3. **Evidence 확정** — `related_events`에 실측 `file_read`가 있음 → `evidence=REALIZED` 확정(§4.2).
4. **confidence.py** — Syscall 관찰 → confidence 0.85(표시용, §6).
5. **verdict.py / §5 LUT** — `LUT[PARTIAL_CI][강] = HIGH` → `severity=HIGH`.
6. **§8.1 차단 규칙** — `PARTIAL_CI ∧ REALIZED` 성립 → **REJECT**, 사유 `data-access`.

### 10.1 fixture/실서버

- **benign 서버** (greet): finding 없음, 또는 fuzz 중 크래시(AVAILABILITY/realized → HIGH(A)) → 차단 트리거 아님 →
툴이 정상 노출됐고 시퀀스가 돌았으면 **PASS**(warnings: stability; SIGSEGV류면 §8.3 플래그). 서버를 못 띄우거나 툴 0개면 **ERROR(검사 불가)**.
- **vulnerable 서버**: 민감경로 read(§10.0) 또는 path-traversal 성공(TAKEOVER/realized → CRITICAL) → **REJECT**. SQL 에러 누출은 MEDIUM warn.
- **malicious 서버**: 툴 응답 인젝션(PARTIAL_CI/realized → HIGH) → **REJECT**; description 패턴은 단독 POTENTIAL이라 warn(같은 R3 그룹으로 표시).
- **redis 서버** (report.md 예시): 이 세션은 **툴 0개 + init_enumerate timeout
  - fuzz_input_validation 완료 전 크래시** — §8.4 트리거(노출 툴 0개 / 시퀀스 완료 전 크래시)에 해당 → **ERROR(검사 불가)**.
  (대조용: 만약 툴이 정상 노출되고 시퀀스가 끝난 뒤 단발성 처리 크래시만 났다면 PASS+warnings(stability)였겠지만, 이 세션은 그 경우가 아니다.)

---

## 11. 구현 매핑


| 로직                                       | 위치                                                                                                                                                                                   |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Verdict 산정기 (§5/§8)                      | 신규 `dynamic/output/verdict.py` ([scorer.py](../src/mcp_security_analyzer/dynamic/output/scorer.py) 대체)                                                                               |
| `kind → (impact, evidence)` 카탈로그 (§9)    | 신규 `policy.py`                                                                                                                                                                       |
| 방법별 confidence 기준치 (§6)                  | 신규 `confidence.py`                                                                                                                                                                   |
| `Finding`에 `kind`/`impact`/`evidence` 필드 | [models.py](../src/mcp_security_analyzer/dynamic/models.py) (현재 없음)                                                                                                                  |
| invisible-unicode 2분할 (§4.4)             | **구현됨** — [descriptions.py:408-427](../src/mcp_security_analyzer/static/scanners/descriptions.py#L408-L427) `_find_invisible` → `kind=r3.invisible_unicode_bidi`/`_zw` ([descriptions.py:308](../src/mcp_security_analyzer/static/scanners/descriptions.py#L308))                                                                                    |
| 메모리 손상 크래시 식별 (§8.3)                     | **구현됨** — `verdict.is_memory_corruption_signal()`([verdict.py:134](../src/mcp_security_analyzer/dynamic/output/verdict.py#L134))가 크래시 프로세스의 음수 returncode로 판정, orchestrator `_collect`가 `crash_signals`→`mem_corruption_crash`로 수집해 `evaluate()`에 전달 → `WARN_MEMORY_CORRUPTION` 플래그(Docker는 컨테이너 returncode라 주로 no-docker에서 동작) |
| coverage→ERROR(검사 불가) (§8.4)             | orchestrator 부팅 실패 예외를 ERROR로 표면화 + `r6.coverage_incomplete` 케비엇                                                                                                                     |


**리팩터 범위(주의):** "스캐너는 `kind`만 부여하고 severity는 카탈로그가 산출"로 바꾸려면 **정적 5 + 동적 7 = 12개 스캐너 전부**가
대상이고, correlation `engine.py`의 `_overlaps` 병합 + `+0.05`도 손봐야 한다(§7). 까다로운 곳: R1 `_NETWORK_SEVERITY` 테이블,
R6의 handled-branch 삼항식([:653,:674,:706](../src/mcp_security_analyzer/dynamic/scanners/r6_stability.py#L653)),
인라인 confidence 리터럴([code_patterns.py:34](../src/mcp_security_analyzer/static/scanners/code_patterns.py#L34),
[schema_audit.py:43](../src/mcp_security_analyzer/static/scanners/schema_audit.py#L43)).

---

## 12. 보정 (Calibration)

- **라벨링 코퍼스**: known-good(공식/인기 MCP 서버) + known-bad(seeded 악성 + 공개 PoC)로 `kind`별 `(impact, evidence)`
배정의 정밀도/재현율을 검증하고 golden 회귀 스위트로 동결. **ERROR(검사 불가) 비율**도 함께 측정(검사 가능성 지표).
- **shadow 모드**: FP율 측정 전까지 verdict는 기록만 하고 자동 차단은 보류.
- **노이즈 우선 검증 대상**: 퍼징 응답 기반 CRITICAL(confidence 0.70).
- **v2 확장**: 메모리 손상 시그니처(ASAN 등)로 exploitable-crash를 식별하면 §8.3 경고 플래그를 R6 TAKEOVER/REJECT로 승격.

---

## 13. 한눈에 보기 (처음 보는 사람을 위한 요약)

**우리가 푸는 문제.** MCP 서버 하나를 검사하면 "의심스러운 점(finding)"이 여러 개 나온다.
각 finding이 *얼마나 심각한지* 정하고, 결국 이 서버를 **써도 되는지(PASS) / 쓰면 안 되는지(REJECT)** 답한다.
(검사 자체가 아예 안 된 경우 — 서버를 못 띄움 등 — 은 위험을 판정하지 않고 **ERROR(검사 불가)** 메시지를 돌려준다.)

**핵심 아이디어 — 질문 두 개로 심각도를 정한다.** 점수를 더하고 나누지 않고, finding마다 두 가지만 묻는다.

1. **"현실이 되면 얼마나 나쁜가?"** (= Impact, 피해 크기)
  - 🔴 **TAKEOVER** : 내 컴퓨터를 통째로 장악 (코드 실행, 파일 마음대로 읽고 쓰기, 비밀정보 빼가기)
  - 🟠 **PARTIAL_CI** : 일부만 — 특정 파일 훔쳐보기, LLM을 속여 엉뚱한 행동 유도
  - 🟡 **AVAILABILITY** : 서버가 죽음 (껐다 켜면 됨)
  - ⚪ **LIMITED** : 사소함 (에러 메시지 노출, 느려짐 등)
2. **"진짜로 일어나는 걸 봤는가?"** (= Evidence, 증거의 직접성)
  - ✅ **REALIZED** : 서버를 **돌려보니 실제로** 그 행동을 목격함
  - ✅ **DETERMINISTIC** : 돌려보진 않았지만 **빼박 증거** (알려진 악성 패키지 등 — 오해의 여지 거의 없음)
  - ❓ **POTENTIAL** : 코드/설명만 보고 **의심**되는 정도 (진짜인지 확인 못 함)

**두 답을 표에 넣으면 심각도가 나온다** (피해 클수록·증거 확실할수록 ↑):

```
                 확실(REALIZED/DETERMINISTIC)   의심만(POTENTIAL)
  TAKEOVER    →  CRITICAL                        HIGH
  PARTIAL_CI  →  HIGH                            MEDIUM
  AVAILABILITY → HIGH(A)                         MEDIUM
  LIMITED     →  MEDIUM                          LOW
```

**최종 판정.**

- **REJECT(쓰지 마라):** 컴퓨터 장악(TAKEOVER)이나 부분 침해(PARTIAL_CI)가 **확실한 증거**로 확인된 finding이 하나라도 있을 때.
여기서 "확실한 증거"는 *돌려봐서 목격(REALIZED)* 했거나 *빼박 정적 증거(DETERMINISTIC, 예: 악성 패키지)* 인 경우 둘 다 포함한다.
- **PASS(써도 된다):** 위 REJECT가 아닐 때. (사소한 경고는 따로 목록으로 보여준다.)
- **ERROR(검사 불가):** 서버가 부팅을 못 하거나 툴이 0개라 **아예 검사를 못 했을 때.** 위험 판정(REJECT/PASS)을 내리지 않고,
왜 못 했는지 에러 메시지로 알려준다(디버깅 과정에서 ERROR로 보임). "나쁜 걸 못 봤다"와 "안전하다"는 다르므로 PASS로 처리하지 않는다.

**일부러 차단하지 *않는* 것들:**

- 서버가 그냥 **죽는 것**(크래시) → 흔한 버그일 뿐 컴퓨터를 먹는 게 아님 → 경고만.
(단, 메모리 손상 의심 크래시는 RCE 가능성이 있어 **경고 플래그**를 달아 사람이 본다.)
- 코드/설명만 보고 **의심**되는 것 → 직접 목격으로 확인되기 전엔 경고만.

> **왜 이렇게?** MCP 서버는 대체재가 많다. "확실히 위험한 것"은 과감히 막되, 흔한 버그(크래시)나 단순 의심까지
> 막으면 멀쩡한 서버도 다 막혀 검사기가 쓸모없어진다. **확실한 증거로 컴퓨터를 위협하는 것만 막는다.**

**confidence(신뢰도)는 따로 논다.** "이 finding이 진짜일 확률"을 0.55~0.95(클수록 확실)로 **보여주기만** 하고
판정에는 쓰지 않는다. (예: honeypot 트랩이 걸리면 0.95로 거의 확실, 코드만 보고 의심하면 0.55.)

**한 문장 요약:** *"얼마나 나쁜가(Impact) × 얼마나 확실한가(Evidence)" 로 심각도를 표에서 찾고,
확실한 증거로 컴퓨터를 위협하는 finding이 하나라도 있으면 REJECT, 아니면 PASS — 단 아예 검사를 못 했으면 판정 대신 ERROR(검사 불가).*