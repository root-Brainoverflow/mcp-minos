# 정적 분석 계층 (Static Analysis)

`src/mcp_security_analyzer/static/`와 `src/mcp_security_analyzer/common/` 하위
모듈의 동작. 패키지 다운로드 절차는 [static-tarball-fetch.md](static-tarball-fetch.md)에
별도.

이 문서에서 쓰는 도메인 용어:

- **타볼(tarball)** — 레지스트리가 패키지를 내려줄 때 쓰는 압축 아카이브.
- **dist-tag** — `latest`·`next`처럼 버전 번호 대신 쓰는 별칭.
- **소스 배포본(sdist)** — PyPI의 원본 소스 배포 형식. 미리 빌드된 *휠(wheel)*
  과 대비.
- **소스 시그널** — 소스 트리를 정규식으로 훑어 잡는 명명된 표식. 예: 코드에
  `channel: 'chrome'`이 있으면 `playwright.channel.chrome` 시그널.

---

## 0. 산출물

정적 분석은 대상 MCP 서버를 실행하지 않고 두 가지를 만든다.

1. **환경 스냅샷** — 서버의 런타임 버전·의존성·소스 시그널을 구조화한 정보.
   동적 분석이 이걸 받아 샌드박스 환경을 첫 시도에 맞춘다.
2. **정적 보안 발견(findings)** — 소스·매니페스트·도구 메타데이터에서 찾은 위험
   신호 목록. 최종 보고서에 들어간다.

같은 입력(소스 트리)에서 두 산출물이 나오지만 용도가 다르다.

```
ServerConfig (실행 명령, 인자)
        │
        ▼
collect_environment_snapshot()       ─▶ EnvironmentSnapshot ─▶ (동적으로 전달)
        │  (로컬 소스 / 원격 패키지 분기)
        │
        ▼ snapshot.source_tree_path
run_static_findings(include_divergence=False)  ─▶ StaticReport (+ source_tools)
        │  매니페스트·Semgrep (단순 + taint 모드) (소스 트리)
        │  도구 추출 (이름·설명·스키마)             ─▶ 2.4·2.5 입력 (소스 우선)
        │  설명문·스키마 감사 (소스 도구 목록으로 선실행)
        ▼  (소스 스캐너는 샌드박스 부팅 *이전*에 끝남)
[동적] init → tools/list → 런타임 도구 목록 수집
        │
        ▼ source_tools + 런타임 목록
scan_metadata_divergence()           ─▶ 2.6 차이 검사 (양쪽 있을 때만, 동적 *이후*)
        │  (소스 추출 실패로 도구를 못 잡았으면 2.4·2.5는 런타임 목록으로 폴백)
        ▼
```

`minos static` 단독에서는 런타임 도구 목록이 없다. 소스에서 도구 정의를 추출
할 수 있으면 네 스캐너(매니페스트·Semgrep·설명문·스키마)가 도커 없이 돈다.
도커는 동적 단계의 페이로드 시험에만 필요하다.

---

## 1. 환경 스냅샷

### 1.1 자료형 — `common/environment_snapshot.py`

`EnvironmentSnapshot`은 frozen 데이터클래스로 다음을 담는다.

- `origin` — 출처: 로컬 소스 / 받아 푼 원격 패키지 / 매니페스트만 / 없음.
- `coverage` — full / partial / none.
- `package_name`, `package_version`.
- `engines_node`, `requires_python` — 매니페스트의 런타임 버전 요구 사항을 원본
  문자열 그대로(예: `">=20"`, `">=3.11"`).
- `node_dependencies`, `python_dependencies`.
- `source_signals` — 소스 시그널 집합 (1.3 참고).
- `source_tree_path` — 소스 트리 경로. 동적 쪽이 컨테이너에 마운트해 패키지
  재다운로드를 피할 수 있다.
- `manifest_label` — 출처 라벨.

설계 원칙: 동적 쪽 내부 이름(샌드박스 이미지 태그 등)은 담지 않는다.
`">=20"` 같은 원본 문자열만 두고 실제 이미지 태그(`node20`/`node22`)로의 변환
은 동적 쪽이 맡는다. 정적 계층을 동적 구현 세부에 묶지 않기 위함.

### 1.2 원격 패키지 다운로드 — `static/tarball_fetcher.py`

`npx @scope/x`나 `uvx y`처럼 지정된 서버는 로컬에 소스가 없으므로 레지스트리에서
타볼을 받아 임시 디렉터리에 푼다. 호스트의 npm/pip에 의존하지 않도록 파이썬
표준 라이브러리(urllib, tarfile)만 쓴다.

npm 흐름:

1. 지정 문자열을 이름과 버전 힌트로 분해. 스코프 패키지(`@scope/name@1.2.3`)는
   두 번째 `@`를 버전 구분자로 본다.
2. `https://registry.npmjs.org/<이름>`에서 메타데이터(모든 버전·태그)를 받는다.
3. 버전 해석. 힌트가 실제 버전 번호면 그대로, dist-tag(`latest`·`next`)면 태그
   매핑에서 실제 버전으로 변환, 힌트가 없으면 `latest` 태그. `npm`/`npx`가
   `@latest`를 태그로 취급하므로 이 변환이 필요하다.
4. 해당 버전의 타볼 URL을 받아 푼다. npm 타볼은 내용물을 `package/`로 한 번
   감싸므로 그 안쪽을 실제 소스 루트로 삼는다.

PyPI 흐름: `https://pypi.org/pypi/<이름>/json`에서 sdist URL을 찾아 받는다. 휠
전용 패키지는 원본 소스가 없어 매니페스트 수준까지만 분석된다.

압축을 풀 때 항목 경로가 대상 디렉터리 바깥을 가리키면(`../` 등) 그 항목은
건너뛴다. 임의 공개 패키지를 다루므로 디렉터리 트래버설 방어가 필요하다.

### 1.3 소스 트리 분석 — `static/source_analyzer.py`

디렉터리 하나를 받아 다음을 추출한다.

- `package.json`: 이름·버전, `engines.node`, dependencies / devDependencies /
  optionalDependencies / peerDependencies.
- `pyproject.toml`: 이름·버전, `requires-python`, project / optional /
  dependency-groups / poetry 의존성.
- `requirements.txt`: 줄별 패키지 이름.
- 소스 코드 스캔: 최대 500개 파일, 파일당 256 KiB까지. `.git`, `node_modules`,
  `.venv` 등은 건너뛴다. 정규식에 걸리면 소스 시그널을 기록한다 (예:
  `channel: 'chrome'` → `playwright.channel.chrome`).

소스 시그널은 동적 쪽 레시피 매칭이 크로미움과 진짜 크롬을 구별하는 근거가 된다.

#### 원격 패키지에서의 유효성

같은 분석기가 그대로 돈다. 효과는 발행된 타볼에 무엇이 들어 있느냐에 달린다.

발행 타볼은 매니페스트의 `files` 항목이 정하는 파일만 담는다. 보통 빌드된
`dist/`는 들어가고 원본 `src/`는 빠진다. 분석 대상이 원본이 아니라 빌드 결과물
인 경우가 많다는 뜻이다.

빌드 결과물 상태별:

- **번들만 됨 (대다수)** — 파일이 합쳐졌을 뿐 변수·함수 이름·문자열은 그대로.
  시그널 스캔이 동작한다. browsermcp의 `dist/index.js`가 이 상태.
- **압축까지 됨 (드묾)** — 변수·함수 이름은 줄어든다. 시그널이 노리는 문자열
  리터럴과 외부 API 속성 키는 통상 압축에서 보존되므로 대부분 살아남는다.
  속성 키까지 공격적으로 줄이는 설정에서만 누락.
- **타볼에 코드가 없음** — 트리 셰이킹·`files` 제외로 빠진 경우. 타볼만으로
  검사 불가.

시그널이 비었다는 사실만으로 "원격에서 안 통한다"고 해석하면 안 된다.
browsermcp는 시그널이 비었으나 정확한 결과였다 — 그 패키지는 웹소켓으로 기존
브라우저에 붙는 방식이라 크롬/플레이라이트 시그널의 근거가 원래 없다.

한계:

- 분석 대상이 원본 소스가 아닌 빌드 결과물일 때가 많다.
- 압축된 발행물에서는 일부 시그널을 놓칠 수 있다.
- 발행물에서 빠진 코드(트리 셰이킹·`files` 제외)는 타볼만으로는 검사 불가.
- Semgrep(2.2)과 동일한 효과 조건. 압축 안 된 발행물에서 잘 되고 압축·누락
  된 경우에 저하된다.

### 1.4 진입점 — `static/runner.py`

`collect_environment_snapshot(server)`의 분기:

1. 인자에 호스트에 존재하는 절대 경로가 있으면 → 매니페스트 디렉터리로 거슬러
   올라가 로컬 소스로 분석. `origin=로컬 소스`.
2. 명령이 `npx`/`pnpx`/`bunx`이고 인자에서 패키지 이름이 추출되면 → npm 타볼을
   받아 분석. `origin=원격 패키지`.
3. 명령이 `uvx`/`pipx`면 → PyPI sdist를 받아 분석. `origin=원격 패키지`.
4. 어느 것도 아니면 → 빈 스냅샷.

반환은 (스냅샷, 정리 함수) 쌍. 정리 함수는 받아 푼 임시 디렉터리를 지운다. 받은
게 없으면 no-op이라 호출 쪽은 무조건 부르면 된다.

`coverage`는 *스캔 수행 여부*로 정한다. 소스 트리를 확보해 스캔했으면 결과가
비어 있어도 full. 소스 자체를 못 본 경우만 partial/none.

### 1.5 동적 쪽 소비

샌드박스는 스냅샷을 받아 두 곳에 넘긴다.

- **런타임 결정기** — 스냅샷에 Node/파이썬 버전 요구 사항이 있으면 그 값으로
  베이스 이미지를 정한다. 원격 패키지의 경우 동적 단독으로는 버전 요구 사항을
  볼 수 없으므로(로컬 절대 경로일 때만 매니페스트를 읽음) 정적 추출본이 필수.
- **사전 검사기** — 스냅샷이 있으면 디스크 재읽기·`npm view`·PyPI 재조회를
  생략하고 스냅샷을 그대로 분석 근거로 변환.

스냅샷이 없거나 비면(원격 다운로드 실패, 정적 비활성) 동적은 기존 탐지·재시도
경로로 폴백한다. 정적은 우선 경로, 동적 자체 탐지는 안전망.

`origin`이 로컬 소스면 근거 출처를 `local-manifest`로 표시해 기존 로컬 의존성
설치 경로가 그대로 작동한다. 원격 패키지면 `extracted-tarball:<이름>`으로 표시.

---

## 2. 정적 보안 스캐너

### 2.0 공통 발견 자료형 — `common/static_finding.py`

`StaticFinding`은 한 위험 신호를 담는다. 필드: 위험 유형·심각도·신뢰도·제목·
설명·스캐너명·위치·증거·도구 이름·태그.

- **위험 유형** — R1(데이터 유출), R2(코드 실행), R3(LLM 행위 조작), R4(행위
  불일치), R5(입력 처리), R6(안정성).
- **심각도** — CRITICAL/HIGH/MEDIUM/LOW/INFO.
- **신뢰도** — 0~1 추정값.

위험 유형·심각도 enum은 동적 쪽 정의를 재사용한다. 최종 보고서가 정적·동적
발견을 동일 분류 체계로 묶기 위함.

정적 신호 대부분은 동적이 확인해야 할 의심이라 신뢰도를 중간 이하로 둔다.

### 2.1 매니페스트 보안 — `static/scanners/manifest_security.py` (R2)

매니페스트의 의존성을 검사해 공급망 위험을 찾는다.

- **알려진 악성 패키지** — 이름이 내장 차단 목록에 있으면 CRITICAL. 목록은 외부
  보안 피드로 확장 가능하게 둠.
- **타이포스쿼팅** — 인기 패키지 이름과 편집 거리 1 이하인데 그 패키지는 아닌
  이름. MEDIUM, 낮은 신뢰도. 편집 거리 계산은 자체 구현.
- **설치 훅** — npm `preinstall`/`install`/`postinstall` 본문에 위험 패턴
  (`curl ... | sh`, `eval`, `base64 -d`, 원격 스크립트 fetch)이 있으면 HIGH,
  단순 빌드 명령이면 LOW. 설치 훅은 사용자가 코드를 보기 전에 실행되므로
  공급망 공격의 흔한 통로.
- **인코딩 페이로드 인라인** — 설치 훅 본문에 base64 블롭(60자 이상)·16진
  시프트 블롭·`node -e "..."`·`python -c "..."` 같은 즉시 실행이 있으면 HIGH.
  Socket·Endor Labs 등이 정형화한 staged payload 패턴 대응.

### 2.2 Semgrep 래퍼 + 룰 — `static/scanners/code_patterns.py`, `static/patterns/`

Semgrep CLI를 서브프로세스로 실행하고 JSON 출력을 발견으로 변환한다. Semgrep이
호스트에 없으면 경고만 남기고 건너뛴다.

**Semgrep.** `grep`이 텍스트를 매칭한다면 Semgrep은 코드를 AST로 파싱한 뒤
패턴 매칭한다. 공백·포맷·주석·문자열 내용에 둔감하며, 룰은 YAML로 적는다.

**룰 6파일 23규칙.**

- r1: 시크릿 형태 환경 변수 읽기, 시스템 루트 광범위 읽기.
- r2: 직접 명령/프로세스 실행, 변수를 넣은 eval, 런타임 패키지 설치.
- r4: 샌드박스/CI/디버그 환경 감지 분기, 시간 기준 분기.
- r5(단순 패턴): f-문자열 SQL, 문자열 연결 경로 열기, 템플릿 문자열 셸 명령.
  호출 사이트의 존재만 보고하므로 신뢰도 낮음.
- r5(taint 모드, [r5-taint.yaml](../src/mcp_security_analyzer/static/patterns/r5-taint.yaml)):
  같은 sink지만 실제 데이터 흐름이 확인된 경우만 매치.
- r6: 타임아웃 없는 HTTP, 파일 전체 메모리 적재.

각 규칙 메타에 위험 유형과 신뢰도(low/medium/high)가 적혀 있고, 래퍼가 이를
발견의 위험 유형·심각도·신뢰도로 변환한다.

**taint 모드.** 단순 패턴(`execSync(...)` 호출 존재)은 정상 사용까지 잡으므로
신뢰도를 높이지 못한다. taint 모드는 데이터 흐름을 추적해 *출처*에서 *sink*
까지 실제 경로가 있을 때만 매치하고, 중간 *살균기*는 제외한다. r5-taint.yaml의
다섯 규칙이 보는 흐름:

- 출처: `@mcp.tool()` / `@server.tool()` 데코레이터 함수의 인자(파이썬),
  `server.tool(name, schema, async (args) => ...)` 같은 핸들러 클로저의
  `args`(Node/TS).
- sink: `subprocess.run(shell=True)`·`os.system`·`os.popen`(명령 실행), 보간
  된 SQL execute, 매개변수 경로의 `open(...)`·`fs.readFileSync`(경로 traversal),
  `execSync(\`...${x}...\`)` 등(보간 셸 명령).
- 살균기: `shlex.quote`·`shlex.split`, `os.path.realpath`,
  `pathlib.Path(...).resolve()`, `path.normalize`/`path.resolve`.

흐름이 확인되면 신뢰도 0.7 이상으로 신고. 합성 테스트의 네 케이스(위험·살균
됨·매개변수 비관련·하드코딩) 중 위험 두 건만 정확히 잡힘.

**`dist/` 기본 무시 우회.** Semgrep 기본 설정은 `dist/`·`build/`·`node_modules/`
를 검사 대상에서 뺀다. 발행 패키지는 코드가 `dist/`에 있으므로 그대로 두면
아무것도 안 잡힌다. 래퍼는 검사 직전 대상 루트에 빈 `.semgrepignore`를 두어
기본 무시를 무력화하고, 끝나면 자기가 만든 그 파일만 지운다.

### 2.3 도구 정의 추출 — `static/tool_extractor.py` + `static/zod_to_schema.py` + `static/pydantic_to_schema.py`

설명문 스캐너(2.4)와 스키마 감사기(2.5)의 입력은 도구 정의 목록(이름·설명·
입력 스키마). 입력은 *소스 추출 우선, 런타임 응답 폴백*.

**이름·설명 추출.** 소스 트리가 있으면 다음을 정규식·AST로 추출:

- JSON 파일의 `{ "name": "...", "description": "..." }` 객체. 매니페스트 객체
  (`version`·`dependencies` 등 표식 2개 이상)는 건너뜀.
- JS/TS·파이썬 소스의 name·description 짝. `z.literal(...)` 래핑, JSON 키
  스타일, 객체 리터럴 스타일, 파이썬 키워드 스타일 모두 인식.

도구 이름은 평평한 식별자(`^[A-Za-z0-9_.-]+$`)로 가드. 공백 있는 제목·스코프
패키지명(`@scope/x`)·URL은 걸러짐.

**입력 스키마 복원.**

*JS/TS — `zod_to_schema`.* 이름·설명 매치 위치 가까이에서 `arguments` /
`inputSchema` / `parameters` / `schema` 필드를 찾아 zod 표현식을 JSON Schema로
변환.

- 기본 타입: `z.object` / `z.string` / `z.number` / `z.boolean` / `z.array`
  / `z.literal` / `z.enum` / `z.null` / `z.union` / `z.record` / `z.any`.
- 수식자: `.optional` / `.nullable` / `.describe` / `.min` / `.max` /
  `.length` / `.regex` / `.email` / `.url` / `.uuid`. `.default` / `.refine`
  / `.transform`은 무시.
- 심볼 참조와 `.extend({...})` 처리. browsermcp 13개 도구 스키마 전수 복원 확인.

*파이썬 — `pydantic_to_schema`.* `.py`는 정규식 대신 표준 라이브러리 `ast`로
파싱하고 두 가지 정의 형태를 인식:

- **FastMCP 데코레이터** (`@mcp.tool()` / `@server.tool()`): 함수 이름 = 도구
  이름, 첫 줄 docstring = 설명, 어노테이션 있는 매개변수 = 스키마. 매개변수
  타입이 pydantic 클래스면 풀어서 중첩.
- **저수준 `Tool(name=..., description=..., inputSchema=...)` 호출.**
  `inputSchema`는 (a) 리터럴 dict, (b) pydantic 클래스 참조, (c)
  `<Class>.model_json_schema()` 호출 모두 지원. `name`/`description`이
  `EnumClass.MEMBER[.value]` 참조이면 같은 파일 enum 정의에서 풀어냄.

변환기 커버리지:

- 기본 타입: `str` / `int` / `float` / `bool` / `bytes` / `None`.
- 컨테이너: `list[T]` / `List[T]` / `tuple[...]` / `dict[K,V]` / `set[T]` 등.
- 선택성: `Optional[T]` / `T | None` → 필수 제외 + null 합성.
- 합성: `Union[A, B]` / `A | B` → anyOf. 원시 타입 합집합은 `type: [...]`로 접힘.
- 리터럴: `Literal["a", "b"]` → enum.
- `Annotated[T, Field(...)]` (PEP 593) — Field 메타가 어노테이션 안에 들어가는
  pydantic v2 표기. 내부 Field 호출을 풀어 description/pattern/min·max/ge/le 등 합성.
- `Field(...)` 키워드: `description`, `default`, `default_factory`,
  `min_length`/`max_length`, `pattern`, `ge`/`gt`/`le`/`lt` 등.

실측: [mcp-server-fetch](https://pypi.org/project/mcp-server-fetch/)는
`Annotated[..., Field(...)]` 방식, [mcp-server-time](https://pypi.org/project/mcp-server-time/)
은 enum 도구 이름 + 리터럴 inputSchema dict 방식. 두 서버 모두 도커 없이 정적
만으로 도구·설명·스키마 복원 확인.

**미커버.** zod의 refinement·custom transform, pydantic의 커스텀 validator,
런타임 동적 합성, 자체 스키마 클래스는 표현 못함. 해당 도구의 `input_schema`
는 `None`이 되고, 스키마 감사기만 런타임 폴백 입력으로 다시 검사. 설명문
검사는 소스 입력으로 정상 동작.

**런타임 폴백 조건.**

- 스냅샷에 소스 트리가 없음(휠 전용 PyPI 패키지, 다운로드 실패 등).
- 소스가 있어도 추출기가 아무 도구도 못 잡음.

런타임 응답이 LLM이 받는 텍스트이자 권위 있는 JSON 스키마의 출처다.

```
[정적] 환경 스냅샷 → 소스 트리 → 추출기 → 도구 목록(소스)
                                              │
                                              ├─▶ 비어 있지 않으면 → 2.4·2.5 입력
                                              │
                                              ▼ (소스 추출 실패 시)
[동적] init → tools/list → 도구 목록(런타임)
                                              │
                                              └─▶ 2.4·2.5 입력 (폴백)
```

### 2.4 설명문 스캐너 — `static/scanners/descriptions.py` (R3)

도구 메타데이터에 숨은 주입·조작을 찾는다.

**검사 대상.** 도구 객체의 모든 텍스트 필드. LLM은 최상위 설명문 외에 매개변수
설명·기본값·enum 값·example 필드도 컨텍스트로 받는다.

- `tool.description`
- `tool.inputSchema.properties[*].description`
- `tool.inputSchema.properties[*].default` (문자열일 때)
- `tool.inputSchema.properties[*].enum` (문자열 원소만)
- `tool.inputSchema.examples` 및 `properties[*].examples`

PipeLab MCP 프록시·Invariant Labs `mcp-scan`이 짚은 우회 채널들이다. 같은 패턴
규칙을 모든 필드에 적용하고, 도구당 같은 종류 발견은 한 번만 신고(중복 제거).

**규칙 카드 형태.** 패턴은 정규식 목록이 아니라 카드로 표현된다.

- `rule_id` — 짧은 식별자(예: `ignore-previous`).
- 정규식 패턴.
- `rationale` — 위험 신호인 이유.
- `example_match` — 양성 예시.
- `example_skip` — 비슷해 보이지만 잡히지 말아야 할 예시(있을 때).

스캐너는 매치 시 카드의 rationale과 예시를 발견 본문에 그대로 박는다. 결과가
"패턴 매치됨"이 아니라 *어떤 규칙·왜 위험·예시*를 함께 설명. AgentWatcher
(2026)의 설명 가능한 규칙 접근에 대응.

**검사 항목.**

- **비가시 유니코드** — 폭 0 문자, BOM, 글자 방향 제어, 태그 문자. CRITICAL.  심각도는 CRITICAL로 동일하나 `kind`가 갈린다: 글자 방향 제어(bidi)·태그
  블록 등 정당한 용도가 없는 문자는 `r3.invisible_unicode_bidi`(DETERMINISTIC),
  i18n·이모지에 정상적으로 쓰일 수 있는 폭 0 문자는 `r3.invisible_unicode_zw`
  (POTENTIAL)로 표기 — verdict 모델의 §4.4 분류와 맞물린다.
- **역할 가로채기/지시 주입** — `ignore-previous`·`you-are-now`·`disregard`·
  `system-prompt`·`as-an-admin`·`new-instructions`·`do-not-tell`·`override`
  카드 8개. HIGH.
- **숨긴 지시 블록** — `html-comment`·`code-comment` 카드. HIGH.
- **인코딩 페이로드** — 긴 base64/URL 인코딩 덩어리. MEDIUM.
- **과도한 길이** — `tool.description`에만 적용. LOW.

### 2.5 스키마 감사 — `static/scanners/schema_audit.py` (R5)

입력 스키마의 느슨함을 점수화한다. 점수를 올리는 요소: `additionalProperties:
true`, 제약 없는 문자열 필드, path/url/cmd 같은 민감 이름인데 형식 제약 없음,
타입 미지정, 빈 스키마.

**설계 원칙.** 느슨한 스키마는 취약점이 아니라 공격 표면의 크기다. 단독으로
높은 위험으로 띄우지 않는다 — 심각도 LOW/MEDIUM, 신뢰도 ≤ 0.45. 동적 퍼징이
같은 도구에서 실제 문제를 찾았을 때 그 신뢰도를 올려 주는 보조 신호로 의도
했다. 스키마가 없는 도구는 건너뜀.

### 2.6 메타데이터 차이 스캐너 — `static/scanners/metadata_divergence.py` (R4)

소스 추출본과 런타임 `tools/list` 응답이 둘 다 있을 때만 발동. 두 채널의 어긋
남을 잡는다.

대개는 둘이 같다. 어긋나는 경우는 셋:

1. **조건부 등록** — 소스에 도구는 있는데 환경/설정에 따라 런타임에 등록 안 됨
   (또는 반대). 정상.
2. **외부 자료에서 채우기** — 코드에 `description=load_help("x")` 호출만 있고
   실제 텍스트는 시작 시 파일·DB에서. 정상.
3. **능동 회피(rug pull)** — 서버가 분석 환경을 감지해 분석 중엔 깨끗한 설명을,
   실제 사용자에는 다른 설명을 줌. 적대적.

(1)/(2)와 (3)을 자동으로 구분하지 못하므로, 어긋남을 낮은 신뢰도 R4 신호로 띄우
고 *어긋남 형태*(누락 방향·길이 비율·내용 변경)를 태그·심각도에 인코딩한다.

| 종류 | 심각도 | 신뢰도 |
|---|---|---|
| 소스에만 있음, 런타임에 없음 | INFO | 0.2 |
| 런타임에만 있음, 소스에 없음 | LOW | 0.35 |
| 설명 길이 비율 ≥ 3× | MEDIUM | 0.45 |
| 길이 비율 1.5×~3× | LOW | 0.3 |
| 내용만 다름(길이 유사) | LOW | 0.25 |

발견 본문에는 두 설명문이 모두 evidence로 들어가 즉시 비교 가능하다. 동적 R3
스캐너 출력과 교차 검토가 의도된 사용법 — 런타임 텍스트에서 R3가 따로 잡혔다면
회피 시나리오 (3)에 가깝다.

### 2.7 발견 러너 — `static/findings_runner.py`

위 스캐너들을 묶어 실행한다. 입력은 환경 스냅샷 + (선택) 런타임 도구 목록.

- 소스 트리가 있으면 매니페스트 보안·Semgrep을 돈다.
- 같은 소스 트리에서 도구 정의를 추출한다(2.3).
- 도구 목록 선택: 소스 추출본이 비어 있지 않으면 그것, 비고 런타임 목록이
  있으면 런타임, 둘 다 비면 빈 목록.
- 채택된 목록으로 설명문(2.4)·스키마 감사(2.5)를 돈다. 감사기는 `input_schema`
  가 비어 있는 도구는 건너뜀.
- 메타데이터 차이 스캐너(2.6)는 소스·런타임 양쪽이 다 있을 때만 발동.

반환은 `StaticReport`. 필드: 발견 목록·분석 도구 수·도구 출처(`source`/`runtime`
/`none`)·실행 스캐너·건너뛴 스캐너.

호출 시점:

- `minos static`: 런타임 도구 목록 없음. 소스 추출이 되면 네 스캐너가 돈다
  (매니페스트·Semgrep·설명문·스키마). 차이 스캐너는 건너뜀.
- `minos scan`: 소스 스캐너 네 개(매니페스트·Semgrep·설명문·스키마)를 샌드박스
  부팅 *이전*에 `run_static_findings(include_divergence=False)`로 먼저 돌린다.
  메타데이터 차이 스캐너(2.6)만 동적 종료 후 런타임 `tools/list`로 따로 발동
  (`scan_metadata_divergence(source_tools, output.tools)`). 끝나면 정적+동적
  발견을 합쳐 통합 verdict를 세션 `findings.json`에 영구 저장한다.

### 2.8 Semgrep과 자체 스캐너의 분담

**매니페스트 보안(2.1)** — 부분 겹침. 설치 훅 본문의 위험 패턴 검사는 Semgrep
규칙으로 표현 가능(Semgrep은 JSON 지원). 단:

- 타이포스쿼팅 — 편집 거리 계산. Semgrep은 AST 패턴 매처지 거리 계산 엔진이
  아님.
- 차단 목록 매칭 — 데이터셋 조회. Semgrep으로 표현하려면 이름 하나당 규칙
  하나 또는 거대한 metavariable-regex가 필요해 유지 비용 폭증.

설치 훅 키의 *존재 자체*도 LOW 신호로 별도 신고하는데, 이건 Semgrep 패턴 모형
에 잘 안 맞음. 같은 모듈에 묶는 게 단순.

**설명문 스캐너(2.4)** — 겹치지 않음. 입력이 도구 정의 객체(소스에서 추출한
구조 / 런타임 응답 JSON). Semgrep이 다루는 "소스 파일 안의 코드 패턴"과 입력
형태가 다름. 인메모리 객체의 텍스트를 정규식·유니코드 카테고리로 검사.

**스키마 감사(2.5)** — 겹치지 않음. 입력이 복원된 JSON Schema 딕셔너리. 검사
자체가 가중치 점수 합산이라 Semgrep의 패턴 매칭 모형과 안 맞음.

| Semgrep | 자체 스캐너 |
|---|---|
| 소스 파일 안의 코드 패턴 | 도구 정의 / 스키마 / 매니페스트 데이터 |
| 규칙당 한 위치 매칭 | 코퍼스 간 계산 (편집 거리, 점수 합산, 목록 대조) |
| YAML로 표현 가능한 구문 패턴 | 외부 데이터(차단 목록, 인기 목록)에 의존하는 검사 |

Semgrep은 코드를 보고, 자체 스캐너는 코드가 아닌 입력을 보거나 패턴 매칭이
아닌 계산을 한다. 중복 없음.

---

## 3. 명령행

세 명령이 `--target <이름>` / `--command --arg` 인터페이스를 공유한다. `scan`·
`dynamic`은 `--timeout <초>`로 설정의 샌드박스 타임아웃을 덮어쓸 수 있다.

- `minos static` — 정적만. 도커 불필요. zod·pydantic 기반 서버는 매니페스트·
  Semgrep·설명문·스키마 네 스캐너가 소스만으로 작동. 소스 추출 실패 시(휠 전용
  PyPI 패키지 등) 설명문·스키마 스캐너는 건너뜀.
- `minos dynamic` — 동적만. 환경 스냅샷은 만들어 샌드박스 환경 정합에 쓰지만
  정적 발견은 만들지 않음. `--no-docker` 지원.
- `minos scan` — 정적 + 동적 통합. 소스 스캐너 네 개(매니페스트·Semgrep·
  설명문·스키마)는 샌드박스 부팅 *이전*에 돈다. 동적 종료 후엔 메타데이터 차이
  스캐너만 런타임 `tools/list`로 추가 실행. 소스 추출이 잡힌 도구는 그대로 유지,
  안 잡힌 도구는 (소스 추출이 비었을 때) 런타임 도구 목록으로 폴백. JSON 출력은
  정적·동적 결과 + 통합 verdict를 모두 담고, 같은 통합 verdict와 합쳐진 발견을
  세션 `findings.json`에 저장한다.

`--format json`은 세 명령 모두 동일. 로그는 stderr, 명령 출력(JSON 포함)은
stdout으로 분리.

---

## 4. 위험 분류 매핑

| 위험 유형 | 담당 스캐너 |
|-----------|-------------|
| R1 (데이터 접근/유출) | Semgrep(시크릿 환경변수, 광범위 파일 읽기) |
| R2 (코드/명령 실행) | 매니페스트 보안(악성 패키지·타이포스쿼팅·설치 훅·인코딩 블롭), Semgrep(명령 실행·eval·런타임 설치) |
| R3 (LLM 행위 조작) | 설명문 스캐너 — 도구 메타데이터 전체 필드 순회, 규칙 카드 형식 |
| R4 (행위 불일치/기만) | Semgrep(환경/시간 조건부 분기), 메타데이터 차이 스캐너(소스 vs. 런타임) |
| R5 (입력 처리) | Semgrep 단순 패턴 + taint 모드(도구 핸들러 인자 → sink), 스키마 감사 |
| R6 (안정성) | Semgrep(타임아웃 없음·무제한 읽기) |

R3·R4의 다른 측면(도구 호출 응답·리소스 본문 주입, 행위 일관성 시험 등)은 동적
R3·R4 스캐너 담당. 위 표는 텍스트만 보는 정적 검사에 한정.

---

## 5. 한계와 미구현

- **압축된 배포물.** 발행물이 minify까지 거쳤으면 Semgrep 구조 패턴은 일부
  맞지만 이름 기반 규칙과 데이터 흐름 추적의 정확도가 떨어진다. 대부분의 MCP
  서버는 압축 안 된 번들이라 현재 잘 동작.
- **휠 전용 PyPI 패키지.** 원본 소스 배포본이 없으면 매니페스트 수준까지만.
- **소스 시그널 부재.** 코드가 한 파일로 뭉치거나 압축되면 시그널이 안 나올
  수 있음. 누락일 수도, 애초에 근거가 없는 경우일 수도.
- **스키마 복원 커버리지.** 변환기는 zod 기본 타입·수식자·심볼 참조·`.extend`,
  pydantic의 BaseModel·`Annotated[Field]`·FastMCP 함수 시그니처·저수준 Tool
  호출·`model_json_schema` 호출까지 처리(browsermcp·mcp-server-fetch·
  mcp-server-time 검증). zod의 refinement·custom transform, pydantic의 커스텀
  validator, 자체 스키마 클래스, 런타임 동적 합성은 표현 못함. 해당 도구만
  런타임 폴백.
- **소스 추출은 휴리스틱.** 런타임에 도구 정의를 동적으로 구성하는 드문 경우
  (이름·설명을 변수로 합성 등)는 못 잡음. 2.4는 그런 경우 런타임 입력으로
  자동 폴백.
- **정적·동적 verdict 통합 구현됨.** `minos scan`은 정적+동적 발견을 합집합으로
  모아 `verdict.evaluate(...)`로 단일 통합 verdict(REJECT/PASS/ERROR)를 산출하고,
  세션 `findings.json`에 영구 저장한다(별도 점수 합산은 아직 없음).
- **추출 트리의 영구 저장 미구현.** 실행 종료 시 임시 디렉터리가 지워짐. 새
  규칙으로 재분석하려면 패키지를 다시 받아야 함.
- **기능 선언 감사 미구현.** SDK별 패턴 의존이 커서 제외.
