# 샌드박스 환경 정합 (Sandbox Environment Matching)

이 문서는 `src/mcp_security_analyzer/dynamic/infrastructure/` 하위 네 모듈의
동작과 책임 분담을 정리한다.

- [runtime_resolver.py](../src/mcp_security_analyzer/dynamic/infrastructure/runtime_resolver.py) — 베이스 도커 이미지 선택.
- [bootstrap.py](../src/mcp_security_analyzer/dynamic/infrastructure/bootstrap.py) — 베이스 이미지 위에 무엇을 더할지 계획.
- [recipes.py](../src/mcp_security_analyzer/dynamic/infrastructure/recipes.py) + [recipes/builtin.yaml](../src/mcp_security_analyzer/dynamic/infrastructure/recipes/builtin.yaml) — 계획 매칭에 쓰이는 선언적 규칙 집합.
- [sandbox.py](../src/mcp_security_analyzer/dynamic/infrastructure/sandbox.py) — 계획대로 컨테이너를 실행하고, 즉시 실패 시 stderr를 분석해 한 번 재시도.

---

## 0. 풀려는 문제

MCP 서버는 `stdio`/`http` JSON-RPC 인터페이스만 표준화되어 있고 실행 환경 요구
사항은 서버마다 다르다.

- Node 20/Node 22/Python 3.11/Python 3.12 등 런타임 버전이 다르다.
- 일부는 `npx @scope/server`처럼 원격 패키지 spec으로, 일부는 호스트 절대 경로
파일(`/Users/.../server.py`)로 지정된다.
- 일부는 Chromium / Google Chrome / Playwright 브라우저 바이너리를 시스템에서
찾는다.
- 일부는 Postgres·Redis·MySQL·MongoDB 인스턴스가 도달 가능해야 부팅 메시지를
내보낸다.

이런 서버를 코드 신뢰 없이 분석하려면 다음 두 조건이 동시에 충족되어야 한다.

1. 서버가 실제로 부팅되어 동적 스캐너(R1~R4)가 신호를 받을 수 있을 정도로
  환경 의존성이 채워져 있을 것. 환경 미비로 서버가 죽으면 분석 결과는
   "취약점 없음"이 아니라 "결과 없음"이다.
2. 컨테이너 안에서 호스트 자원(파일시스템, 네트워크, 자격증명, 실데이터베이스)
  에 도달할 수 없을 것. 사용자 설정에 프로덕션 connection string이 들어 있어도
   분석 시점에는 일회용 사이드카로 리다이렉트되어야 한다.

본 문서는 이 두 조건을 어떻게 달성하는지를 모듈 단위로 기술한다.

---

## 1. 전체 흐름

`Sandbox.start()` 호출 시 다음 순서로 동작한다.

```
ServerConfig
       │
       ▼
[1] RuntimeResolver.resolve()        ──▶ ResolvedRuntime(image, command, reason)
       │
       ▼
[2] SourcePreflightInspector.inspect() ─▶ PreflightEvidence(deps, signals, …)
       │
       ▼
[3] plan_bootstrap()                  ──▶ BootstrapPlan(actions, services, env, rewrites)
       │
       ▼
[4a] _prepare_bootstrap_image()       ──▶ <image>-bootstrap-<hash>  (필요 시 docker build)
[4b] _start_sidecars()                ──▶ --internal 네트워크 + 사이드카 컨테이너
[4c] _build_docker_cmd() + spawn      ──▶ docker run -i …
       │
       ▼
0.3초 내 종료 시 _retry_bootstrap_from_stderr()
       │  stderr 분석 → 이미지 추가 빌드 → 1회 한정 respawn
       ▼
stdio 채널이 열린 Sandbox
```

이하 단계별로 각 함수의 입력·출력·분기 조건을 정리한다.

---

## 2. 단계 1 — 런타임 프로필 결정 (`runtime_resolver.py`)

### 2.1 출력

`RuntimeResolver.resolve(server)`는 `ResolvedRuntime(image, command, reason)`을
돌려준다. `image`는 도커 베이스 이미지 태그, `command`는 그 이미지 안에서 실행할
명령(컨테이너 PATH에서 해석 가능한 형태로 정규화된 것), `reason`은 어느 분기로
정해졌는지를 적은 사람이 읽는 문자열(로그용).

후보 이미지는 다음으로 고정되어 있다.

- `mcp-sandbox-node20`, `mcp-sandbox-node22`
- `mcp-sandbox-python311`, `mcp-sandbox-python312`
- `mcp-sandbox-polyglot`

각 이미지에는 해당 언어 런타임·패키지 매니저·`/workspace` 디렉터리·비루트 `user`
계정이 미리 설치되어 있다.

### 2.2 결정 순서

`resolve()`는 다음 분기를 위에서 아래로 평가하고, 처음 매치되는 분기에서 반환한다.

1. `server.env["MCP_SANDBOX_PROFILE"]`이 세팅되어 있으면 그 값을
  `mcp-sandbox-<value>`로 이미지 태그를 만들고 거기서 멈춘다.
2. `_classify_command(server.command)`가 basename으로 명령 종류를 정한다.
  - `node`, `nodejs`, `npx`, `npm`, `pnpm`, `pnpx`, `yarn`, `bunx`, `bun` →
   "node"
  - `python`, `python3`, `python3.10`~`python3.13`,` uv`,` uvx`,` pipx`,` poetry` → "python"
  - 어디에도 안 들어가면 `None`.
3. `_find_manifest_dir(server.args)`는 `Path(raw).is_absolute() and exists()`
  를 통과한 인자가 있을 때만 동작한다. 그 경로(파일이면 부모)에서 최대 5단계까지
   부모를 거슬러 올라가 `package.json` 또는 `pyproject.toml`을 찾아 디렉터리를
   돌려준다.
4. 위 (2)가 "node"이면, (3)이 찾아낸 디렉터리의 `package.json`에서
  `engines.node`를 읽어 메이저 버전 ≤20이면 `node20`, 그 외에는 `node22`로
   정한다. 매니페스트가 없거나 `engines.node`가 없으면 `DEFAULT_NODE = "node22"`.
5. (2)가 "python"이면 다음 우선순위로 프로필을 정한다:
  `_python_version_from_command(server.command)` (예: `python3.11` →
   `python311`) → 매니페스트의 `requires-python` (3.11 이하면 `python311`, 그
   외 `python312`) → `DEFAULT_PYTHON = "python312"`.
6. (2)가 `None`이고 (3)에서 매니페스트가 있으면, `pyproject.toml`을 먼저 보고
  매치되면 그 프로필을, 아니면 `package.json`을 본다.
7. 위 어디서도 결정이 나지 않으면 `polyglot` 이미지로 떨어지고
  `runtime_resolver.fallback` 경고 로그를 남긴다.

원격 패키지 spec(`npx @scope/server`, `uvx mcp-server-xyz` 등)이 인자로 들어온
경우에는 (3)의 게이트(`is_absolute() and exists()`)를 통과하지 못한다. 그래서
원격 패키지에서는 (4)·(5)의 매니페스트 기반 버전 결정이 동작하지 않고
`DEFAULT_NODE`/`DEFAULT_PYTHON`으로 떨어진다. 원격 패키지의 `engines.node`/
`requires-python`을 베이스 이미지 선택에 반영하는 경로는 현재 구현에 없다.

(6)에서 두 매니페스트가 같이 존재할 때 `pyproject.toml`을 먼저 보는 순서는
`runtime_resolver.py:222-235`에 그렇게 적혀 있다.

### 2.2.1 RuntimeResolver와 SourcePreflightInspector의 역할 분리

매니페스트를 읽는 코드는 두 모듈에 있고 서로 독립이다.

- RuntimeResolver는 베이스 이미지 결정에만 매니페스트를 읽고, 호스트 디스크의
파일만 본다.
- SourcePreflightInspector는 레시피 매칭용 의존성·메타데이터 수집에 매니페스트를
읽는다. 디스크에 없을 때는 `npm view` / PyPI JSON API로 같은 종류의 메타
데이터를 받아 온다.


|                                                  | 로컬(`/Users/.../my-server`) | 원격(`npx @scope/server`)      |
| ------------------------------------------------ | -------------------------- | ---------------------------- |
| 베이스 이미지 결정 시 `engines.node`/`requires-python` 반영 | ✅ RuntimeResolver          | ❌ DEFAULT로 폴백                |
| 레시피 매칭용 deps 수집                                  | ✅ 로컬 매니페스트 파싱              | ✅ `npm view` / PyPI JSON API |
| 소스 시그널(`channel:'chrome'` 등) 정규식 스캔              | ✅ 트리 워크                    | ❌ (소스 본문은 받지 않음)             |
| 의존성 컨테이너에 일괄 설치                                  | ✅ `_local_install_action`  | ❌ (npx/uvx가 런타임에 가져옴)        |


원격 패키지에서도 deps·패키지 이름은 단계 2에서 수집되어 단계 3의 레시피 매칭에
입력된다. 베이스 이미지 선택에는 들어가지 않는다.

### 2.3 컨테이너용 명령 정규화 (`_normalise_command`)

`server.command`가 절대 경로(예: `/Users/woojin/.venv/bin/python3`)면 basename
만 남긴다. 별칭은 다음과 같이 흡수된다.

- node 프로필: `nodejs` → `node`. 그 외에는 입력 그대로.
- python 프로필: `python`, `python3.X` → `python3`. 그 외에는 입력 그대로.
- polyglot 프로필: 입력 그대로.

결과 문자열이 컨테이너 이미지의 `$PATH`에서 해석 가능해야 단계 5.3의 `docker run <image> <command> <args>`가 동작한다. basename이 PATH에 없으면 컨테이너가
"command not found"로 죽고 단계 6의 stderr 학습 경로로 넘어간다.

---

## 3. 단계 2 — 사전 증거 수집 (`SourcePreflightInspector`)

### 3.1 역할

서버를 띄우기 전에 그 서버가 무엇을 의존하는지를 모아 둔다. 단계 3의 레시피
매칭(`node_deps_any`, `python_deps_any`, `source_signals_any`,
`package_name_any`)이 이 정보를 입력으로 받는다. 정보가 없어도 단계 3은
identity 토큰만으로 매칭을 시도하므로 분석이 멈추지는 않는다 — 다만 의존성·
패키지 이름에 묶인 게이트는 못 잡는다.

선제(proactive) 경로다. 반응(reactive) 경로인 stderr 학습(단계 5)과 짝을
이룬다.

### 3.2 세 가지 소스

`SourcePreflightInspector.inspect()`는 다음 순서로 시도하고, 먼저 신호를 주는
소스를 채택한다. 한 번의 분석에서 셋이 모두 돌지 않는다 — 로컬이 잡히면 원격은
보지 않는다.

#### (A) 로컬 매니페스트 — `_inspect_local_manifests`

`server.command`/`server.args` 중 호스트에 실재하는 절대 경로가 있을 때만
동작한다. 5단계까지 부모를 거슬러 올라가 `package.json` / `pyproject.toml` /
`requirements.txt` 중 하나라도 있으면 그 디렉터리를 프로젝트 루트로 본다.

- `package.json`에서 `dependencies`/`devDependencies`/`optionalDependencies`/
`peerDependencies`를 모두 모아 노드 의존성 맵을 만든다.
- `pyproject.toml`에서 `project.dependencies`,
`project.optional-dependencies.*`, `dependency-groups.*`,
`tool.poetry.dependencies`를 합쳐 파이썬 의존성 집합을 만든다.
- `requirements.txt`의 각 줄을 `_normalise_python_requirement`로 파싱해서
추가한다.
- `_scan_source_tree`가 소스 트리를 스캔한다. 최대 200개 파일, 파일당 256
KiB까지, `.git`/`node_modules`/`.venv` 등은 건너뛴다. `_SOURCE_SIGNAL_ PATTERNS`의 정규식에 매칭되는 게 있으면 source signal로 적재한다 — 예:
`channel: 'chrome'`이 있으면 `playwright.channel.chrome` 신호. 이 신호가
단계 3에서 Chromium 레시피와 Chrome 레시피를 가른다.

evidence가 만들어지면 `source="local-manifest"`로 태깅된다. 이 태깅이
`_local_install_action`(단계 3) 발동과 `PYTHONPATH`에 프로젝트 마운트를 잇는
분기(단계 4c)의 트리거다.

#### (B) 원격 npm 메타데이터 — `_inspect_remote_node`

로컬 매니페스트가 없고, 명령 basename이 `npx`/`pnpx`/`bunx`이고, `network_mode != "none"`일 때 발동한다.

1. `_extract_node_package_spec(server)`이 `args`에서 패키지 spec 하나를 뽑는다.
  `_NODE_SKIP_FLAGS`/`_NODE_VALUE_FLAGS`로 플래그·값을 건너뛰고 첫 번째 비
   플래그 인자를 spec으로 본다. 그 인자가 `.`나 `/`로 시작하면 로컬 경로로
   해석하고 `None`을 돌려 이 분기를 끈다.
2. 호스트에서 `npm view <spec> --json`을 서브프로세스로 실행한다. 30초 타임아웃,
  호스트에 `npm`이 없으면 `None`. 응답에는 published `package.json` 메타데이터
   가 들어 있다 — `name`, `version`, `dependencies`/`devDependencies`/
   `peerDependencies`/`optionalDependencies`. spec이 버전 범위면 npm이 매칭
   버전을 골라 그 버전의 메타데이터를 돌려준다.
3. 응답이 list면 마지막 원소를, dict면 그대로 사용한다.
  `_collect_node_dependencies`로 의존성을 정렬·튜플화한다.
4. `PreflightEvidence(source="npm-view:", manifest_path="npm registry
  (package.json metadata)", package_name=..., package_version=...,
   node_dependencies=...)`로 정규화한다.` manifest_path`는 라벨이며 실제 디스크
   경로가 아니다.

소스 본문은 받지 않는다 — tarball을 풀거나 GitHub를 보지 않는다. 따라서 이
분기에서 `source_signals`는 항상 비어 있다. 단계 3의 레시피는 `node_deps_any`/
`identity_tokens_any`/`stderr_tokens_any`/`package_name_any`로도 매치가 걸리도록
OR 게이트가 깔려 있어서 source signal 부재가 곧바로 매칭 실패로 이어지지는
않는다.

`package_name`/`package_version`이 채워지면 `package_name_any` 게이트가 활성
화된다. 예: `npx -y postgres-mcp@latest`로 띄우면 `npm view`가 `name: postgres-mcp`를 돌려주고, `postgres-mcp-sidecar` 레시피의 `package_name_any`
가 매치되어 사이드카가 붙는다.

`network_mode == "none"`이면 이 분기 전체가 스킵된다. evidence가 `None`이 되어
단계 3은 `identity_tokens`(명령/인자 텍스트)로만 매칭하게 된다. 주요 레시피들
이 `identity_tokens_any`를 함께 두는 이유다.

#### (C) 원격 PyPI JSON API — `_inspect_remote_python`

명령 basename이 `uvx`/`pipx`이고 `_extract_python_package_spec`이 args에서
패키지 spec을 뽑을 때 발동.

- `_python_spec_to_name`이 spec에서 순수 패키지 이름(버전 제약 제거)을 추출.
- `https://pypi.org/pypi/<name>/json`을 `urllib.request.urlopen`으로 받는다.
executor에 던져 비동기화, 15초 타임아웃.
- `info.name`/`info.version`/`info.requires_dist`를 뽑아
`_normalise_python_requirement`(소문자화, `_`→`-`, 환경 마커 제거)로
정규화한 집합을 만든다.
- `PreflightEvidence(source="pypi-api:<spec>", manifest_path="PyPI package metadata", python_dependencies=...)`로 정규화.

(B)와 마찬가지로 소스 본문은 받지 않으므로 `source_signals`는 비어 있다.

### 3.3 한계

- `engines.node`/`requires-python`은 evidence에 담기지 않는다.
`_collect_node_dependencies`/`_collect_pyproject_dependencies`는 의존성
필드만 본다. 단계 1의 RuntimeResolver도 원격 패키지에서는 이 값을 볼 수
없으므로(2.2 참고), 원격 npm 패키지가 `engines.node: ">=20 <22"`를 선언해도
본 시스템은 `DEFAULT_NODE = "node22"`로 띄운다.
- 원격 분기에서 `source_signals`는 항상 빈 frozenset이다. 소스 본문을 받지
않기 때문이다.
- `npm view`/PyPI API가 실패하면 (네트워크 오류, 타임아웃, `npm` 미설치 등)
inspect는 `None`을 돌려준다. evidence 없이 단계 3은 identity 토큰만으로
매칭한다.
- `npm view <spec>`이 spec 범위에서 고르는 버전과, 컨테이너 안 npx가 런타임에
실제로 받아 오는 버전이 반드시 같다는 보장은 없다 (그 사이에 publish가
발생했다면 다를 수 있다). 단계 3의 `_pin_playwright_version`만이 받아온
버전을 Dockerfile 라인에 핀 버전으로 고정한다. 그 외에는 메이저/마이너 일치 정도의
약한 보장만 갖는다.

### 3.4 결과물 — `PreflightEvidence`

```python
PreflightEvidence(
    source="local-manifest" | "npm-view:<spec>" | "pypi-api:<spec>",
    manifest_path="...",
    package_name=..., package_version=...,
    node_dependencies=( (name, version), ... ),
    python_dependencies=( "psycopg2", "fastapi", ... ),
    source_signals=( "playwright.channel.chrome", ... ),
)
```

`source` 필드의 의미가 단계 3에서 분기를 만든다. `"local-manifest"`일 때만
`_local_install_action`이 추가되어 evidence의 deps를 컨테이너 이미지에 깐다.
원격 패키지 러너 분기에서는 npx/uvx가 런타임에 가져오는 것을 전제로 한다
(다만 사이드카 모드에서는 그 가정이 깨지므로 `_remote_install_action`이 별도로
개입한다 — 4.5 참고).

evidence가 어떤 소스로도 만들어지지 않으면 `inspect()`는 `None`을 반환한다.
그 경우 단계 3은 `identity_tokens`와 `stderr_snippet`만으로 레시피를 매칭한다.

---

## 4. 단계 3 — 부트스트랩 계획 (`plan_bootstrap`)

### 4.1 `BootstrapPlan` / `BootstrapAction` 자료구조

`BootstrapPlan`은 `BootstrapAction`의 순서 있는 튜플과 사람이 읽는 `reason`
문자열로 구성된다. 각 `BootstrapAction`이 가질 수 있는 필드는 다음과 같다.

- `dockerfile_lines` — `FROM <base>` 뒤에 그대로 이어붙일 Dockerfile 라인.
- `env` — 런타임에 `docker -e KEY=VAL`로 주입할 환경변수 쌍.
- `services` — 사설 네트워크에 함께 띄울 사이드카 컨테이너 명세.
- `arg_rewrites` — `server.args`에 적용할 정규식 치환 규칙.
- `command_wrapper` — 서버 명령 앞에 끼울 셸 스크립트 경로.

`BootstrapPlan`의 파생 프로퍼티:

- `image_tag(base)` — `dockerfile_lines`가 있는 액션들의 `action_id`만 골라
SHA-256으로 해싱한 12자리를 `<base>-bootstrap-<hash>`로 붙인다. 사이드카·
arg 재작성·env-only 액션은 해시에 포함되지 않으므로, 그것들만 바뀐 경우
이미지 캐시가 그대로 재사용된다.
- `forced_runtime_env` — `services`를 가진 액션의 env만 모아 별도 dict로 반환.
단계 5의 `_merged_env`가 이 dict를 사용자 env 위에 덮어쓴다.

### 4.2 계획 구성 흐름

`plan_bootstrap(server, runtime, evidence, stderr_snippet)`은 다음을 차례로
실행해 결과 액션을 `tuple`로 합친다.

1. `RecipeRegistry.match(ctx)` — `builtin.yaml`의 매칭된 레시피를 `BootstrapAction`
  으로 변환 (Playwright 버전 핀 후처리만 적용).
2. `_local_install_action(evidence)` — evidence.source가 `local-manifest`일
  때만 액션을 반환.
3. `_remote_install_action(server, matched, stderr_snippet)` — 선제/반응
  조건 중 하나라도 충족되면 액션을 반환.

세 단계의 결과가 모두 비어 있으면 `None`을 반환한다. 그렇지 않으면 reason은
세 출처의 description을 쉼표로 이은 문자열.

### 4.3 레시피 매칭 (`RecipeRegistry`)

#### 4.3.1 매칭 컨텍스트

`_build_match_context()`가 다음 필드를 가진 `MatchContext`를 만든다.

- `runtime_image` — 단계 1에서 정한 이미지 태그.
- `node_deps`, `python_deps` — preflight가 모은 의존성 집합.
- `source_signals` — preflight가 소스 스캔으로 적재한 신호 집합.
- `identity_tokens` — `server.command`와 `server.args`를 소문자로 변환한 튜플.
- `stderr_snippet` — 직전 실패의 stderr 텍스트 (재시도 경로에서만 채워진다).
- `package_name` — preflight가 알아낸 패키지 이름 (소문자).

#### 4.3.2 매치 규칙

`_matches(recipe, ctx)`는 다음 순서로 평가한다.

AND 조건 (하나라도 false면 즉시 반환):

- `runtime_prefix` — `ctx.runtime_image`가 이 접두사로 시작해야 한다.
- `source_signals_none` — 지정된 신호 중 하나라도 `ctx.source_signals`에
있으면 false.
- `source_signals_any` — 지정되어 있다면 `ctx.source_signals`에 최소 하나는
있어야 한다.

OR 게이트: `any_of` 블록 중 하나가 `_block_matches`를 통과하면 매치. 블록 내부
에서는 다음 키가 OR로 평가된다.

- `node_deps_any` — `ctx.node_deps`와 교집합이 있으면 매치.
- `python_deps_any` — `ctx.python_deps`와 교집합이 있으면 매치.
- `identity_tokens_any` — `_bounded_match`(다음 절)로 토큰이 매치되면.
- `stderr_tokens_any` — `ctx.stderr_snippet`에 부분 문자열로 들어 있으면.
stderr는 경계 검사 없이 단순 substring으로 비교한다.
- `package_name_any` — `ctx.package_name`에 `_bounded_match`로 토큰이
매치되면.

`any_of`가 없고 OR 트리거 키가 `match` 블록 최상위에 적혀 있으면
`_top_level_block`이 그것을 단일 암시 블록으로 묶어 동일하게 평가한다.

AND 조건이 통과하고 `any_of`/암시 블록이 모두 비어 있으면 매치로 처리된다.

#### 4.3.3 경계 매칭 (`_bounded_match`)

`identity_tokens_any`와 `package_name_any`는 단순 substring이 아닌 경계
매치를 쓴다. `_bounded_match`는 needle 양쪽이 다음 문자 중 하나거나 문자열의
끝이어야 매치를 인정한다 (`_IDENTITY_BOUNDARY_CHARS`):

```
공백, /, @, :, 탭
```

`-`, `_`는 경계가 아니므로 `postgres-mcp`는 한 컴포넌트로 취급된다. `.`도
경계가 아니므로 `postgres-mcp.json`이라는 문자열은 `postgres-mcp`에 매치
되지 않는다.

#### 4.3.4 `builtin.yaml`에 등록된 레시피 분류

**(i) Playwright 브라우저 설치**

- `playwright-node-chrome` — `runtime_prefix=mcp-sandbox-node` AND
`source_signals_any` 중 하나(`playwright.channel.chrome` 등) AND
(`node_deps_any`에 playwright 계열 OR identity 토큰에 playwright-mcp).
매치 시 `npx -y playwright install --with-deps chrome` 라인과
`PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`를 추가.
- `playwright-node-chromium` — 같은 패키지/identity 조건이지만
`source_signals_none`에 Chrome 신호를 두어 chrome 변형과 상호 배제. 매치 시
Chromium 번들을 설치.
- `playwright-python-chrome`, `playwright-python-chromium` — 동일한 구조의
파이썬 대응.
- `_pin_playwright_version()`이 후처리로 evidence의 Playwright 버전을 읽어
`npx -y playwright install` → `npx -y playwright@<version> install`로 치환.
파이썬 쪽은 `pip install playwright` → `pip install playwright==<version>`.

**(ii) `system-chrome`**

`puppeteer-core` / `chrome-launcher` / `chrome-remote-interface` 계열 서버는
`/opt/google/chrome/chrome` 경로에 브라우저 바이너리를 기대한다. 이 레시피는:

- amd64이면 Google의 apt 저장소를 등록하고 `google-chrome-stable` 설치를
시도.
- arm64이면 Debian `chromium`을 설치하고 `/opt/google/chrome/chrome`에 심볼릭
링크를 만든다.
- `CHROME_PATH`, `PUPPETEER_EXECUTABLE_PATH`를 위 경로로 설정.

트리거는 (a) deps에 `puppeteer-core`/`chrome-launcher`/`chrome-remote-interface`
가 있는 경우, 또는 (b) 재시도 경로에서 stderr에 "could not find chrome"/
"could not find google chrome executable"/`/opt/google/chrome/chrome`이 들어
있는 경우.

**(iii) 백엔드 사이드카**

`postgres-mcp-sidecar`, `mysql-mcp-sidecar`, `redis-mcp-sidecar`,
`mongodb-mcp-sidecar`는 같은 구조를 따른다.

- 트리거: `identity_tokens_any` 또는 `package_name_any`에 매치.
- `services`에 alias/image/env/health_cmd/port/startup_timeout_sec 명세.
- `env`에 다양한 이름의 connection string을 적어 두어 어느 키를 읽든 사이드카
로 향하게 한다. 예: postgres-mcp-sidecar는 `DATABASE_URL`, `DATABASE_URI`,
`POSTGRES_URL`, `POSTGRES_URI`, `POSTGRES_CONNECTION_STRING`,
`PG_CONNECTION_STRING`, `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`,
`PGDATABASE`.
- `arg_rewrites`에 connection-string용 정규식과 치환 문자열.

`runtime_prefix`를 두지 않아 node/python 어느 베이스에서도 매치된다.

`postgres-mcp-python-install`은 별도 레시피로 `pip install postgres-mcp`를
이미지에 미리 설치한다. 노드 변형은 동일한 레시피가 없고 `_remote_install_action`이
처리한다 (4.5 참고).

**(iv) `puppeteer-node`**

deps에 `puppeteer`/`puppeteer-core`가 있거나 identity에 `puppeteer`가 있으면
`npx -y puppeteer browsers install chrome` 라인을 추가.

#### 4.3.5 출력

`RecipeRegistry.match`는 매치된 액션을 레시피 정의 순서대로, `action_id`로 dedup
하여 리스트로 돌려준다. `plan_bootstrap`은 이 리스트를 `BootstrapAction`으로
복제하고 `dockerfile_lines`에 `_pin_playwright_version` 후처리를 적용한다.

### 4.4 로컬 의존성 일괄 설치 (`_local_install_action`)

`evidence.source == "local-manifest"`일 때만 액션을 반환. 로컬 서버는 컨테이너
인터프리터로 실행되므로 호스트 venv가 의미를 갖지 못하고, manifest의 deps를
이미지에 설치해야 import 에러 없이 부팅된다.

- 파이썬: `pip install --no-cache-dir <spec1> <spec2> …`. 각 spec은
`shlex.quote`로 묶고 줄 끝에 `|| true`를 붙여 일부 실패가 다른 설치를 막지
않도록 한다.
- 노드: `npm install -g <name1> <name2> …`. 버전 범위는 무시하고 이름만 사용
한다. `^1.2`, git URL, `workspace:*` 등 npm의 다양한 버전 표기가 깔끔히
install spec으로 매핑되지 않기 때문. 함께 `NODE_PATH=/usr/local/lib/node_modules`
를 env에 추가하여 `node server.js` 같은 평평한 실행이 글로벌 설치본을
`require()`할 수 있게 한다.

단계 5의 `_build_docker_cmd`는 evidence가 `local-manifest`이고 절대경로 인자로
인한 프로젝트 마운트가 존재하면 `PYTHONPATH`에 그 마운트 경로를 append한다.

### 4.5 사이드카 종속 원격 패키지의 선제 설치 (`_remote_install_action`)

#### 4.5.1 동기

`npx @modelcontextprotocol/server-postgres` 같은 패키지 러너 서버는 일반
bridged 네트워크에서는 런타임에 레지스트리에서 패키지를 받아 온다. 그러나
매칭된 레시피가 `services`를 포함하면 단계 4b에서 `docker network create --internal`로 호스트·외부 라우팅이 끊긴 사설 네트워크에 컨테이너가 합류한다.
이 상태에서는 `npx`의 레지스트리 fetch가 DNS 단계에서 실패한다(`getaddrinfo EAI_AGAIN`).

#### 4.5.2 발동 조건

다음 중 하나가 참이면 액션을 만든다:

- `matched`(이번 plan에서 이미 매치된 레시피들) 중 `services`를 가진 것이
하나라도 있다.
- `_is_registry_fetch_failure(stderr_snippet)`이 참이다. 이 함수는
`registry.npmjs.org`, `pypi.org`, `eai_again`, `getaddrinfo`, "temporary
failure in name resolution", "name or service not known" 중 하나가 stderr에
포함되어 있을 때만 참을 돌려준다.

`_extract_node_package_spec` 또는 `_extract_python_package_spec`이 spec을
뽑아내지 못하면 액션은 만들어지지 않는다.

#### 4.5.3 노드 패키지 처리 — prebuilt node_modules + shim

npm 10의 `npx <pkg>`는 글로벌 설치된 패키지에 대해서도 `registry.npmjs.org`에
manifest probe를 보낸다. `--internal` 네트워크에서는 그 probe가 DNS 단계에서
실패하므로 단순 `npm install -g` 만으로는 부족하다.

대신 cwd의 `node_modules`에 패키지를 두면 npx의 로컬 해석 경로가 매치되어
probe가 발생하지 않는다. 이 액션은 다음 두 단계를 이미지에 굽는다.

1. `/opt/mcp-prebuilt`에 `npm install --no-audit --no-fund --no-package-lock
  `을 실행해 미리 받아 둔다.
2. `/usr/local/bin/mcp-prebuilt-shim` 스크립트를 만든다. 내용:
  "cwd에 `node_modules`가 없으면 `/opt/mcp-prebuilt/.`를 cwd로 복사하고
   `exec "$@"`".

런타임에는 `command_wrapper=("/usr/local/bin/mcp-prebuilt-shim",)`로 이 shim이
`npx …` 앞에 prepend된다. 단계 5.3에서 패키지 러너의 cwd는 빈 tmpfs `/tmp`로
설정되므로 매 컨테이너마다 깨끗한 상태에서 복사가 수행된다. `NPM_CONFIG_PREFER_OFFLINE=true`도
env에 추가된다.

#### 4.5.4 파이썬 패키지 처리

`pip install --no-cache-dir <spec>`을 이미지에 추가한다. `uvx`/`pipx`가
ephemeral venv를 만들면서 PyPI에 재접속하는 동작은 이 액션으로 막지 못한다.
현재 코드 주석은 이 부분을 follow-up으로 남겨 두었다.

#### 4.5.5 중복 방지

`matched` 액션들의 `dockerfile_lines` 중 어느 줄에라도 spec 문자열이 들어
있으면 generic 액션은 반환되지 않는다. `action_id`는 spec + dockerfile_lines

- env_pairs + command_wrapper의 repr을 함께 해싱하므로, shim 패턴이 바뀌면
이전 빌드 캐시가 자동으로 무효화된다.

---

## 5. 단계 4 — 실행 (`Sandbox.start`)

### 5.1 부트스트랩 이미지 준비 (`_prepare_bootstrap_image`)

`Sandbox.start()`의 첫 단계. `use_docker`가 false면 즉시 반환한다.

순서:

1. `_resolve_runtime()`으로 베이스 런타임 결정 (단계 1).
2. `SourcePreflightInspector.inspect()`로 evidence 수집 (단계 2).
3. `plan_bootstrap(server, runtime, evidence, stderr_snippet=self._prereq_hint)`
  호출 (단계 3).
4. `self._prereq_hint`가 비어 있지 않으면 추가로
  `_apt_bootstrap_action(prereq_hint)`을 돌려 plan에 합친다.
5. plan이 `None`이면 베이스 이미지를 그대로 사용한다.
6. `plan.has_image_changes`가 false이면 (사이드카·env-only인 경우) 이미지
  빌드를 건너뛰고 `_bootstrap_image = None`으로 둔다. env는 단계 5.3에서
   `docker -e`로 주입된다.
7. `image_tag(runtime.image)`로 결정된 태그가 이미 존재하면 (`docker image
  inspect` 성공) 재사용한다.
8. 없으면 임시 디렉터리에 Dockerfile을 쓰고 (`render_bootstrap_dockerfile`이
  `FROM <base>` + 액션의 `dockerfile_lines` + 끝에 `ENV` 라인을 생성) `docker  build -t <tag>`를 실행. 빌드가 실패하면 `_bootstrap_image = None`으로 두고
   경고 로그만 남긴 채 계속 진행한다.

### 5.2 사이드카 부팅 (`_start_sidecars`)

`plan.services`가 비어 있으면 건너뛴다. 비어 있지 않으면:

1. `docker network create --internal mcp-net-<uuid>`. `--internal` 플래그는
  네트워크와 호스트·외부 라우팅을 차단한다. 이 플래그가 없으면 컨테이너가
   `host.docker.internal`을 통해 호스트의 DB에 도달할 수 있다.
2. 각 서비스마다 `docker run -d --rm --name mcp-svc-- --network
   --network-alias  [-e ...] `를 실행한다.
3. `health_cmd`가 지정된 경우 `_wait_for_sidecar_health`가 1초 간격으로
  `docker exec <container> <health_cmd>`를 호출하여 0이 반환되거나
   `startup_timeout_sec`이 경과할 때까지 폴링한다.
4. `_inspect_sidecar_ip`로 컨테이너 IP를 받아 `_sidecar_ips`에 저장한다. R1
  스캐너가 RFC1918 SSRF 판정을 할 때 이 IP 목록을 화이트리스트로 사용한다.

`network_name`이 설정되면 `has_sidecars`가 true가 되고, 분석 측이 RFC1918
차단 휴리스틱을 비활성화한다 (해당 네트워크의 모든 트래픽이 RFC1918이지만
호스트 외부 도달이 차단된 상태이므로 SSRF의 의미가 달라진다).

### 5.3 `docker run` 명령 조립 (`_build_docker_cmd`)

**(a) arg 재작성** — `_apply_arg_rewrites`가 `plan.arg_rewrites` 규칙을 순서
대로 `re.sub`로 적용. 정규식이 부정확하면 그 규칙만 건너뛰고 경고 로그.
원본 arg와 결과는 `_redact_secrets_in_uri`로 마스킹되어 로그에 찍힌다.

**(b) 절대경로 arg의 마운트 매핑** — (a) 이후 인자 중 `is_absolute() and exists()`인 것에 대해:

1. `_guess_mount_root(path)` — 경로(파일이면 부모)부터 최대 5단계까지 부모를
  거슬러 올라가 `package.json`, `pyproject.toml`, `setup.py`, `setup.cfg`,
   `Cargo.toml`, `go.mod`, `.git` 중 하나가 있는 디렉터리를 마운트 루트로
   삼는다. 없으면 경로 자신.
2. 그 루트를 `/mcp-server-N`에 read-only로 마운트한다. 동일 루트가 여러 인자
  에서 등장하면 N을 공유한다.
3. arg는 루트 기준 상대경로를 컨테이너 마운트 경로에 이어붙인 문자열로 치환
  된다.

(a) → (b) 순서가 고정되어 있어, 사용자 인자에 들어 있던 connection string은
(a)에서 사이드카 URL로 치환된 다음에야 (b)가 절대경로 판정을 한다. 그래서
URL이 마운트 대상으로 잘못 인식되는 경로가 없다.

**(c) 도커 옵션**

- `-i --rm --name <generated>`.
- `--memory <sb.memory_limit>` (기본 `512m`), `--cpus <sb.cpu_limit>` (기본
0.5), `--pids-limit 512`.

**(d) 격리 강도**

`sb.isolation == "strict"` (기본):

- `--read-only`.
- `--tmpfs /tmp:size=...,exec(?)`. 패키지 러너(`uv`, `uvx`, `npx`, `pnpx`,
`bunx`, `pipx`)이면 `size=512m,exec`. 그 외에는 `size=100m`만(noexec 기본).
패키지 러너는 cwd 또는 `/tmp/.npm/_npx`에 venv·바이너리를 깔고 실행하므로
noexec일 때 `Permission denied`가 발생한다. 100 MB는 typical 파이썬 서버의
uv 캐시에 부족해서 ENOSPC가 발생하므로 512 MB로 늘렸다.
- `--security-opt no-new-privileges`, `--cap-drop ALL`.
- `sysmon_enabled == True`이면 `--cap-add SYS_PTRACE`.

`sb.isolation == "permissive"`: `--cap-add ALL`, `--security-opt seccomp=unconfined`, `--security-opt apparmor=unconfined`.

**(e) 네트워크**

- 사이드카 네트워크가 설정되었으면 `--network <name>`.
- 아니면 `network.mode`에 따라 `--network none` 또는 `--network bridge`.

**(f) env 머지** — `_merged_env`가 다음 순서로 dict를 누적한다.

1. `merged_bootstrap_env(plan)` — plan 액션의 env.
2. `server.env`.
3. `self._env_override`.
4. `plan.forced_runtime_env` — `services`를 가진 액션의 env. 마지막에 적용되어
  사용자 env를 덮어쓴다. 덮어쓰기가 발생하면 `sandbox.env_redirected_to_sidecar`
   경고 로그가 마스킹된 값과 함께 기록된다.

evidence가 `local-manifest`이고 `extra_mounts`가 비어 있지 않으면
`PYTHONPATH`에 첫 마운트(`/mcp-server-0`)가 append된다.

env 키가 `secret|token|api[_\-]?key|password|passwd|credential` 정규식에
매치되면 `sandbox.env_secret_exposure` 경고 로그를 남긴다 (env 전달은 막지
않는다).

머지 결과는 각 항목이 `-e KEY=VAL`로 펼쳐진다.

**(g) 허니팟 마운트** — `honeypot_dir`가 지정되어 있으면 `<dir>:/home/user:rw`
를 mount한다.

**(h) 작업 디렉터리와 워크스페이스 마운트**

- 패키지 러너이고 `extra_mounts`가 비어 있는 경우: `-w /tmp`로 설정하고 호스트
cwd는 마운트하지 않는다. `HOME=/tmp`와 `XDG_CACHE_HOME=/tmp/.cache`가
env에 없을 때만 추가한다. 호스트 cwd를 마운트하지 않는 것은, 호스트 cwd가
분석기 자신의 repo일 경우 `.venv/`가 컨테이너에서 read-only로 보여 uv가 실패
하는 사례 때문이다.
- 그 외: 호스트 cwd를 `/workspace`에 mount하고 `-w /workspace`. mount 모드는
`sb.isolation == "permissive"`이면 `rw`, 아니면 `ro`.

**(i) 추가 마운트** — (b)에서 만든 `extra_mounts`는 모두 `:ro`로 추가한다.

**(j) HTTP 포트** — `server.transport == "http"`이고 `http_port`가 있으면
`-p 127.0.0.1:<port>:<port>/tcp`. 다른 인터페이스에는 노출하지 않는다.

**(k) 이미지·command·args**

- 이미지는 `_bootstrap_image`가 있으면 그것을, 아니면 `runtime.image`.
- plan 액션 순서대로 `command_wrapper`를 풀어 cmd에 추가.
- `runtime.command` (단계 1에서 정규화된 명령).
- (a)·(b)를 거친 `remapped_args`.

최종 `cmd` 리스트는 `asyncio.create_subprocess_exec(*cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, limit=2**25)`로 실행된다. `limit`이 32 MiB인 이유는
fuzz 페이로드가 10 MB까지 가는 경우가 있고 서버가 그 입력을 에러 메시지에
echo하면 한 줄이 그 크기까지 늘어날 수 있기 때문이다.

### 5.4 stderr 수집

`_drain_stderr` 태스크가 비동기로 stderr를 한 줄씩 읽어 `self._stderr_lines`에
적재하고 동시에 `sandbox.server_stderr` 로그로도 흘린다. 단계 6의 재시도가
이 버퍼를 입력으로 받는다.

### 5.5 즉시 종료 감지

`start()`는 spawn 후 `await asyncio.sleep(0.3)`을 건다. 그 시점에 `returncode`
가 `None`이 아니면 서버가 spawn 직후에 종료된 것으로 본다. 정상 MCP 서버는
stdio 루프를 돌며 살아 있어야 한다.

`_bootstrap_retry_done`이 false이면 한 번에 한해 단계 6의 재시도를 시도한다.
true이거나 재시도가 실패하면 `RuntimeError`로 stderr 내용과 함께 호출자에게
보고한다.

---

## 6. 단계 5 — stderr 기반 재시도

### 6.1 두 가지 액션 생성

`_retry_bootstrap_from_stderr(stderr)`가 다음 두 단계로 추가 액션을 만든다.

**Layer 1 — 레시피 stderr 매칭**

`plan_bootstrap(..., stderr_snippet=stderr)`을 다시 호출한다. `MatchContext. stderr_snippet`이 채워져 있어 첫 실행에서 매치되지 않았던 `stderr_tokens_any`
조건이 이번에는 매치될 수 있다. 예: 첫 실행 stderr에 "chromium distribution
'chrome' is not found"가 있으면 `playwright-node-chromium` 레시피가 새로
매치되어 Chromium 설치 라인이 추가된다.

**Layer 2 — apt 패키지 추정 (`_apt_bootstrap_action`)**

`_apt_packages_from_stderr(stderr)`가 다음 정규식으로 패키지 후보를 모은다.

1. `_RE_CMD_NOT_FOUND` — `X: command not found` / `X: not found` / `X: No
  such file or directory`. 매치된 X가` _COMMAND_TO_APT`에 있으면 그 apt  패키지를 추가한다 (`curl`→`curl`,` convert`→`imagemagick`,` pdftotext `→`poppler-utils`,` psql`→`postgresql-client` 등).
2. `_RE_LIB_NOT_FOUND` — `cannot open shared object file: libY.so.N` /
  `error while loading shared libraries: libY.so.N`. base 이름이
   `_LIB_TO_APT`에 있으면 그 매핑을 사용. 매핑이 없으면 `libY.so.N` →
   `libYN`(예: `libfoo.so.3` → `libfoo3`) 규칙을 적용.
3. `_RE_CMD_NF_BARE`, `_RE_SPAWN_ENOENT` — 큐레이션 맵에 없는 명령 X에 대해
  "패키지 이름 == 명령 이름" 가정으로 X 자체를 후보로 넣는다. 단
   `_NOT_A_PACKAGE`(인터프리터·패키지 러너 셋)는 제외한다.

생성된 Dockerfile 라인은 `( apt-get install -y --no-install-recommends <p> || true )`로 감싸진다. 한 패키지의 설치 실패가 같은 RUN 내 다른 설치를 막지
않는다.

### 6.2 새 액션 선별

`current_ids`(기존 plan의 `action_id` 집합)와 비교하여, Layer 1·2에서 생성된
액션 중 새 id를 가진 것만 `extra_lines`에 모은다. 새 id가 하나도 없으면 재시도
하지 않고 `sandbox.bootstrap.retry_skip` 로그를 남긴다.

### 6.3 이미지 재빌드 (`_build_dynamic_image`)

base는 기존 `_bootstrap_image`(있다면) 또는 `runtime.image`. extra Dockerfile
라인과 env로 `<base>-retry-<hash>` 태그를 만든다. hash는 base와 라인을 합쳐
SHA-256. 같은 태그가 이미 존재하면 빌드를 건너뛴다. 빌드가 실패하면 `None`을
반환하고 재시도를 포기한다.

### 6.4 재실행

기존 stderr drain task를 cancel하고, 살아 있는 프로세스가 있으면 kill한 뒤
새 이미지로 docker run cmd를 다시 만들어 spawn한다. 0.3초 게이트를 다시 확인
한다. 이번에도 returncode가 None이 아니면 `RuntimeError`를 던진다 — 자동
재시도는 한 번뿐이다.

### 6.5 `prereq_hint`와의 결합

호출자가 `Sandbox(..., prereq_hint=<text>)`로 sandbox를 생성하면, 단계 5.1의
(4)에서 본 것처럼 첫 spawn *전에* `_apt_bootstrap_action(prereq_hint)`이 plan
에 합쳐진다. 즉 이전 실행에서 얻은 stderr 단서를 다음 실행의 빌드 단계로
앞당겨 쓸 수 있어, 동일한 의존성 문제로 두 번 죽지 않는다.

---

## 7. 종료 (`Sandbox.stop`)

1. stderr drain task를 cancel.
2. `terminate()` 후 최대 10초 대기. 그래도 살아 있으면 `kill()`.
3. exit code가 `0`/`-15`/`-9`/`None`이 아니면 `sandbox.abnormal_exit` 경고
  로그.
4. `_stop_sidecars`:
  - 각 사이드카에 `docker kill`. `--rm`이므로 자동 삭제.
  - 0.3초 대기 후 `docker network rm <network_name>`. 실패하면 경고만.

이미지 캐시는 의도적으로 남는다 (다음 실행에서 docker build 비용을 줄이기 위해).
컨테이너·네트워크는 모두 제거된다.

---

## 8. 안전 장치 요약

- 시크릿 로그 마스킹: `_redact_secrets_in_uri`가 arg/env URI에서 `user:pass@`
→ `***:***@` 치환.
- 시크릿 env 경고: env 키가 `secret|token|api[_\-]?key|password|passwd| credential`에 매치되면 `sandbox.env_secret_exposure` 경고 로그.
- `forced_runtime_env`: `services`를 가진 액션의 env가 사용자 env를 마지막에
덮어쓴다.
- arg rewrite → path remap 순서 고정: 사이드카 URL 치환이 절대경로 마운트 판정
보다 먼저 일어난다.
- `--internal` 네트워크: 사이드카 모드에서 호스트·외부 라우팅 차단.
- 패키지 러너의 호스트 cwd 비-마운트: 분석기 자신의 `.venv` 등이 컨테이너에
노출되지 않는다.
- best-effort 설치: `apt-get install ... || true`, `pip install ... || true`,
`npm install -g ... || true`. 일부 spec 실패가 분석 전체를 막지 않는다.
- 이미지 해시 범위: 사이드카·arg 재작성은 `image_tag` 해시에 포함되지 않는다.
그것들만 바뀌면 이미지 캐시가 재사용된다.
- `action_id` 해시 범위: `apt:` 액션은 패키지 목록 해시이므로 같은 누락이
재발해도 dedup된다. `remote-install-` 액션은 (spec, dockerfile_lines,
env_pairs, command_wrapper)의 repr 해시이므로 shim 패턴 변경 시 캐시가
무효화된다.
- R1 휴리스틱 전환: `has_sidecars`가 true이면 분석 측이 RFC1918 차단 휴리스틱을
비활성화한다. `sidecar_ips`는 화이트리스트로 사용된다.

---

## 9. 데이터 흐름 요약

```
ServerConfig                         SandboxConfig
   │                                       │
   │  resolve()                            │
   ▼                                       │
ResolvedRuntime ─────────────────┐         │
   │                              │        │
   │  inspect()                   │        │
   ▼                              │        │
PreflightEvidence ────────┐       │        │
       (deps + signals)   │       │        │
                          ▼       ▼        │
                  plan_bootstrap()         │
              (Recipes + local + remote)   │
                          │                │
                          ▼                │
                    BootstrapPlan          │
                  ┌───────┴─────────┐      │
                  │  Dockerfile     │      │
                  │  lines + env    │──▶ docker build → <image>-bootstrap-<hash>
                  │  services       │──▶ --internal network + 사이드카
                  │  arg_rewrites   │──▶ docker run 인자 치환
                  │  command_wrapper│──▶ shim 삽입
                  └─────────────────┘      │
                                           ▼
                                  docker run -i …
                                           │
                                  0.3s alive check
                                  ├─ ok  → stdio 채널 사용
                                  └─ die → stderr →
                                          ├─ recipe(stderr_tokens) 매칭
                                          └─ apt heuristic
                                          → patch image (한 번만)
                                          → respawn
```

---

## 10. 책임 분담 요약

- `runtime_resolver.py` — 베이스 이미지와 컨테이너용 명령 결정.
- `bootstrap.py` — 의존성·메타데이터 수집과 그 위에서 만들어지는 액션 plan.
- `recipes.py` + `builtin.yaml` — plan 생성에 쓰이는 매칭 규칙과 액션 정의.
- `sandbox.py` — plan을 받아 이미지 빌드·사이드카 부팅·`docker run`을 수행하고
즉시 종료 시 stderr 기반 1회 재시도.

새 MCP 서버 클래스 지원은 일반적으로 `builtin.yaml`에 레시피를 추가하는
변경으로 끝난다. 시스템 패키지 누락 같은 저수준 문제는 단계 6의 apt 휴리스틱이
stderr를 통해 best-effort로 처리한다.