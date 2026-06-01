# 정적 분석의 원격 패키지 타볼 수신 — `minos scan --target browsermcp` 사례

이 문서는 사용자가 원격 npm 패키지로 등록된 MCP 서버를 스캔할 때, 정적 분석
단계가 그 패키지의 타볼을 호스트로 받아 풀고 분석해서 환경 스냅샷을 만드는
과정을 실제 실행 결과와 함께 정리한 것이다.

대상 명령:

```
minos scan --target browsermcp
```

`browsermcp`는 보통 `npx @browsermcp/mcp@latest` 형태로 실행되는 원격 패키지다.
로컬 디스크에 소스가 없으므로, 정적 분석은 레지스트리에서 타볼을 직접 받아
분석한다.

---

## 0. 이 단계가 끼는 위치

```
minos scan --target browsermcp
        │
        ▼
[정적] collect_environment_snapshot(server)
        │   ← 이 문서가 다루는 부분
        │   1. 명령이 npx → 원격 npm 패키지로 판단
        │   2. 레지스트리에서 타볼 URL 조회
        │   3. 타볼 다운로드 + 압축 해제
        │   4. 풀린 트리에서 매니페스트·시그널 추출
        │   → EnvironmentSnapshot 반환
        ▼
[동적] run_analysis(..., environment_snapshot=snapshot)
        │   스냅샷을 받아 베이스 이미지·의존성을 첫 시도에 맞춤
        ▼
[정리] snapshot_cleanup()  ← 받아 푼 임시 디렉터리 삭제
```

타볼 수신은 정적 단계의 진입점(`static/runner.py`)이 원격 패키지 분기로
들어갔을 때 일어난다. 흐름:

1. 진입점이 명령 basename(`npx`)을 보고 원격 노드 패키지로 분류.
2. 인자에서 패키지 spec(`@browsermcp/mcp@latest`)을 추출.
3. 타볼 수신 모듈(`static/tarball_fetcher.py`)을 호출.
4. 받아 푼 디렉터리를 소스 분석기(`static/source_analyzer.py`)에 넘김.
5. 결과를 환경 스냅샷으로 정규화.

---

## 1. 타볼 수신 단계별 동작

타볼 수신 모듈은 호스트의 `npm`/`pip` 없이 순수 표준 라이브러리만으로 동작한다.
npm 공개 레지스트리와 PyPI는 둘 다 인증 없이 메타데이터·아카이브를 제공한다.

### 1.1 패키지 spec 분해

`@browsermcp/mcp@latest`를 이름과 버전 힌트로 나눈다.

- 스코프 패키지는 `@`로 시작하므로, 버전 구분자는 *두 번째* `@`를 찾는다.
- 결과: 이름 `@browsermcp/mcp`, 버전 힌트 `latest`.

### 1.2 레지스트리 메타데이터 조회

이름을 URL 인코딩해서 (`@browsermcp%2Fmcp`) 레지스트리 메타데이터 주소를 만든다.

```
GET https://registry.npmjs.org/@browsermcp%2Fmcp
```

응답에는 모든 발행 버전(`versions`)과 dist-tag 맵(`dist-tags`)이 들어 있다.

### 1.3 버전 해석 — dist-tag vs 실제 버전

여기에 함정이 하나 있다. `@latest`의 `latest`는 *버전 번호가 아니라 dist-tag*다.
`versions` 맵의 키는 `0.1.3` 같은 실제 버전 번호뿐이라서, `latest`로 직접
색인하면 실패한다. npm과 npx도 `@latest`를 태그로 취급해 먼저 해석한다.

그래서 버전 힌트는 다음 순서로 해석한다.

1. 힌트가 `versions`의 키이면 그대로 실제 버전으로 사용.
2. 아니면 `dist-tags`에서 그 이름의 태그를 찾아 실제 버전으로 변환.
   (`latest` → `0.1.3`)
3. 힌트가 없으면 `dist-tags.latest`를 사용.

> 이 처리는 첫 구현에서 누락되어 있었고, 실제로 `@browsermcp/mcp@latest`를
> 받으려다 "version 'latest' not present" 오류로 실패했다. 그 후 dist-tag 해석을
> 추가하여 수정했다.

### 1.4 타볼 다운로드 + 안전 압축 해제

해석된 버전 메타데이터에서 타볼 URL을 꺼낸다.

```
https://registry.npmjs.org/@browsermcp/mcp/-/mcp-0.1.3.tgz
```

이걸 임시 디렉터리에 내려받아 압축을 푼다. 압축 해제 시 각 멤버의 정규화된
경로가 대상 디렉터리를 벗어나면(예: 악의적 `../` 항목) 그 멤버는 건너뛴다 —
임의의 공개 패키지를 다루므로 경로 탈출 방어가 필요하다.

npm 타볼은 관습적으로 내용물을 `package/` 디렉터리로 감싸므로, 풀린 위치에서
`package/`가 있으면 그것을 실제 루트로 삼는다.

---

## 2. browsermcp 실제 실행 결과

위 흐름으로 `@browsermcp/mcp@latest`를 실제로 받아 분석한 결과:

```
=== SNAPSHOT ===
origin       : extracted-tarball
coverage     : full
package      : @browsermcp/mcp 0.1.3
engines.node : None
node_deps    : @modelcontextprotocol/sdk ^1.8.0, ws ^8.18.1, zod ^3.24.2,
               commander ^13.1.0, zod-to-json-schema ^3.24.3, (+ devDeps)
signals      : []
tarball url  : https://registry.npmjs.org/@browsermcp/mcp/-/mcp-0.1.3.tgz
extracted to : /var/folders/.../mcp-static-npm-XXXX/extracted/package
tree files   : ['README.md', 'dist', 'package.json']

=== DYNAMIC DECISION (스냅샷이 주도) ===
image : mcp-sandbox-node22
reason: node command 'npx' → node22
evidence.source: extracted-tarball:@browsermcp/mcp
```

### 2.1 받은 패키지의 실제 매니페스트

```json
{
  "name": "@browsermcp/mcp",
  "version": "0.1.3",
  "type": "module",
  "bin": { "mcp-server-browsermcp": "dist/index.js" },
  "files": ["dist"],
  "scripts": {
    "build": "tsup src/index.ts --format esm && shx chmod +x dist/*.js",
    "prepare": "npm run build"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.8.0",
    "commander": "^13.1.0",
    "ws": "^8.18.1",
    "zod": "^3.24.2",
    "zod-to-json-schema": "^3.24.3"
  }
}
```

### 2.2 시그널이 비어 있는 이유 — 이 패키지는 브라우저를 띄우지 않는다

타볼을 풀어 보면 파일이 `README.md`, `package.json`, `dist/index.js` 셋뿐이다.
`dist/index.js`는 `tsup`으로 번들된 약 20 KB짜리 단일 파일이다 (원본 `src/`는
`files` 필드가 `dist`만 포함하므로 발행 타볼에 없다).

처음에는 이 빈 시그널을 "번들된 배포물이라 매치가 안 된 것"으로 봤는데, 실제로
확인해 보니 두 가지 점에서 그 설명은 틀렸다.

1. 이 번들은 **압축(minify)되지 않았다.** import·함수명·포맷이 모두 살아 있어
   정규식이든 AST 분석이든 정상적으로 읽을 수 있다 (2.4 참고).
2. 번들 안에 `chrome`/`chromium`/`playwright`/`puppeteer`/`channel` 문자열이
   **0회** 등장한다. browsermcp는 자체적으로 브라우저 바이너리를 띄우는 서버가
   아니라, 웹소켓으로 사용자의 기존 브라우저(브라우저 확장)에 붙는 방식이다.
   그래서 브라우저 실행 시그널이 애초에 존재하지 않는다.

즉 빈 시그널 집합은 누락이 아니라 *정확한 결과*다. 이 패키지에는 그 신호의
근거가 되는 코드가 없다.

(번들된 배포물 한계 자체는 여전히 실재한다 — 다만 그건 *압축까지 된* 패키지에
해당하고, 이 패키지는 거기에 해당하지 않는다. 2.4에서 구분한다.)

### 2.3 베이스 이미지가 node22로 결정된 이유

이 패키지의 매니페스트에는 `engines.node` 필드가 없다. 그래서 런타임 결정기는
스냅샷에서 노드 버전 제약을 얻지 못하고 기본값 node22로 떨어진다. 만약 매니페스트
에 `engines.node`가 있었다면(예: `>=20 <22`) 스냅샷이 그 값을 담고, 결정기가
첫 시도에 node20을 골랐을 것이다.

### 2.4 그래서 이 타볼에 시맨틱 그레프를 돌릴 수 있는가

돌릴 수 있고, 유용하다. 받은 `dist/index.js`를 실제로 열어 보면:

- 743줄, 평균 줄 길이 28자. 압축된 코드 특유의 "한 줄에 수천 자"가 아니다.
- `import { StdioServerTransport } from "@modelcontextprotocol/sdk/..."`,
  `import { WebSocket } from "ws"`, `function createSocketMessageSender(ws)`
  처럼 import 바인딩·함수명·구조가 원본 그대로 보존되어 있다.
- 모듈 경계마다 `// src/index.ts` 같은 주석까지 남아 있다.

시맨틱 그레프는 텍스트가 아니라 AST 위에서 동작하므로 이렇게 읽히는 번들에서는
위험 API 호출 탐지, taint 추적이 거의 원본 수준으로 작동한다. 실제로 이 번들에
`child_process` 참조가 1회 있어 탐지 대상이 존재한다.

핵심 구분:

- **번들되었지만 압축은 안 됨 (이 패키지, 그리고 대다수 MCP 서버):** tsup/
  esbuild/rollup의 기본 동작이 minify 미적용이다. 이 경우 AST가 그대로 읽혀
  시맨틱 그레프가 잘 작동한다.
- **압축까지 됨 (드묾):** 이름이 짧은 토큰으로 치환되고 한 줄로 뭉친다. 그래도
  시맨틱 그레프는 파싱은 하므로 `eval(...)` 같은 구조 패턴은 import 바인딩이
  보존된 경우 여전히 매치된다. 다만 번들러가 import를 별칭으로 바꿨다면
  (`exec` → `a`) 이름 기반 규칙은 놓치고, taint 추적은 크게 저하된다.

따라서 "타볼로 풀면 시맨틱 그레프를 돌릴 수 있나"의 답은: **소스 트리가 확보
되므로 돌릴 수 있고, 압축되지 않은 일반적 배포물에서는 유용하다. 압축된
배포물에서만 효과가 제한되며, 그 경우 매니페스트의 원본 리포지토리 주소를
따라가 비압축 소스를 받는 보완 경로가 필요하다.**

---

## 3. 동적 단계로의 전달과 정리

정적이 만든 스냅샷은 인메모리 객체로 동적 분석에 전달된다. 동적 쪽은:

- 런타임 결정기가 스냅샷의 노드/파이썬 버전 제약을 우선 사용 (여기서는 제약이
  없어 node22).
- 사전 검사기가 스냅샷을 곧장 증거로 변환해서 디스크 읽기·`npm view`·PyPI 조회를
  생략. 증거 출처 라벨은 `extracted-tarball:@browsermcp/mcp`.
- 의존성 14개와 패키지 이름이 그대로 레시피 매칭에 입력된다.

분석이 끝나면 명령행 입구가 정리 콜백을 호출해 받아 푼 임시 디렉터리를 삭제한다.
정적이 받아 둔 트리를 동적 컨테이너에 마운트하는 최적화는 이 사례에는 적용하지
않았다 (이번 변경 범위는 환경 정합 첫 시도 정확도에 한정).

---

## 4. 다른 생태계의 차이

- 원격 PyPI 패키지(`uvx <pkg>` / `pipx <pkg>`)는 PyPI JSON API에서 소스 배포본
  URL을 찾아 같은 방식으로 받아 푼다. 버전은 메타데이터의 `info.version`을
  사용하므로 dist-tag 같은 함정은 없다. 다만 휠만 발행된 패키지는 소스 배포본이
  없어 매니페스트 수준까지만 분석된다.
- 로컬 절대 경로로 지정된 서버는 타볼을 받지 않고 그 디렉터리를 그대로 분석한다.

세 경우 모두 결과는 동일한 환경 스냅샷 형태로 정규화되어 동적 단계가 출처를
구분할 필요가 없다.
