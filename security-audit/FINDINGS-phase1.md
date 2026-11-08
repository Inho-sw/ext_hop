# HOP v0.4.5 보안 점검 — 1단계(정적 분석·재현 빌드) 결과

점검일: 2026-11-08 · 대상: `golbin/hop` v0.4.5 (태그 커밋 `34bd15c`), 서브모듈 `edwardkim/rhwp` v0.8.7 (`1a76570e`)

## 결론

- 문서 내용을 외부로 보내는 코드 경로 **없음**.
- 앱이 스스로 하는 외부 통신은 **업데이트 확인 1건**뿐: 릴리스 빌드에서 앱 시작 시 1회
  `GET https://github.com/golbin/hop/releases/latest/download/latest.json`.
  다운로드·설치는 사용자가 알림 버튼을 눌러야만 실행되며 minisign 서명을 검증한다.
- 날짜/시각 조건 분기, 주기적 원격 호출, 특정 문서 내용에 반응하는 분기 **없음**.
- 자동 실행·서비스·예약 작업 등록 **없음** (WiX 템플릿의 예약 작업 블록은 비활성).
- **공식 v0.4.5 바이너리 = 이 저장소 소스**임을 재현 빌드로 확인 (아래).

## 외부 통신 지점

| 경로 | 시점 | 보내는 것 |
|---|---|---|
| 업데이트 확인 `github.com/golbin/hop/releases/latest/...` | 앱 시작 시 1회 (릴리스 빌드) | GET 요청만 |
| 업데이트 다운로드 | 사용자가 버튼 클릭 시 | 없음 (다운로드) |
| 문서 하이퍼링크 | 사용자가 클릭 시 (http/https 만) | 해당 URL 접속 |
| WebView2 런타임 다운로드 `go.microsoft.com` | Windows 설치 시, WebView2 없을 때만 | 없음 |

근거: Rust 전체에 소켓/HTTP 사용 코드 없음(`reqwest` 는 updater 플러그인만 끌어옴), 빌드된 프론트엔드의
실제 `fetch` 2곳은 모두 앱 내부 자원, CSP `connect-src 'self' ipc:` 로 웹뷰의 외부 요청 차단.
번들에 남은 `cdn.jsdelivr.net` 폰트 URL 256건은 upstream 웹용 카탈로그 데이터이며 HOP 폰트 로더는
로컬 `/fonts/*` 만 사용 → **2단계 실측에서 jsdelivr 접속이 0건인지 확인할 것**.

## 재현 빌드 검증 (`.github/workflows/repro-verify.yml`)

| 구간 | 결과 |
|---|---|
| 공식 Windows MSI 안 `hop-desktop.exe` vs 재빌드 | `.text/.rdata/.data/.rsrc/.pdata/.reloc` 전부 일치 (빌드 시각·PDB GUID만 다름) |
| 공식 Linux deb `hop-desktop` vs 재빌드 | `.text` 일치. `.rodata` 차이는 CSP 해시 4개 순서, 심볼 차이는 LLVM `.llvm.<id>` 접미사뿐 |
| 공식 바이너리에 내장된 웹 자산 37개 vs 로컬 빌드 | 34개 바이트 일치, SVG 2개는 CRLF 차이, `index.html` 은 Tauri 재직렬화 차이(구조 동일) |
| 저장소 `vendor/rhwp-core` WASM vs rhwp v0.8.7 소스 재빌드 | macOS 러너에서 4개 파일 바이트 일치 |

## 참고 해시

- 공식 MSI `HOP-windows-x64.msi`: `9d833572f9da11ba711a66f518ee71deca5404f621a5f934ca58408439716478`
- MSI 안 `hop-desktop.exe`: `ca8d6708842de134b2ecc98f2ef7f5bc7458f19b75386e25cd785e6b7a4ed55f`
- 공식 Windows 바이너리는 **Authenticode 미서명**.

## 의존성 감사 (2026-11-08)

- `pnpm audit --prod`: 취약점 없음.
- `cargo audit`(desktop): 19건. 실사용 경로는 `rustls` 계열(업데이트 확인 TLS)뿐 → 패치 버전 갱신 권고.
  `zip` 은 `extract()` 미사용, `zip 4.x`/`quick-xml`/`rkyv` 는 런타임 트리에 없음.

## 사내 배포 권고

1. MSI 배포 사용 (NSIS `.exe` 는 비교하지 않음). 미서명 허용 여부 확인.
2. 버전 통제가 필요하면 방화벽/프록시에서 `github.com/golbin/hop/releases` 차단 (차단해도 기능 영향 없음).
3. 2단계 실측 결과로 최종 판정.
