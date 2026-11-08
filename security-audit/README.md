# HOP 2단계 보안 감시 실행서 (Hyper-V, 24시간)

1단계(정적 분석·재현 빌드) 결과는 [FINDINGS-phase1.md](FINDINGS-phase1.md). 이 문서는 **2단계 실측**을
사용자 PC(Windows 11 Pro 호스트 + Hyper-V Windows 11 Pro VM)에서 수행하는 절차다.

## 다음 세션 시작 방법 (Claude 용 인수인계)

- 이 폴더는 브랜치 `claude/sleepy-ride-ptbi94` 에 있다. 로컬 PC 에서
  `git clone -b claude/sleepy-ride-ptbi94 https://github.com/Inho-sw/ext_hop` 후 `security-audit\` 에서 작업.
- 호스트 스크립트는 **관리자 PowerShell**, Hyper-V 모듈 필요. 게스트 스크립트는 호스트가 PowerShell Direct 로 복사·실행한다
  (VM 네트워크를 쓰지 않으므로 캡처에 섞이지 않음).
- 모든 `.ps1` 은 UTF-8 BOM. 실행 정책이 막으면 `Set-ExecutionPolicy -Scope Process Bypass`.
- 아직 실제 Windows 에서 실행해 본 적이 없다. **첫 실행에서 오류가 나면 고치면서 진행**할 것.
  분석기(`analysis/`)는 합성 패킷 단위 테스트를 통과했다.

## 사용자 준비물

| 항목 | 내용 |
|---|---|
| VM 이름 | `HopAudit.config.psd1` 의 `VMName` 에 입력 (`Get-VM` 으로 확인) |
| VM 관리자 계정 | HOP 를 실행할 그 계정. PowerShell Direct 접속에 사용 |
| VM 상태 | 켜져 있고 위 계정으로 로그인된 상태 |
| VM 네트워크 | 인터넷 연결 필요(업데이트 확인 관찰). **정적 MAC 권장** |
| 호스트 절전 | 24시간 동안 호스트가 절전에 들지 않게 설정 |
| (선택) Sysmon | Sysinternals 에서 받은 `Sysmon64.exe` 경로. 없어도 WFP 감사로 충분 |
| (분석) Python 3 | `analysis/analyze_capture.py` 실행용. 호스트에 없으면 결과를 다른 PC 로 옮겨 분석 |

## 절차

모든 명령은 호스트의 관리자 PowerShell 에서 `security-audit\host` 폴더 기준.

### 0. 설정
`HopAudit.config.psd1` 에서 `VMName` 입력. 나머지는 기본값 유지.

### 1. 준비 (약 15분)
```powershell
.\Initialize-HopAudit.ps1                      # Sysmon 사용 시: -SysmonPath C:\Tools\Sysmon64.exe
```
- 체크포인트 `HOP-Audit-00-Clean` 생성 → 공식 MSI 다운로드·SHA-256 검증 → 게스트 감사 로깅(WFP 5156, 4688, DNS) 활성화
  → 설치 전 기준선 수집 → 체크포인트 `HOP-Audit-01-Instrumented` 생성. **HOP 는 아직 설치하지 않는다.**

### 2. 대조군 캡처 (1시간, HOP 미설치)
```powershell
.\Start-HopCapture.ps1 -Phase control
# 1시간 대기 (VM 은 로그인 상태로 그대로 둠)
.\Stop-HopCapture.ps1
```
Windows 자체 배경 트래픽(업데이트, Defender, 시간 동기화 등)을 파악해 본 감시와 비교하기 위함.

### 3. 본 감시 시작
```powershell
.\Start-HopCapture.ps1 -Phase main             # 반드시 설치보다 먼저
.\Invoke-HopGuestStep.ps1 -Step Install         # 공식 MSI 무인 설치 + exe 해시 출력
.\Invoke-HopGuestStep.ps1 -Step StartMonitor    # 24시간 자원/연결 감시 (게스트 예약 작업)
.\Invoke-HopGuestStep.ps1 -Step Canary          # 카나리 토큰 생성 → 게스트 C:\HopAudit\canary.txt
```

### 4. 문서 작업 시나리오 (VM 안에서 사람이 수행, 각 단계 시각을 메모)
1. 시작 메뉴에서 HOP 실행. 업데이트 알림이 떠도 **설치 버튼은 누르지 않는다**.
2. 새 문서 → `C:\HopAudit\canary.txt` 의 토큰을 메모장에서 복사해 본문에 붙여 넣기 (몇 줄 더 입력).
3. HWPX 로 저장 → HWP 로 다른 이름 저장 → 닫고 다시 열기.
4. PDF 내보내기 (내보낸 뒤 열기 옵션 포함).
5. 인쇄 → `Microsoft Print to PDF`.
6. 앱 종료 → 작업 관리자에서 `hop-desktop.exe`/`msedgewebview2.exe` 잔류 여부 확인.
7. 다시 HOP 실행 후 문서를 연 채로 **방치**.

### 5. 24시간 방치
VM 화면 잠금은 무방. 호스트·VM 모두 절전 금지 (게스트 절전은 1단계에서 이미 해제).

### 6. 수집
```powershell
.\Stop-HopCapture.ps1
.\Invoke-HopGuestStep.ps1 -Step Collect -Label post
```
결과: `C:\HopAudit\capture\main-*\*.pcapng`, `C:\HopAudit\results\hop-audit-post-*.zip`.

### 7. 시간 트리거 시험 (약 1.5시간)
```powershell
.\Start-HopCapture.ps1 -Phase timeshift
.\Set-HopVmClock.ps1 -OffsetDays 30       # VM 에서 HOP 실행, 30분 관찰
.\Set-HopVmClock.ps1 -OffsetDays 335      # 누적 +365일, HOP 재실행, 30분 관찰
.\Set-HopVmClock.ps1 -Restore
.\Stop-HopCapture.ps1
.\Invoke-HopGuestStep.ps1 -Step Collect -Label timeshift
```

### 8. 분석
```powershell
cd ..\analysis
$mac = (Get-Content C:\HopAudit\state.json | ConvertFrom-Json).Nic.MacAddress
# results zip 을 풀어 wfp-connections.csv 위치 확인 후:
python analyze_capture.py C:\HopAudit\capture\main-<시각> --vm-mac $mac --canary-file C:\HopAudit\canary.txt `
    --wfp-csv <압축해제>\wfp-connections.csv --out C:\HopAudit\report-main.md
python analyze_capture.py C:\HopAudit\capture\control-<시각> --vm-mac $mac --out C:\HopAudit\report-control.md
```
종료 코드 2 = 카나리 발견.

### 9. 원상 복구
```powershell
Restore-VMSnapshot -VMName <VM이름> -Name HOP-Audit-00-Clean -Confirm:$false
```

## 판정 기준

| 항목 | 정상 | 이상 (즉시 보고) |
|---|---|---|
| HOP 프로세스 외부 연결 | `github.com` (+ 리다이렉트 `objects/release-assets.githubusercontent.com`), 시작 시 1회 | 그 밖의 도메인/IP, 주기적 반복 접속, `cdn.jsdelivr.net` |
| WebView2(`msedgewebview2.exe`) | Microsoft 도메인 소량 (SmartScreen, 구성요소 업데이트 등) | Microsoft 외 도메인 |
| 카나리 | 캡처 어디에도 없음 | 원문/UTF-16/Base64/Hex 어떤 형태든 발견 |
| 업로드량 | 연결당 수 KB 수준 | 문서 크기에 비례하는 송신, 수십 KB 이상 반복 송신 |
| 자원 (`monitor\resources.csv`) | 유휴 시 CPU 1% 미만, 메모리 안정 | 유휴 상태 지속 CPU/GPU 사용, 메모리 지속 증가 |
| 자식 프로세스 (`events.csv`, 4688) | WebView2 계열뿐 | cmd/powershell/기타 실행 |
| 기준선 차이 (`baseline-diff.txt`) | HOP 설치 항목(프로그램·파일 연결·바로가기) | 서비스·예약 작업·자동 실행·방화벽 규칙·루트 인증서·프록시·Defender 제외 추가 |
| 시간 이동 | 동작 변화 없음 (TLS 오류는 정상) | 날짜에 따라 새 연결·프로세스·파일 |

TLS 내부는 암호화되어 있어 카나리 검색은 평문 구간만 유효하다. HOP 프로세스의 TLS 연결이 github 외 대상으로 있으면
그 자체로 이상으로 판정하고, 필요 시 mitmproxy 로 내용을 추가 확인한다.

## 파일 구성

```text
HopAudit.config.psd1        설정 (VM 이름, 체크포인트 이름, MSI URL/해시, 감시 주기)
host/                       호스트(관리자) 스크립트
  Initialize-HopAudit.ps1   체크포인트·MSI 검증·게스트 로깅·기준선
  Start-HopCapture.ps1      pktmon(기본) 또는 dumpcap 캡처 시작
  Stop-HopCapture.ps1       캡처 중지, ETL→pcapng 변환, 해시 목록
  Invoke-HopGuestStep.ps1   Install / StartMonitor / StopMonitor / Canary / Collect
  Set-HopVmClock.ps1        시간 트리거 시험
guest/                      게스트에서 실행되는 스크립트 (호스트가 복사)
sysmon/sysmonconfig-hop.xml (선택) Sysmon 설정
analysis/                   pcap 분석기 (Python 표준 라이브러리만) + 테스트
```
