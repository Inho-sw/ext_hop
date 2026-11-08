@{
    # Hyper-V VM 이름. 비워 두면 Initialize-HopAudit.ps1 이 VM 목록을 보여 주고 멈춘다.
    VMName              = ''

    # 체크포인트 이름. 00 = 아무것도 바꾸기 전, 01 = 감사 로깅/기준선 수집 후(HOP 설치 전).
    CheckpointClean     = 'HOP-Audit-00-Clean'
    CheckpointReady     = 'HOP-Audit-01-Instrumented'

    # 작업 폴더. 호스트와 VM(게스트) 모두 같은 경로를 쓴다.
    HostWorkDir         = 'C:\HopAudit'
    GuestWorkDir        = 'C:\HopAudit'

    # 점검 대상: 공식 v0.4.5 MSI. 해시는 1단계 재현 빌드 검증에서 확인한 값이다.
    MsiUrl              = 'https://github.com/golbin/hop/releases/download/v0.4.5/HOP-windows-x64.msi'
    MsiSha256           = '9d833572f9da11ba711a66f518ee71deca5404f621a5f934ca58408439716478'

    # 패킷 캡처: pktmon multi-file 모드의 파일 하나당 크기(MB).
    CaptureFileSizeMB   = 512

    # 게스트 자원 감시 주기와 기간.
    MonitorIntervalSec  = 60
    MonitorHours        = 24
}
