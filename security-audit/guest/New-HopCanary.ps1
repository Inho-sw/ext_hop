<#
.SYNOPSIS
    (게스트) 문서 유출 판별용 카나리 문자열을 만든다.

.DESCRIPTION
    무작위 토큰 HOPCANARY-xxxxxxxx-xxxxxxxx 를 만들어 canary.txt 에 저장한다.
    이 문자열을 HOP 문서 본문에 붙여 넣고 저장·PDF 내보내기·인쇄를 하면,
    analyze_capture.py 가 캡처 전체에서 원문/UTF-16/Base64/Hex 형태로 검색한다.
    마지막 출력 줄이 토큰이다 (호스트 스크립트가 이 줄을 읽는다).
#>
param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference = 'Stop'

$bytes = [byte[]]::new(8)
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
$token = 'HOPCANARY-{0}-{1}' -f $hex.Substring(0, 8), $hex.Substring(8, 8)

$path = Join-Path $Root 'canary.txt'
Set-Content -LiteralPath $path -Value $token -Encoding utf8
Write-Output "카나리 저장: $path"
Write-Output $token
