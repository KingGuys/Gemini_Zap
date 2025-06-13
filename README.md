Gemini_Zap Scanner

# 주요 기능
완전 자동화된 스캔: URL만 입력하면 Spider, Active Scan, AI 분석까지 자동으로 수행합니다.

AI 기반 심층 분석: ZAP의 스캔 결과를 Gemini API를 통해 분석하여, 단순 탐지를 넘어선 깊이 있는 리포트를 제공합니다.

논리 취약점 분석: 애플리케이션의 맥락을 추론하여 '불충분한 인증/인가'와 같은 논리적 취약점까지 분석합니다.

다양한 분석 모드: 전체 스캔, 기존 경고 분석, 특정 패킷 정밀 분석 등 다양한 모드를 지원합니다.

전문가용 HTML 보고서: 분석 결과를 가독성 높은 표 형식의 대시보드가 포함된 HTML 파일로 저장합니다.

시큐어 코딩 가이드: 발견된 취약점에 대한 구체적인 방어 코드 예시를 제공합니다.

# 사전 준비 사항
Python 3.8 이상

OWASP ZAP 설치 및 실행:
스크립트가 ZAP API를 사용하므로, ZAP 프로그램이 반드시 실행 중이어야 합니다.

필요한 Python 라이브러리:
pip install requests python-zap

# 설치 및 설정
스크립트 다운로드: 이 저장소를 클론하거나 스크립트 파일(Zap.py)을 다운로드합니다.

설정 파일 생성 및 수정:
스크립트를 처음 실행하면 config.ini 파일이 자동으로 생성됩니다.

생성된 config.ini 파일을 열고 아래 두 가지 정보를 입력합니다.

[zap] 섹션의 api_key: ZAP의 API 키 (ZAP UI > Tools > Options > API 에서 확인)

[gemini] 섹션의 api_key: Google AI Studio에서 발급받은 본인의 Gemini API 키

사용법 (명령어)
터미널에서 아래와 같이 스크립트를 실행합니다.

python Zap.py [모드] [옵션]


# 분석 모드 (하나만 선택)
@ 지정된 URL에 대해 전체 자동 스캔(Spider, Active Scan) 및 분석을 수행합니다.
--scan-url <URL>

@ ZAP에 이미 존재하는 모든 보안 경고(Alerts)를 가져와 분석합니다.
--analyze-alerts

@ ZAP의 History 탭에 있는 특정 ID의 패킷 하나만 정밀 분석합니다.
--analyze-packet <ID>

@ 실제 스캔 없이 Gemini API 연결 및 인증만 테스트합니다.
--test-gemini

# 옵션 (필요에 따라 추가)
@ 분석할 보안 경고의 최대 개수를 지정합니다. (기본값: 30)
--limit <숫자>

@ 분석 결과를 지정된 파일 이름의 HTML 보고서로 저장합니다. (기본값: report.html)
--html-report <파일이름>

@ 보고서에 표시될 분석 대상 URL을 수동으로 지정할 때 사용합니다.
--target-override <URL>

@ 사용할 설정 파일의 경로를 지정합니다. (기본값: config.ini)
--config <파일경로>

# 명령어 사용 예시
1. 가장 기본적인 전체 스캔 및 분석
http://testphp.vulnweb.com 사이트를 전체 스캔하고, 분석 결과를 vulnweb_report.html 파일로 저장합니다.

python Zap.py --scan-url [http://testphp.vulnweb.com](http://testphp.vulnweb.com) --html-report vulnweb_report.html

2. 기존 ZAP 경고를 분석하여 보고서 생성
현재 ZAP에 쌓여있는 경고들 중 위험도가 높은 순으로 50개를 분석하고, 결과를 기본 파일명(report.html)으로 저장합니다.

python Zap.py --analyze-alerts --limit 50

3. 특정 패킷 하나만 정밀 분석
ZAP History 탭에서 확인한 ID가 125인 패킷 하나만 정밀 분석하고, 결과를 packet_125_report.html로 저장합니다.

python Zap.py --analyze-packet 125 --html-report packet_125_report.html

4. Gemini API 연결 테스트
실제 스캔을 시작하기 전에 config.ini 파일의 Gemini API 키가 올바른지 확인합니다.

python Zap.py --test-gemini


# 보고서 html 형식
sample.html 확인


# 라이선스
이 프로젝트는 MIT 라이선스를 따릅니다.

