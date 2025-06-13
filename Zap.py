#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZAP + Gemini API Integration (v9.0 - Final Prompt Engineering)
OWASP ZAP과 Google Gemini API를 사용한 자동화된 보안 분석 도구
- AI의 '환각' 현상 방지 및 방어 코드 예시 보장을 위한 최종 프롬프트 튜닝
"""

import time
import json
import argparse
import sys
import os
from configparser import ConfigParser
from urllib.parse import urlparse
import requests
from zapv2 import ZAPv2
import re

class ZapGeminiAutomation:
    def __init__(self, config_file="config.ini"):
        self.config_file = config_file
        self.config = ConfigParser()
        if not os.path.exists(self.config_file):
            self._create_default_config(self.config_file)
            print(f"'{self.config_file}'이 생성되었습니다. ZAP 및 Gemini의 API 키와 주소를 입력해주세요.")
            sys.exit(1)

        self.config.read(self.config_file, encoding='utf-8')

        # ZAP 설정
        zap_apikey = self.config.get("zap", "api_key", fallback="").strip()
        zap_address_full = self.config.get("zap", "address", fallback="127.0.0.1").strip()
        zap_port = self.config.get("zap", "port", fallback="8080").strip()
        
        # Gemini 설정
        self.gemini_api_key = self.config.get("gemini", "api_key", fallback="").strip()
        
        if not self.gemini_api_key or self.gemini_api_key == "YOUR_GEMINI_API_KEY_HERE":
            print("❌ 오류: 설정 파일에 유효한 Gemini API 키가 없습니다.", file=sys.stderr)
            sys.exit(1)

        parsed_url = urlparse(zap_address_full)
        zap_host = parsed_url.hostname if parsed_url.hostname else zap_address_full

        try:
            proxies = {
                'http': f'http://{zap_host}:{zap_port}',
                'https': f'http://{zap_host}:{zap_port}',
            }
            self.zap = ZAPv2(apikey=zap_apikey, proxies=proxies)
            version = self.zap.core.version
            print(f"✅ ZAP API 연결 성공! (ZAP 버전: {version})")
        except Exception as e:
            print(f"❌ 오류: ZAP에 연결할 수 없습니다. ZAP 프로그램이 실행 중인지 확인해주세요. ({e})", file=sys.stderr)
            sys.exit(1)
            
        self.gemini_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={self.gemini_api_key}"


    def _create_default_config(self, file_path):
        config = ConfigParser()
        config["zap"] = {
            "api_key": "YOUR_ZAP_API_KEY_HERE",
            "address": "127.0.0.1",
            "port": "8080"
        }
        config["gemini"] = {"api_key": "YOUR_GEMINI_API_KEY_HERE"}
        with open(file_path, "w", encoding='utf-8') as f:
            f.write("# OWASP ZAP API 설정\n")
            f.write("# ZAP UI -> Tools -> Options -> API 에서 확인 및 설정 가능\n\n")
            config.write(f)

    def test_gemini_api(self):
        print("\n" + "="*70)
        print("🧪 Gemini API 연결 테스트를 시작합니다...")
        print("="*70)
        test_prompt = "이것은 Gemini API 연결 테스트입니다. '성공'이라고만 대답해주세요."
        try:
            result = self.analyze_with_gemini(test_prompt, is_test=True)
            if "성공" in result:
                print(f"✅ Gemini API 테스트 성공! 응답: {result}")
                return True
            else:
                print(f"❌ Gemini API 테스트 실패. 예상치 못한 응답: {result}")
                return False
        except Exception as e:
            print(f"❌ Gemini API 테스트 중 심각한 오류 발생: {e}")
            return False

    def run_scan(self, target_url):
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        print(f"\n" + "="*70)
        print(f"🚀 자동 스캔을 시작합니다... 대상: {target_url}")
        print("="*70)

        print("\n[1/2] Spider 스캔을 시작합니다...")
        try:
            scan_id = self.zap.spider.scan(target_url)
            while int(self.zap.spider.status(scan_id)) < 100:
                print(f"Spider 스캔 진행률: {self.zap.spider.status(scan_id)}%", end='\r')
                time.sleep(5)
            print("Spider 스캔 진행률: 100%")
            print("✅ Spider 스캔 완료!")
        except Exception as e:
            print(f"❌ Spider 스캔 중 오류 발생: {e}")
            return False

        print("\n[2/2] Active 스캔을 시작합니다... (시간이 오래 걸릴 수 있습니다)")
        try:
            scan_id = self.zap.ascan.scan(target_url)
            while int(self.zap.ascan.status(scan_id)) < 100:
                print(f"Active 스캔 진행률: {self.zap.ascan.status(scan_id)}%", end='\r')
                time.sleep(10)
            print("Active 스캔 진행률: 100%")
            print("✅ Active 스캔 완료!")
        except Exception as e:
            print(f"❌ Active 스캔 중 오류 발생: {e}")
            return False
            
        print("\n" + "="*70)
        print("✅ 모든 자동 스캔이 완료되었습니다.")
        print("="*70)
        return True
        
    def get_zap_alerts(self, baseurl=None):
        print("ZAP에서 보안 경고를 가져옵니다...")
        return self.zap.core.alerts(baseurl=baseurl)

    def get_zap_message_by_id(self, msg_id):
        print(f"ZAP에서 메시지 ID '{msg_id}'를 가져옵니다...")
        try:
            msg = self.zap.core.message(msg_id)
            if msg and 'message' in msg:
                 return msg['message']
            return None
        except Exception as e:
            print(f"❌ 메시지 ID '{msg_id}'를 가져오는 중 오류 발생: {e}")
            return None

    def _summarize_alerts(self, alerts, limit=30):
        if not alerts:
            return "발견된 보안 경고가 없습니다.", 0
        
        total_alerts = len(alerts)
        risk_map = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        confidence_map = {"High": 3, "Medium": 2, "Low": 1, "Confirmed": 4, "False Positive": 0}

        sorted_alerts = sorted(alerts, 
                               key=lambda x: (risk_map.get(x.get('risk'), 0), confidence_map.get(x.get('confidence', '').title(), 0)), 
                               reverse=True)
        
        summary_lines = []
        summary_lines.append(f"총 {total_alerts}개의 보안 경고가 발견되었습니다. 위험도가 높은 상위 {min(total_alerts, limit)}개를 분석 대상으로 선정했습니다.\n")
        
        for i, alert in enumerate(sorted_alerts[:limit]):
            summary_lines.append(f"--- 경고 {i+1} ---")
            summary_lines.append(f"  - 이름 (Name): {alert.get('name')}")
            summary_lines.append(f"  - 위험도 (Risk): {alert.get('risk')}")
            summary_lines.append(f"  - URL: {alert.get('url')}")
            summary_lines.append(f"  - 파라미터 (Param): {alert.get('param')}")
            summary_lines.append(f"  - 공격 (Attack): {alert.get('attack')}")
            summary_lines.append(f"  - 설명 (Description): {alert.get('description', '').strip().replace('*', '')}")
            summary_lines.append("")
        
        return "\n".join(summary_lines), total_alerts

    def analyze_with_gemini(self, prompt, is_test=False):
        if not is_test:
            print("Gemini API에 분석을 요청하는 중...")
            
        headers = {"Content-Type": "application/json"}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        try:
            response = requests.post(self.gemini_api_url, json=payload, headers=headers, timeout=300)
            response.raise_for_status()
            result = response.json()
            return result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        except requests.exceptions.HTTPError as e:
            print(f"❌ Gemini API 요청 오류: {e.response.status_code} {e.response.reason}", file=sys.stderr)
            print(f"응답 내용: {e.response.text}", file=sys.stderr)
            return "Gemini API 호출에 실패했습니다. (HTTP 오류)"
        except requests.exceptions.RequestException as e:
            print(f"❌ Gemini API 요청 오류: {e}", file=sys.stderr)
            return "Gemini API 호출에 실패했습니다. (네트워크 오류)"
        except (KeyError, IndexError):
            print(f"❌ Gemini API 응답 파싱 오류. 응답 JSON 구조를 확인하세요.", file=sys.stderr)
            print(f"전체 응답: {result}", file=sys.stderr)
            return "Gemini API 응답을 처리하는 데 실패했습니다."

    def create_prompt(self, data, analysis_type, total_alerts_count=0, limit=30):
        """[개선됨 v9.0] '환각' 현상 방지 및 방어 코드 예시를 보장하도록 프롬프트 수정"""
        data_str = json.dumps(data, indent=2, ensure_ascii=False) if isinstance(data, dict) else data

        # [개선됨] 프롬프트에 더 강력한 제약 조건 추가
        prompt_base = f"""당신은 세계 최고 수준의 보안 컨설턴트입니다. 제공된 ZAP 스캔 데이터를 분석하여, 반드시 아래의 마크다운 테이블 형식으로 상세한 보안 분석 보고서를 작성해주세요.
제공된 '분석 대상 데이터'에만 근거하여 분석해야 하며, 목록에 없는 경고 번호(예: '경고 16-20 참고')를 임의로 언급해서는 안 됩니다.
모든 내용은 한국어로 작성해야 합니다.

| No. | 취약점 분류 (CWE) | 위험도 | 상세 분석 및 조치 방안 | 공격 벡터 및 방어 코드 |
|---|---|---|---|---|
| 1 | 여기에 첫 번째 취약점의 정확한 이름과 관련 CWE 번호를 기입합니다. (예: SQL Injection (CWE-89)) | `High`, `Medium`, `Low` 중 하나 | **[상세 설명]** 이 취약점이 무엇이며, 비즈니스에 어떤 영향을 미칠 수 있는지 구체적으로 설명합니다.<br><br>**[조치 방안]** 개발자가 명확히 이해하고 따를 수 있도록, 단계별로 구체적인 해결 방안을 제시합니다. | **[공격 벡터]** 취약점이 발견된 URL, 파라미터, 공격 페이로드 예시를 명확하게 보여줍니다.<br><br>**[방어 코드 예시]** 반드시 이 취약점을 방어할 수 있는 안전한 코드 예시(Java, Python, PHP 등)를 제공해야 합니다. 만약 특정 언어로 제공하기 어렵다면, 의사 코드(Pseudo-code)라도 제시해야 합니다. |
| 2 | ... | ... | ... | ... |
"""
        
        recommendation_prompt = f"""
---
## 총평 및 추가 권고

위 표의 분석 결과를 바탕으로 애플리케이션의 전반적인 보안 상태를 종합적으로 평가해주세요.
- **주요 취약점 패턴:** 어떤 종류의 취약점이 집중적으로 발견되었는지 요약합니다.
- **추가 분석 제안:** 현재 분석된 {limit}개 외에, 총 {total_alerts_count}개의 경고가 있습니다. 이를 바탕으로 어떤 부분(예: 인증 및 권한 관리, 비즈니스 로직 등)에 대한 심층적인 수동 점검이 필요한지 제안해주세요.
- **종합 보안 강화 방안:** 개발팀이 즉시 적용할 수 있는 3가지 이상의 실질적인 보안 강화 방안(예: 시큐어 코딩 프레임워크 도입, 보안 헤더 일괄 적용, WAF 정책 튜닝 등)을 우선순위와 함께 제시해주세요.
"""

        if analysis_type == "alerts_summary":
            return prompt_base + recommendation_prompt + f"\n### 분석 대상 데이터 (ZAP 경고 요약)\n{data_str}"
        elif analysis_type == "single_packet":
            return prompt_base + "\n---" + f"\n### 분석 대상 데이터 (단일 HTTP 패킷)\n{data_str}"
        else:
            return f"다음 데이터를 보안 관점에서 심층 분석하고, 발견된 모든 잠재적 이슈와 개선 권장 사항을 한국어로 상세히 설명해주세요.\n\n{data_str}"


    def save_html_report(self, markdown_content, output_file, target_url="N/A", alerts=None):
        print(f"HTML 보고서를 생성하는 중... ({output_file})")
        
        risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        if alerts:
            for alert in alerts:
                risk = alert.get('risk')
                if risk in risk_counts:
                    risk_counts[risk] += 1
        
        report_parts = re.split(r'## 총평 및 추가 권고', markdown_content)
        table_markdown = report_parts[0]
        recommendation_markdown = "## 총평 및 추가 권고" + report_parts[1] if len(report_parts) > 1 else ""

        html_template = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZAP + Gemini 보안 분석 보고서</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;700&display=swap');
        body {{ font-family: 'Noto Sans KR', sans-serif; background-color: #f8f9fa; }}
        .markdown-body table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 1.5rem; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            border: 1px solid #adb5bd;
        }}
        .markdown-body th, .markdown-body td {{ 
            border: 1px solid #ced4da;
            padding: 1rem 1.25rem; 
            text-align: left; 
            vertical-align: top; 
            line-height: 1.7;
        }}
        .markdown-body th {{ 
            background-color: #f1f3f5; 
            font-weight: 600; 
            font-size: 0.95rem; 
            color: #212529;
            border-color: #adb5bd;
        }}
        .markdown-body td {{ background-color: #ffffff; }}
        .markdown-body tr:nth-child(even) td {{ background-color: #f8f9fa; }}
        .markdown-body code {{ background-color: #e9ecef; color: #c92a2a; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.875em; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;}}
        .markdown-body pre {{ background-color: #212529; color: #f8f9fa; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }}
        .markdown-body ul {{ list-style-position: inside; padding-left: 1rem; }}
        .markdown-body strong {{ color: #212529; font-weight: 600; }}
        .risk-high {{ color: #d9480f; font-weight: 700; }}
        .risk-medium {{ color: #f08c00; font-weight: 700; }}
        .risk-low {{ color: #1971c2; font-weight: 700; }}
    </style>
</head>
<body class="text-gray-800">
    <div class="container mx-auto p-4 md:p-6 lg:p-8 max-w-screen-xl">
        <header class="text-center mb-10">
            <h1 class="text-5xl font-bold text-gray-800">보안 취약점 분석 보고서</h1>
            <p class="text-gray-600 mt-3">Powered by OWASP ZAP & Google Gemini</p>
        </header>
        
        <div class="grid grid-cols-2 md:grid-cols-4 gap-6 mb-10 text-center">
            <div class="bg-white border-t-4 border-red-500 p-4 rounded-lg shadow-md"><p class="text-3xl font-bold">{risk_counts['High']}</p><p class="text-gray-500">High Risk</p></div>
            <div class="bg-white border-t-4 border-yellow-500 p-4 rounded-lg shadow-md"><p class="text-3xl font-bold">{risk_counts['Medium']}</p><p class="text-gray-500">Medium Risk</p></div>
            <div class="bg-white border-t-4 border-blue-500 p-4 rounded-lg shadow-md"><p class="text-3xl font-bold">{risk_counts['Low']}</p><p class="text-gray-500">Low Risk</p></div>
            <div class="bg-white border-t-4 border-gray-400 p-4 rounded-lg shadow-md"><p class="text-3xl font-bold">{risk_counts['Informational']}</p><p class="text-gray-500">Informational</p></div>
        </div>

        <div class="bg-white p-6 rounded-lg shadow-md mb-10">
            <h2 class="text-2xl font-semibold mb-3 border-b pb-2">분석 개요</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-base">
                <p><strong>분석 대상:</strong> <span class="font-mono text-blue-700">{target_url}</span></p>
                <p><strong>분석 일시:</strong> <span class="font-mono">{time.strftime('%Y-%m-%d %H:%M:%S')}</span></p>
            </div>
        </div>

        <main id="report-table-content" class="markdown-body"></main>
        
        <div id="report-recommendation-content" class="markdown-body mt-10 bg-white p-8 rounded-lg shadow-md"></div>
    </div>

    <textarea id="table-markdown-source" style="display:none;">{table_markdown}</textarea>
    <textarea id="recommendation-markdown-source" style="display:none;">{recommendation_markdown}</textarea>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const tableSource = document.getElementById('table-markdown-source').value;
            const recommendationSource = document.getElementById('recommendation-markdown-source').value;
            
            let tableHtml = marked.parse(tableSource);
            tableHtml = tableHtml.replace(/<td>High<\/td>/g, '<td class="risk-high">High</td>');
            tableHtml = tableHtml.replace(/<td>Medium<\/td>/g, '<td class="risk-medium">Medium</td>');
            tableHtml = tableHtml.replace(/<td>Low<\/td>/g, '<td class="risk-low">Low</td>');

            document.getElementById('report-table-content').innerHTML = tableHtml;
            document.getElementById('report-recommendation-content').innerHTML = marked.parse(recommendationSource);
        }});
    </script>
</body>
</html>
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_template)
            print(f"✅ HTML 보고서가 '{output_file}'에 성공적으로 저장되었습니다.")
        except IOError as e:
            print(f"❌ 오류: HTML 보고서 파일 저장 실패 - {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="OWASP ZAP + Gemini API 자동화된 보안 분석 도구 (v9.0)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--scan-url", help="URL을 지정하여 전체 자동 스캔 및 분석을 수행합니다.")
    mode_group.add_argument("--analyze-alerts", action="store_true", help="ZAP에 이미 존재하는 모든 보안 경고(Alerts)를 분석합니다.")
    mode_group.add_argument("--analyze-packet", type=int, metavar="ID", help="ZAP History의 특정 ID를 가진 패킷 하나를 정밀 분석합니다.")
    mode_group.add_argument("--test-gemini", action="store_true", help="Gemini API 연결 및 인증을 테스트합니다.")

    parser.add_argument("--limit", type=int, default=30, help="분석할 보안 경고의 최대 개수 (위험도 높은 순, 기본값: 30)")
    parser.add_argument("--html-report", default="report.html", help="분석 결과를 저장할 HTML 보고서 파일 이름 (기본값: report.html)")
    parser.add_argument("--config", default="config.ini", help="설정 파일 경로 (기본값: config.ini)")
    parser.add_argument("--target-override", help="보고서에 표시될 분석 대상 URL을 수동으로 지정합니다.")
    
    args = parser.parse_args()
    
    automation = ZapGeminiAutomation(config_file=args.config)
    analysis_result, alerts_data = None, None
    total_alerts_count = 0
    
    target_for_report = args.target_override if args.target_override else args.scan_url

    if args.test_gemini:
        automation.test_gemini_api()
        sys.exit(0)

    if args.scan_url:
        if not automation.run_scan(args.scan_url):
            print("자동 스캔에 실패하여 분석을 진행할 수 없습니다.")
            sys.exit(1)
    
    if args.scan_url or args.analyze_alerts:
        alerts_data = automation.get_zap_alerts(baseurl=target_for_report)
        if alerts_data:
            if not target_for_report and alerts_data:
                try:
                    first_url = alerts_data[0].get('url', 'N/A')
                    parsed = urlparse(first_url)
                    target_for_report = f"{parsed.scheme}://{parsed.netloc}"
                except:
                    target_for_report = "Multiple Targets"

            alerts_summary, total_alerts_count = automation._summarize_alerts(alerts_data, limit=args.limit)
            prompt = automation.create_prompt(alerts_summary, "alerts_summary", total_alerts_count=total_alerts_count, limit=args.limit)
            analysis_result = automation.analyze_with_gemini(prompt)
        else:
            print("분석할 보안 경고가 없습니다.")

    elif args.analyze_packet:
        packet_data = automation.get_zap_message_by_id(args.analyze_packet)
        if packet_data:
            if not target_for_report:
                 try:
                    host_match = re.search(r"Host: (.*?)\r\n", packet_data.get('requestHeader', ''))
                    host = host_match.group(1) if host_match else "N/A"
                    target_for_report = f"http://{host}"
                 except:
                    target_for_report = "N/A"

            prompt = automation.create_prompt(packet_data, "single_packet")
            analysis_result = automation.analyze_with_gemini(prompt)
        else:
            print(f"ID '{args.analyze_packet}'에 해당하는 패킷을 찾을 수 없습니다.")

    if analysis_result:
        print("\n" + "="*25 + " Gemini 분석 결과 " + "="*25)
        print(analysis_result)
        print("="*70)
        
        automation.save_html_report(analysis_result, args.html_report, target_url=target_for_report, alerts=alerts_data)

if __name__ == "__main__":
    main()
