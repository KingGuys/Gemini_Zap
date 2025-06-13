#!/usr/bin/env python3
"""
Burp Suite API Connection - Final Test Script
config.ini를 사용하지 않고 오직 API 키 연결만 테스트하는 최종 진단용 스크립트입니다.
"""
import requests
import sys

def test_burp_connection():
    """터미널에서 직접 API 키를 입력받아 연결을 테스트합니다."""
    
    burp_url = "http://127.0.0.1:1337"
    test_url = f"{burp_url}/v0.1/health"

    print("="*70)
    print("🔥 Burp Suite API 연결 최종 테스트를 시작합니다.")
    print("="*70)
    print("Burp Suite에서 새로 생성한 API 키를 준비해주세요.")
    
    # 사용자에게 직접 API 키 입력받기
    api_key = input("🔑 Burp API 키를 여기에 붙여넣고 Enter 키를 누르세요: ").strip()

    if not api_key:
        print("❌ API 키가 입력되지 않았습니다. 프로그램을 종료합니다.")
        sys.exit(1)

    headers = {'X-Burp-Api-Key': api_key}
    
    print("\nDEBUG: 입력된 키로 Burp API에 연결을 시도하는 중...")
    
    try:
        response = requests.get(test_url, headers=headers, timeout=15)
        
        # 성공
        if response.status_code == 200 and response.json().get('healthy') is True:
            print("\n" + "🎉"*20)
            print("✅✅✅ 드디어 연결 및 인증에 성공했습니다! ✅✅✅")
            print("🎉"*20)
            print("\n이제 모든 것이 정상입니다. 원래 스크립트로 돌아가서 이 키를 사용하시면 됩니다.")
            return True
        
        # 인증 실패
        elif response.status_code == 401:
            print("\n" + "❌"*20)
            print("❌ 최종 테스트 실패: 401 Unauthorized (인증 실패)")
            print("❌ 진짜 원인: Burp Suite 프로그램이 API 키를 올바르게 처리하지 못하고 있습니다.")
            print("❌ 해결책: Burp Suite 프로그램을 완전히 재설치하는 것을 권장합니다.")
            print("❌"*20)
            return False
        
        # 기타 오류
        else:
            print(f"\n❌ 오류: 예상치 못한 응답 (상태 코드: {response.status_code})")
            print(f"응답 내용: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"\n❌ 오류: Burp Suite에 연결할 수 없습니다. ({test_url})")
        print(" - Burp Suite 프로그램이 실행 중인지 다시 확인해주세요.")
        print(" - Burp의 'User options -> REST API'에서 'Service running'이 활성화되었는지 확인해주세요.")
        print(f" - 상세 정보: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    test_burp_connection()
