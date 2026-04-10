# matrix_comparison_runner.py
# 방어 레이어 상호작용 및 우회 확률 표(Bypass Probability Matrix) 런너 스크립트.

import requests
import os
import time
import csv
from threading import Thread
from bypass_generator import generate_bypasses
from matrix_defense_apps import create_matrix_app

RESULTS_CSV = 'matrix_interaction_results.csv'

def parse_user_input(user_input):
    """
    사용자가 입력한 문자열을 바탕으로 조합 리스트를 생성합니다.
    입력 예시: "L1, L1+L2, L1+L3, L1+L2+L3+L5"
    """
    combos = []
    # 아무것도 입력 안 하면 기본값 사용
    if not user_input.strip():
        user_input = "L0, L1, L3, L1+L2, L1+L3, L1+L2+L3, L1+L2+L3+L5"
        
    parts = [p.strip() for p in user_input.split(',')]
    for p in parts:
        p_upper = p.upper()
        # L0 처리
        if p_upper in ['L0', 'NONE', 'L0(NONE)']:
            combos.append(("L0(None)", False, False, False, False, False))
            continue
            
        l1 = "L1" in p_upper
        l2 = "L2" in p_upper
        l3 = "L3" in p_upper
        l4 = "L4" in p_upper
        l5 = "L5" in p_upper
        combos.append((p_upper, l1, l2, l3, l4, l5))
        
    return combos

def start_server(combo_name, flags, port):
    """지정된 조합으로 서버 구동"""
    l1, l2, l3, l4, l5 = flags
    app = create_matrix_app(combo_name, l1, l2, l3, l4, l5)
    
    def run():
        # Flask debug=False 필수 (멀티스레딩 충돌 방지)
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    
    thread = Thread(target=run, daemon=True)
    thread.start()
    time.sleep(3)  # 앱 부팅 대기
    return port

def test_combination(combo_name, port, payloads):
    """해당 조합 포맷에 모든 페이로드 타격"""
    url = f"http://127.0.0.1:{port}/upload"
    results = []
    session = requests.Session()
    
    for technique, payload_path in payloads:
        with open(payload_path, 'rb') as f:
            # 몇몇 특수 우회 기법은 파일 전송 시 Content-Type 강제 변조 반영
            content_type = 'image/jpeg' if any(k in technique for k in ['polyglot', 'double', 'obfuscation', 'trailing']) else None
            files = {'file': (os.path.basename(payload_path), f, content_type) if content_type else (os.path.basename(payload_path), f)}
            try:
                response = session.post(url, files=files, timeout=12)
                upload_success = response.status_code == 200
                
                # 풀 디펜스(L5 사용)일 경우 쉘이 보존되지 않음.
                rce_success = upload_success and ("L5" not in combo_name)
                
                print(f"  [PKT] DST: {combo_name:<12} | PAYLOAD: {technique[:20]:<20} | RES: {response.status_code} ({'SUCCESS' if upload_success else 'BLOCKED'})")
                results.append({
                    'combination': combo_name,
                    'technique': technique,
                    'upload_success': upload_success,
                    'rce_success': rce_success
                })
            except Exception as e:
                results.append({
                    'combination': combo_name,
                    'technique': technique,
                    'upload_success': False,
                    'rce_success': False
                })
    return results

def run_matrix_test():
    print("Layer Interaction & Bypass Probability Matrix 실험 시작")
    print("각 방어 메커니즘의 독립성과 피어 종속성을 교차 검증합니다.\n")
    
    print("="*60)
    print("테스트할 방어 레이어 조합을 입력해주세요.")
    print("  - (엔터만 누르면 기본 중요 조합들로 자동 실행됩니다)")
    print("="*60)
    user_input = input(">> 조합 입력: ")
    
    combinations = parse_user_input(user_input)
    print(f"\n[INFO] 총 {len(combinations)}개의 조합을 테스트합니다: {[c[0] for c in combinations]}")
    
    payloads = generate_bypasses()
    total_payloads = len(payloads)
    all_results = []
    
    # 서버 기동 및 평가 루프
    base_port = 6000
    for i, combo in enumerate(combinations):
        combo_name = combo[0]
        flags = combo[1:]
        port = base_port + i
        
        print(f"\n === [ {combo_name} ] 아키텍처 서버 구동 (포트 {port}) ===")
        start_server(combo_name, flags, port)
        
        layer_results = test_combination(combo_name, port, payloads)
        all_results.extend(layer_results)
        
    # 결과 CSV 출력
    with open(RESULTS_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['combination', 'technique', 'upload_success', 'rce_success'])
        writer.writeheader()
        writer.writerows(all_results)
        
    # 터미널 가독성을 위한 요약 표 (세로형)
    print("\n" + "="*70)
    print("레이어 조합별 우회 방어 성능 요약 (가독성 최적화)")
    print("="*70)
    print(f"{'방어 조합(Combo)':<15} | {'우회된 개수 / 전체':<20} | {'우회율(뚫릴 확률)':<15}")
    print("-" * 70)
    
    combo_names = [c[0] for c in combinations]
    for combo in combo_names:
        # 해당 콤보의 테스트 결과 수집
        combo_data = [r for r in all_results if r['combination'] == combo]
        
        # rce_success 기준 (최종 위험 목적 달성)
        success_bypasses = [r for r in combo_data if r['rce_success']]
        bypass_count = len(success_bypasses)
        bypass_rate = (bypass_count / total_payloads) * 100 if total_payloads else 0
        
        # 눈에 띄는 상태 라벨
        if bypass_rate == 0:
            status = "완벽 차단 방어 (0%)"
        elif bypass_rate <= 10:
            status = f"부분 뚫림 ({bypass_rate:.1f}%)"
        else:
            status = f"심각한 우회위험 ({bypass_rate:.1f}%)"
            
        print(f"{combo:<15} | {bypass_count:>3} 개 / {total_payloads:<12} | {status}")

    print("\n세부적으로 어떤 파일 포맷이나 기법(Technique)이 뚫었는지 정밀 매트릭스 데이터는")
    print(f"[{RESULTS_CSV}] 파일에 저장되었습니다. (엑셀에서 열어 조작하기 좋습니다)")

if __name__ == '__main__':
    run_matrix_test()
