import requests
import csv
import time
import re
from bs4 import BeautifulSoup
import html
import random

class WPScanVulnerabilityCollector:
    def __init__(self):
        self.base_url = "https://wpscan.com"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        
    def get_page(self, url, max_retries=3):
        """페이지를 가져오는 함수 (재시도 로직 포함)"""
        for attempt in range(max_retries):
            try:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                return response
            except requests.exceptions.RequestException as e:
                print(f"요청 실패 (시도 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    wait_time = random.uniform(2, 5)
                    print(f"{wait_time:.2f}초 대기 후 재시도...")
                    time.sleep(wait_time)
                else:
                    print(f"최대 재시도 횟수 초과. URL: {url}")
                    return None
    
    def extract_vulnerability_data(self, url):
        """개별 취약점 페이지에서 데이터 추출"""
        print(f"🔍 취약점 페이지 분석 중: {url}")
        
        response = self.get_page(url)
        if not response:
            print("❌ 페이지 로드 실패")
            return None
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        try:
            # 1. 제목에서 플러그인 이름과 취약점 이름 추출 
            title_element = soup.find('h1', class_='vulnerabilities__title')
            if not title_element:
                print("❌ 제목을 찾을 수 없습니다.")
                return None
            
            title_text = title_element.get_text().strip()
            
            # 플러그인 이름과 버전 추출
            # 다양한 형태 처리:
            # "Backup by 10Web <= 1.0.20 - Reflected Cross-Site Scripting (XSS)"
            # "ActiveDemand plugin for WordPress <= 1.2.0 - Unauthenticated Post Creation/Update/Deletion"
            plugin_match = re.match(r'^(.+?)\s*(?:plugin\s+for\s+WordPress\s+)?([<>=!]+\s*[\d.]+)\s*[-–]\s*(.+)$', title_text)
            
            if not plugin_match:
                print(f"❌ 제목 파싱 실패: {title_text}")
                return None
            
            plugin_name = plugin_match.group(1).strip()
            vulnerable_version = plugin_match.group(2).strip()
            vulnerability_name = plugin_match.group(3).strip()
            
            # "plugin" 단어 제거 및 정리
            plugin_name = re.sub(r'\s+plugin\s*$', '', plugin_name, flags=re.IGNORECASE)
            plugin_name = plugin_name.strip()
            
            # 2. 설명 추출
            description = ""
            desc_element = soup.find('div', class_='vulnerabilities__single-description')
            if desc_element:
                # p 태그의 텍스트만 추출
                p_elements = desc_element.find_all('p')
                if p_elements:
                    description = ' '.join([p.get_text().strip() for p in p_elements])
                    # HTML 엔티티 디코딩
                    description = html.unescape(description)
            
            # 3. PoC 추출
            poc = ""
            poc_element = soup.find('textarea', class_='vulnerabilities-single__poc')
            if poc_element:
                poc = poc_element.get_text().strip()
                # HTML 엔티티 디코딩
                poc = html.unescape(poc)
            
            # 4. CVE 번호 추출
            cve = ""
            # References 섹션 찾기
            references_section = None
            sections = soup.find_all('section', class_='vulnerabilities-single__section')
            for section in sections:
                heading = section.find('h3')
                if heading and 'references' in heading.get_text().lower():
                    references_section = section
                    break
            
            if references_section:
                # CVE 정보가 있는 데이터 테이블에서 CVE 번호 추출
                data_table = references_section.find('div', class_='vulnerabilities-single__data-table')
                if data_table:
                    data_rows = data_table.find_all('div', class_='vulnerabilities-single__data-row')
                    for row in data_rows:
                        title_div = row.find('div', class_='vulnerabilities-single__data-title')
                        if title_div and 'cve' in title_div.get_text().strip().lower():
                            value_div = row.find('div', class_='vulnerabilities-single__data-value')
                            if value_div:
                                # CVE 링크에서 CVE 번호 추출
                                cve_link = value_div.find('a')
                                if cve_link:
                                    cve_text = cve_link.get_text().strip()
                                    if cve_text.startswith('CVE-'):
                                        cve = cve_text
                                        break
                                else:
                                    # 링크가 아닌 경우 직접 텍스트에서 추출
                                    cve_text = value_div.get_text().strip()
                                    if cve_text.startswith('CVE-'):
                                        cve = cve_text
                                        break
            
            # CVE와 PoC가 모두 있는지 확인
            if not cve or not poc:
                print(f"❌ CVE({bool(cve)}) 또는 PoC({bool(poc)}) 누락")
                return None
            
            print(f"✅ 데이터 추출 성공:")
            print(f"   - 플러그인: {plugin_name}")
            print(f"   - 취약한 버전: {vulnerable_version}")
            print(f"   - 취약점: {vulnerability_name}")
            print(f"   - CVE: {cve}")
            print(f"   - PoC 길이: {len(poc)} 문자")
            
            return {
                'plugin_name': plugin_name,
                'vulnerable_version': vulnerable_version, 
                'vulnerability_name': vulnerability_name,
                'description': description,
                'poc': poc,
                'cve': cve,
                'url': url
            }
            
        except Exception as e:
            print(f"❌ 데이터 추출 중 오류: {e}")
            return None
    
    def load_poc_links(self, filename='poc_links.txt'):
        """poc_links.txt 파일에서 링크 목록 로드"""
        print(f"📂 {filename} 파일에서 링크 로드 중...")
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                links = [line.strip() for line in f if line.strip()]
            
            print(f"📋 총 {len(links)}개의 링크를 발견했습니다.")
            return links
            
        except FileNotFoundError:
            print(f"❌ 파일을 찾을 수 없습니다: {filename}")
            return []
        except Exception as e:
            print(f"❌ 파일 읽기 오류: {e}")
            return []
    
    def collect_vulnerabilities_from_links(self, target_count=6362):
        """poc_links.txt의 링크들을 사용해서 취약점 정보 수집"""
        print(f"🎯 목표: CVE와 PoC가 모두 있는 취약점을 최대한 많이 수집")
        print(f"📋 총 {target_count}개 링크 처리 예정")
        print("=" * 50)
        
        # 링크 목록 로드
        links = self.load_poc_links()
        if not links:
            print("❌ 처리할 링크가 없습니다.")
            return []
        
        processed_count = 0
        success_count = 0
        
        for i, url in enumerate(links):
            processed_count += 1
            print(f"\n📈 진행상황: {processed_count}/{len(links)} (성공: {success_count})")
            
            # 중복 제거
            if any(vuln['url'] == url for vuln in self.vulnerabilities):
                print(f"⏭️  이미 처리된 URL: {url}")
                continue
            
            # 취약점 데이터 추출
            vulnerability_data = self.extract_vulnerability_data(url)
            
            if vulnerability_data:
                self.vulnerabilities.append(vulnerability_data)
                success_count += 1
                
                # 50개씩 수집할 때마다 중간 저장
                if success_count % 50 == 0:
                    self.save_to_csv(f'wordpress_vulnerabilities_progress_{success_count}.csv')
                
                print(f"🎯 수집 완료: {success_count}")
            else:
                print("❌ 데이터 추출 실패")
            
            # 요청 간 간격 두기 (1-3초)
            wait_time = random.uniform(1, 3)
            print(f"⏳ {wait_time:.2f}초 대기...")
            time.sleep(wait_time)
        
        print(f"\n🏁 수집 완료!")
        print(f"   - 처리된 URL: {processed_count}")
        print(f"   - 성공적으로 수집: {success_count}")
        print(f"   - 성공률: {(success_count/processed_count)*100:.1f}%")
        
        return self.vulnerabilities
    
    def save_to_csv(self, filename='wordpress_vulnerabilities.csv'):
        """수집된 데이터를 CSV로 저장"""
        if not self.vulnerabilities:
            print("저장할 취약점 데이터가 없습니다.")
            return
        
        print(f"💾 CSV 파일로 저장 중: {filename}")
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'plugin_name', 'vulnerable_version', 'vulnerability_name', 'description', 'poc', 'cve', 'url']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for i, vulnerability in enumerate(self.vulnerabilities, 1):
                # ID를 1부터 시작해서 순차적으로 부여
                row = {'id': i}
                row.update(vulnerability)
                writer.writerow(row)
        
        print(f"✅ CSV 파일 저장 완료: {filename}")
        print(f"📊 저장된 데이터: {len(self.vulnerabilities)}개")

def main():
    """메인 실행 함수"""
    print("🚀 WordPress 플러그인 취약점 수집기 시작")
    print("=" * 50)
    
    # 수집기 초기화
    collector = WPScanVulnerabilityCollector()
    
    # poc_links.txt에서 링크들을 사용해서 취약점 정보 수집
    vulnerabilities = collector.collect_vulnerabilities_from_links(target_count=6362)
    
    if vulnerabilities:
        # 최종 CSV 파일 저장
        collector.save_to_csv('wordpress_vulnerabilities_final_6362.csv')
        
        print(f"\n🎊 수집 완료!")
        print(f"   - 총 수집된 취약점: {len(vulnerabilities)}개")
        print(f"   - 파일: wordpress_vulnerabilities_final_6362.csv")
    else:
        print("❌ 수집된 취약점이 없습니다.")

if __name__ == "__main__":
    main()
