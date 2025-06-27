import requests
import csv
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import random
import html

class WPScanVulnerabilityCollector:
    def __init__(self):
        self.base_url = "https://wpscan.com"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.visited_urls = set()  # 이미 방문한 URL 추적
        
    def get_page(self, url, max_retries=3):
        """페이지를 가져오는 함수 (재시도 로직 포함)"""
        for attempt in range(max_retries):
            try:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                print(f"페이지 요청 실패 (시도 {attempt + 1}/{max_retries}): {url}")
                print(f"오류: {e}")
                if attempt < max_retries - 1:
                    time.sleep(random.uniform(2, 5))
                else:
                    return None
    
    def get_related_vulnerability_links(self, page_url):
        """페이지 하단의 관련 취약점 링크들을 추출"""
        print(f"관련 취약점 링크 수집 중: {page_url}")
        response = self.get_page(page_url)
        if not response:
            return []
        
        soup = BeautifulSoup(response.content, 'html.parser')
        links = []
        
        # "Other" 섹션에서 관련 취약점 링크들 찾기
        other_section = None
        sections = soup.find_all('section', class_='vulnerabilities-single__section')
        
        for section in sections:
            heading = section.find('h3')
            if heading and 'other' in heading.get_text().lower():
                other_section = section
                break
        
        if other_section:
            # 관련 취약점 테이블에서 링크들 추출
            related_table = other_section.find('div', class_='vulnerabilities-single__related-table')
            if related_table:
                vulnerability_links = related_table.find_all('a', href=re.compile(r'/vulnerability/'))
                for link in vulnerability_links:
                    href = link.get('href')
                    if href:
                        # URL 정규화
                        if href.startswith('/'):
                            full_url = self.base_url + href
                        elif href.startswith('http'):
                            # a8cteam5105.wordpress.com을 wpscan.com으로 변경
                            if 'a8cteam5105.wordpress.com' in href:
                                parsed = urlparse(href)
                                full_url = f"https://wpscan.com{parsed.path}"
                            else:
                                full_url = href
                        else:
                            full_url = urljoin(self.base_url, href)
                        
                        # wpscan.com 도메인이고 이미 방문하지 않은 URL만 추가
                        if 'wpscan.com' in full_url and full_url not in self.visited_urls:
                            links.append(full_url)
                            print(f"✅ 새 관련 링크 발견: {full_url}")
        
        print(f"발견된 새 관련 링크 수: {len(links)}")
        return links
    
    def extract_vulnerability_details(self, url):
        """개별 취약점 상세 정보 추출"""
        print(f"취약점 상세 정보 수집 중: {url}")
        
        # 이미 방문한 URL인지 확인
        if url in self.visited_urls:
            print(f"이미 방문한 URL입니다: {url}")
            return None, []
        
        self.visited_urls.add(url)
        response = self.get_page(url)
        if not response:
            return None, []
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        try:
            # 1. 페이지 제목에서 플러그인 정보 추출
            title_element = soup.find('h1', class_='vulnerabilities__title')
            if not title_element:
                print("제목을 찾을 수 없습니다.")
                return None, []
            
            title_text = title_element.get_text().strip()
            # HTML 엔티티 디코딩
            title_text = html.unescape(title_text)
            
            plugin_name = ""
            vulnerable_version = ""
            vulnerability_name = ""
            
            # 제목 파싱: "플러그인명 plugin <= 버전 - 취약점명"
            if ' - ' in title_text:
                parts = title_text.split(' - ', 1)
                plugin_part = parts[0].strip()
                vulnerability_name = parts[1].strip()
                
                # 플러그인 이름과 버전 분리
                # "plugin" 키워드 제거하고 버전 정보 추출
                plugin_part = plugin_part.replace(' plugin', '')
                version_match = re.search(r'^(.+?)\s*(<=|<|>=|>|=)\s*([\d\.]+)', plugin_part)
                if version_match:
                    plugin_name = version_match.group(1).strip()
                    vulnerable_version = f"{version_match.group(2)} {version_match.group(3)}"
                else:
                    plugin_name = plugin_part.strip()
            else:
                vulnerability_name = title_text
                plugin_name = title_text.split()[0] if title_text else "Unknown"
            
            # 2. 설명 추출
            description = ""
            description_element = soup.find('div', class_='vulnerabilities__single-description')
            if description_element:
                # Description 헤딩 다음의 p 태그 찾기
                desc_p = description_element.find('p')
                if desc_p:
                    description = desc_p.get_text().strip()
            
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
                data_rows = references_section.find_all('div', class_='vulnerabilities-single__data-row')
                for row in data_rows:
                    title_div = row.find('div', class_='vulnerabilities-single__data-title')
                    if title_div and 'cve' in title_div.get_text().lower():
                        value_div = row.find('div', class_='vulnerabilities-single__data-value')
                        if value_div:
                            cve_link = value_div.find('a')
                            if cve_link:
                                cve = cve_link.get_text().strip()
                            else:
                                cve = value_div.get_text().strip()
                        break
            
            # 5. 플러그인 이름 재확인 (Affects Plugins 섹션에서)
            plugin_slug_element = soup.find('div', class_='vulnerabilities__table--slug')
            if plugin_slug_element:
                slug_link = plugin_slug_element.find('a', class_='vulnerabilities__table--slug-link')
                if slug_link:
                    slug_text = slug_link.get_text().strip()
                    # 아이콘과 텍스트가 함께 있으므로 마지막 텍스트 부분만 추출
                    lines = [line.strip() for line in slug_text.split('\n') if line.strip()]
                    if lines:
                        actual_plugin_name = lines[-1]
                        if actual_plugin_name and len(actual_plugin_name) > 2:
                            plugin_name = actual_plugin_name
            
            # 6. 취약한 버전 재확인 (Fixed in 정보에서)
            fixed_in_element = soup.find('div', class_='vulnerabilities__table--fixed-in-text')
            if fixed_in_element and not vulnerable_version:
                fixed_text = fixed_in_element.get_text().strip()
                version_match = re.search(r'Fixed in\s+([\d\.]+)', fixed_text)
                if version_match:
                    fixed_version = version_match.group(1)
                    vulnerable_version = f"< {fixed_version}"
            
            # 7. 관련 취약점 링크들 수집 (PoC가 있든 없든)
            related_links = self.get_related_vulnerability_links(url)
            
            # CVE와 PoC가 모두 있는 경우만 저장
            if poc and len(poc.strip()) >= 20 and cve and cve.startswith('CVE-'):
                vulnerability_data = {
                    'plugin_name': plugin_name,
                    'vulnerable_version': vulnerable_version,
                    'vulnerability_name': vulnerability_name,
                    'description': description,
                    'cve': cve,
                    'poc': poc,
                    'url': url
                }
                
                print(f"✅ CVE와 PoC 모두 있는 취약점 수집 완료: {plugin_name} - {vulnerability_name}")
                print(f"   CVE: {cve}")
                print(f"   PoC 길이: {len(poc)} 문자")
                return vulnerability_data, related_links
            else:
                missing_info = []
                if not poc or len(poc.strip()) < 20:
                    missing_info.append("PoC")
                if not cve or not cve.startswith('CVE-'):
                    missing_info.append("CVE")
                
                print(f"❌ 정보 부족으로 스킵 ({', '.join(missing_info)} 없음): {plugin_name} ({len(related_links)}개 링크)")
                return None, related_links
            
        except Exception as e:
            print(f"취약점 정보 추출 중 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            # 오류가 발생해도 관련 링크는 시도해보기
            try:
                related_links = self.get_related_vulnerability_links(url)
                return None, related_links
            except:
                return None, []
    
    def collect_vulnerabilities_recursive(self, start_url, target_count=100, max_depth=1000):
        """재귀적으로 취약점 정보 수집"""
        print("WordPress 플러그인 취약점 수집을 시작합니다...")
        print("PoC가 있는 취약점만 수집합니다.")
        print(f"시작 URL: {start_url}")
        
        # BFS 방식으로 링크들을 처리
        urls_to_process = [start_url]
        processed_count = 0
        
        while urls_to_process and len(self.vulnerabilities) < target_count and processed_count < max_depth:
            current_url = urls_to_process.pop(0)
            processed_count += 1
            
            print(f"\n진행상황: {processed_count}/{max_depth} (수집됨: {len(self.vulnerabilities)}/{target_count})")
            print(f"대기 중인 URL 수: {len(urls_to_process)}")
            
            # 취약점 정보 추출 및 관련 링크 수집
            vulnerability_data, related_links = self.extract_vulnerability_details(current_url)
            
            if vulnerability_data:
                self.vulnerabilities.append(vulnerability_data)
                print(f"✅ 수집 완료 ({len(self.vulnerabilities)}/{target_count})")
            
            # 새로운 링크들을 처리 대기열에 추가
            for link in related_links:
                if link not in self.visited_urls and link not in urls_to_process:
                    urls_to_process.append(link)
            
            # 중간 저장 (10개마다)
            if len(self.vulnerabilities) > 0 and len(self.vulnerabilities) % 10 == 0:
                self.save_to_csv(f'wordpress_vulnerabilities_progress_{len(self.vulnerabilities)}.csv')
            
            # 요청 간격 조절 (서버 부하 방지)
            time.sleep(random.uniform(1, 3))
        
        print(f"\n수집 완료! 총 {len(self.vulnerabilities)}개의 취약점 정보를 수집했습니다.")
        print(f"총 {processed_count}개 페이지를 확인했고, 그 중 {len(self.vulnerabilities)}개에서 PoC를 찾았습니다.")
        return self.vulnerabilities
    
    def save_to_csv(self, filename='wordpress_vulnerabilities.csv'):
        """수집된 데이터를 CSV로 저장"""
        if not self.vulnerabilities:
            print("저장할 취약점 데이터가 없습니다.")
            return
        
        print(f"CSV 파일로 저장 중: {filename}")
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'plugin_name', 'vulnerable_version', 'vulnerability_name', 'description', 'cve', 'poc', 'url']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for i, vulnerability in enumerate(self.vulnerabilities, 1):
                # ID를 1부터 시작해서 순차적으로 부여
                row = {'id': i}
                row.update(vulnerability)
                writer.writerow(row)
        
        print(f"✅ CSV 파일 저장 완료: {filename}")
        print(f"총 {len(self.vulnerabilities)}개의 취약점 정보가 저장되었습니다.")

def main():
    """메인 실행 함수"""
    collector = WPScanVulnerabilityCollector()
    
    # 시작 URL (PoC가 있는 실제 URL)
    start_url = "https://wpscan.com/vulnerability/d06a2db3-557b-4eae-ad80-85701cd40f3a/"
    
    try:
        # 재귀적으로 취약점 정보 수집 (PoC가 있는 것만)
        vulnerabilities = collector.collect_vulnerabilities_recursive(
            start_url=start_url, 
            target_count=100, 
            max_depth=1000  # 최대 1000개 페이지까지 확인
        )
        
        # 최종 CSV로 저장
        collector.save_to_csv('wordpress_vulnerabilities_final.csv')
        
        # 수집 결과 요약
        print("\n=== 수집 결과 요약 ===")
        print(f"총 수집된 취약점 수: {len(vulnerabilities)}")
        print(f"방문한 총 페이지 수: {len(collector.visited_urls)}")
        
        if vulnerabilities:
            print("\n처음 5개 취약점:")
            for i, vuln in enumerate(vulnerabilities[:5]):
                print(f"{i+1}. {vuln['plugin_name']} {vuln['vulnerable_version']} - {vuln['vulnerability_name']}")
                print(f"   PoC 길이: {len(vuln['poc'])} 문자")
                print(f"   URL: {vuln['url']}")
                print()
        
    except KeyboardInterrupt:
        print("\n사용자에 의해 중단되었습니다.")
        print(f"현재까지 수집된 취약점 수: {len(collector.vulnerabilities)}")
        if collector.vulnerabilities:
            collector.save_to_csv('wordpress_vulnerabilities_partial.csv')
    except Exception as e:
        print(f"오류 발생: {e}")
        import traceback
        traceback.print_exc()
        if collector.vulnerabilities:
            collector.save_to_csv('wordpress_vulnerabilities_error.csv')

if __name__ == "__main__":
    main()
