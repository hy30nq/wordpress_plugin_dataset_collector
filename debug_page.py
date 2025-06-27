import requests
from bs4 import BeautifulSoup
import re

def debug_page_structure():
    url = "https://wpscan.com/vulnerability/f7411320-b3e3-49bd-bb99-bd046a4bfcf2/"
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    print(f"페이지 분석 중: {url}")
    response = session.get(url)
    
    if response.status_code != 200:
        print(f"페이지 로드 실패: {response.status_code}")
        return
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    print("=== 페이지 제목 ===")
    title = soup.find('h1')
    if title:
        print(f"제목: {title.get_text().strip()}")
    else:
        print("제목을 찾을 수 없습니다.")
    
    print("\n=== 모든 섹션들 ===")
    sections = soup.find_all('section')
    for i, section in enumerate(sections):
        print(f"섹션 {i+1}:")
        # 섹션의 첫 번째 헤딩이나 중요한 텍스트 찾기
        heading = section.find(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        if heading:
            print(f"  헤딩: {heading.get_text().strip()}")
        
        # 취약점 링크가 있는지 확인
        vuln_links = section.find_all('a', href=re.compile(r'/vulnerability/'))
        if vuln_links:
            print(f"  취약점 링크 수: {len(vuln_links)}")
            for j, link in enumerate(vuln_links[:3]):  # 처음 3개만 출력
                print(f"    링크 {j+1}: {link.get('href')}")
                print(f"    텍스트: {link.get_text().strip()[:50]}...")
        print()
    
    print("\n=== Proof of Concept 검색 ===")
    headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
    poc_found = False
    for heading in headings:
        if 'proof of concept' in heading.get_text().lower():
            print(f"PoC 헤딩 발견: {heading.get_text().strip()}")
            # 다음 몇 개 요소들 확인
            next_element = heading.find_next_sibling()
            content_count = 0
            while next_element and content_count < 3:
                if next_element.name in ['p', 'div', 'pre', 'code', 'blockquote']:
                    text = next_element.get_text().strip()
                    if text:
                        print(f"  내용 {content_count + 1}: {text[:100]}...")
                        content_count += 1
                next_element = next_element.find_next_sibling()
            poc_found = True
            break
    
    if not poc_found:
        print("Proof of Concept 섹션을 찾을 수 없습니다.")
    
    print("\n=== CSS 선택자 테스트 ===")
    selectors_to_test = [
        '#wp--skip-link--target > div > section:nth-child(7)',
        'section:nth-child(7)',
        'section:last-child',
        '.vulnerabilities__other',
        '[class*="other"]'
    ]
    
    for selector in selectors_to_test:
        element = soup.select_one(selector)
        if element:
            vuln_links = element.find_all('a', href=re.compile(r'/vulnerability/'))
            print(f"선택자 '{selector}': {len(vuln_links)}개 취약점 링크 발견")
        else:
            print(f"선택자 '{selector}': 요소를 찾을 수 없음")

if __name__ == "__main__":
    debug_page_structure() 