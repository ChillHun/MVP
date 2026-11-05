import streamlit as st
import re

# 웹 페이지 제목 및 설명
st.title("팀 SC: AI 코딩 보안 스캐너")
st.write("바이브 코딩 후 놓치기 쉬운 보안 취약점을 웹에서 즉시 진단하고 KISA 가이드에 따른 조치 방법을 제공합니다.")

st.markdown("---")

# KISA 가이드 기반 취약점 탐지 룰셋
SENSITIVE_PATTERNS = [
    {
        "name": "SQL 인젝션 (문자열 + 연산 쿼리 결합)",
        "pattern": re.compile(r'(execute|query)\s*\(.*?[''"].*?(SELECT|INSERT|UPDATE|DELETE).*?[''"]\s*\+', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 변수가 문자열 연산(+)으로 직접 결합되어 있습니다. 파라미터 바인딩 방식을 사용하세요."
    },
    {
        "name": "SQL 인젝션 (f-string 및 포맷팅 결합)",
        "pattern": re.compile(r'(execute|query)\s*\(\s*f?[''"].*?(SELECT|INSERT|UPDATE|DELETE).*?(\{.*?\}|\%s)', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 f-string이나 포맷팅 기호가 포함되어 있습니다. 인자화된 쿼리와 바인딩 인자를 분리하여 사용하세요."
    },
    {
        "name": "코드 삽입 취약점 (위험한 eval/exec 함수 사용)",
        "pattern": re.compile(r'\b(eval|exec)\s*\(', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] 외부 입력값이 검증 없이 eval() 또는 exec() 함수에 전달되면 임의의 코드가 실행될 수 있습니다. 사전 검증(isalnum 등)을 거치거나 해당 함수 사용을 금지하세요."
    }
]

# 주석 제거 및 원본 줄 번호 추적 전처리 함수
def remove_python_comments_and_docstrings(source_code):
    lines = source_code.splitlines()
    clean_lines_with_info = []
    
    in_docstring = False
    docstring_delim = ''

    for orig_line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 1. 문서화 주석(독스트링) 시작/끝 감지
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                docstring_delim = stripped[:3]
                if stripped.count(docstring_delim) < 2:
                    in_docstring = True
                continue
        else:
            if docstring_delim in line:
                in_docstring = False
            continue
            
        if in_docstring:
            continue
            
        # 2. 인라인 주석(# 이후 내용) 제거
        line_without_comment = re.sub(r'(?<!["\'])\s*#.*$', '', line)
        
        # 3. 빈 줄이 아닐 경우에만 원본 줄 번호와 함께 저장
        if line_without_comment.strip():
            clean_lines_with_info.append((orig_line_num, line_without_comment))
            
    return clean_lines_with_info

# 파일 업로드 인터페이스
uploaded_file = st.file_uploader("검사할 파이썬(.py) 파일을 업로드하세요", type=["py"])

if uploaded_file is not None:
    # 업로드된 파일의 바이트를 텍스트로 안전하게 변환
    file_bytes = uploaded_file.read()
    code_text = file_bytes.decode("utf-8")
    
    with st.expander("업로드한 코드 미리보기"):
        st.code(code_text, language="python")

    if st.button("보안 취약점 스캔 시작"):
        st.write("---")
        st.subheader("스캔 결과 리포트")
        
        clean_lines_with_info = remove_python_comments_and_docstrings(code_text)
        detected_results = []
        
        for orig_line_num, line in clean_lines_with_info:
            # HTML 템플릿 변수 선언부(<pre> 등 HTML 태그가 포함된 줄)는 오탐 방지를 위해 제외
            if any(tag in line for tag in ["<pre", "</pre>", "<form", "<input", "<hr"]):
                continue
            
            # [규칙 1] SQL 실행 구문(execute 등) 검사
            if re.search(r'\bexecute\s*\(', line, re.IGNORECASE):
                if 'f"' in line or "f'" in line or "%s" in line or "+" in line or "{" in line:
                    detected_results.append({
                        "line_num": orig_line_num,
                        "line_content": line,
                        "rule_name": "SQL 인젝션 (취약한 쿼리 파라미터 결합)",
                        "guide": "[KISA 보안 가이드] SQL 쿼리 실행문 내에 변수 결합(f-string, 포맷팅, 연산)이 포함되어 있습니다. 파라미터 바인딩 방식을 사용하세요."
                    })
            
            # [규칙 2] 코드 삽입 취약점 (eval/exec) 검사
            if re.search(r'\b(eval|exec)\s*\(', line, re.IGNORECASE):
                detected_results.append({
                    "line_num": orig_line_num,
                    "line_content": line,
                    "rule_name": "코드 삽입 취약점 (위험한 eval/exec 함수 사용)",
                    "guide": "[KISA 보안 가이드] 외부 입력값이 검증 없이 eval() 또는 exec() 함수에 전달되면 임의의 코드가 실행될 수 있습니다. 사전 검증(isalnum 등)을 거치거나 해당 함수 사용을 금지하세요."
                })
        
        # 줄 번호 기준으로 오름차순 정렬 및 중복 제거
        seen_lines = set()
        unique_results = []
        for res in sorted(detected_results, key=lambda x: x["line_num"]):
            if res["line_num"] not in seen_lines:
                seen_lines.add(res["line_num"])
                unique_results.append(res)
        
        detected_count = len(unique_results)
        
        for res in unique_results:
            with st.expander(f"[취약점 발견] {res['rule_name']} (원본 코드 {res['line_num']}번째 줄)"):
                st.code(res['line_content'].strip(), language="python")
                st.error(f"조치 가이드: {res['guide']}")
                        
        if detected_count == 0:
            st.success("안전: 업로드한 파일에서 주요 보안 취약점이 발견되지 않았습니다.")
        else:
            st.error(f"총 {detected_count}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")
else:
    st.info("검사할 소스 코드 파일을 업로드해 주세요.")
