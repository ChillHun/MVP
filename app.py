import streamlit as st
import re

# 웹 페이지 제목 설정
st.title("팀 SC: AI 코딩 보안 스캐너")
st.write("바이브 코딩 후 놓치기 쉬운 보안 취약점을 웹에서 즉시 진단하고 KISA 가이드에 따른 한국어 조치 방법을 확인하세요.")

# KISA 가이드 기반 탐지 룰셋 Python
SENSITIVE_PATTERNS = [
    {
        "name": "SQL 인젝션 (파이썬 문자열 및 + 연산 쿼리 결합)",
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*[a-zA-Z0-9_]+', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 사용자 입력값이나 변수가 문자열 연산(+)으로 직접 결합되어 있습니다. SQL 인젝션 방지를 위해 파라미터 바인딩(예: curs.execute(sql, params))을 사용하세요."
    },
    {
        "name": "SQL 인젝션 (f-string 및 포맷팅 결합)",
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?f?["\'].*?(\{.*?\}|\%s)', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 f-string이나 포맷팅 기호가 포함되어 있습니다. 인자화된 쿼리와 바인딩 인자를 분리하여 사용하세요."
    },
    {
        "name": "코드 삽입 취약점 (위험한 eval/exec 함수 사용)",
        "pattern": re.compile(r'\b(eval|exec)\s*\(', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] 외부 입력값이 검증 없이 eval() 또는 exec() 함수에 전달되면 임의의 코드가 실행될 수 있습니다. 입력값에 대한 사전 검증(예: isalnum() 등)을 거치거나 해당 함수의 사용을 전면 금지하세요."
    }
]

def remove_python_comments_and_docstrings(source_code):
    """
    파이썬 코드에서 여러 형태의 주석(한 줄 주석, 인라인 주석, 여러 줄 따옴표 주석)을 제거합니다.
    """
    # 1. 여러 줄 주석 (''' ... ''' 또는 """ ... """) 제거
    code_no_docstrings = re.sub(r'(""".*?"""|\'\'\'.*?\'\'\')', '', source_code, flags=re.DOTALL)
    
    clean_lines = []
    for line in code_no_docstrings.splitlines():
        # 2. 인라인 주석 제거: 코드 뒤에 오는 '#' 이후 내용 제거
        line_without_comment = re.sub(r'(?<!["\'])\s*#.*$', '', line)
        
        # 3. 빈 줄이나 공백만 있는 줄이 아니면 유효한 코드 라인으로 인정
        if line_without_comment.strip():
            clean_lines.append(line_without_comment)
            
    return clean_lines

uploaded_file = st.file_uploader("검사할 파일을 업로드하세요 (예: .py)", type=["py"])

if uploaded_file is not None:
    # 업로드된 파일 읽기 (UTF-8 인코딩)
    file_bytes = uploaded_file.read()
    code_text = file_bytes.decode("utf-8")
    
    # 업로드된 코드 미리보기
    with st.expander("업로드한 코드 미리보기"):
        st.code(code_text, language="python")

    # 스캔 실행 버튼
    if st.button("보안 취약점 스캔 시작"):
        st.write("---")
        st.subheader("스캔 결과 리포트")
        
        # 검사 시작 전에 주석 제거 함수를 통과시켜 깨끗한 코드 라인만 추출
        clean_lines = remove_python_comments_and_docstrings(code_text)
        
        detected_count = 0
        
        # 주석이 모두 발라진 clean_lines를 대상으로 검사 진행
        for line_num, line in enumerate(clean_lines, 1):
            for rule in SENSITIVE_PATTERNS:
                if rule["pattern"].search(line):
                    detected_count += 1
                    with st.expander(f"[취약점 발견] {rule['name']} ({line_num}번째 유효 코드 줄)"):
                        st.code(line.strip(), language="python")
                        st.error(f"**조치 가이드:** {rule['guide']}")
                        
        if detected_count == 0:
            st.success("안전함: 업로드한 파일에서 주요 보안 취약점이 발견되지 않았습니다!")
        else:
            st.error(f"총 {detected_count}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")
else:
    st.info("검사할 소스 코드 파일을 업로드해주세요.")
