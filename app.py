import streamlit as st
import re

# 웹 페이지 제목 및 설명
st.title("팀 SC: AI 코딩 보안 스캐너")
st.write("바이브 코딩 후 놓치기 쉬운 보안 취약점을 웹에서 즉시 진단하고 KISA 가이드에 따른 조치 방법을 제공합니다.")

st.markdown("---")
st.subheader("테스트 파일 다운로드 및 미리보기")
st.write("스캐너 진단 테스트를 위한 샘플 파일(test.py)입니다. 파일을 다운로드하거나 아래 미리보기를 통해 코드를 확인하세요.")

target_test_file = "test.py"

try:
    with open(target_test_file, "r", encoding="utf-8") as f:
        file_content = f.read()
    
    st.download_button(
        label="테스트 파일(test.py) 다운로드",
        data=file_content,
        file_name=target_test_file,
        mime="text/plain"
    )

    with st.expander("연동된 test.py 코드 미리보기"): st.code(file_content, language="python")

except FileNotFoundError:
    st.warning(f"경고: '{target_test_file}' 파일이 동일한 폴더에 존재하지 않습니다. test.py 파일을 생성해 주세요.")

st.markdown("---")

# KISA 가이드 기반 취약점 탐지 룰셋
SENSITIVE_PATTERNS = [
    {
        "name": "SQL 인젝션 (문자열 + 연산 쿼리 결합)",
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*[a-zA-Z0-9_]+', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 변수가 문자열 연산(+)으로 직접 결합되어 있습니다. 파라미터 바인딩 방식을 사용하세요."
    },
    {
        "name": "SQL 인젝션 (f-string 및 포맷팅 결합)",
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?f?["\'].*?(\{.*?\}|\%s)', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 f-string이나 포맷팅 기호가 포함되어 있습니다. 인자화된 쿼리와 바인딩 인자를 분리하여 사용하세요."
    },
    {
        "name": "코드 삽입 취약점 (위험한 eval/exec 함수 사용)",
        "pattern": re.compile(r'\b(eval|exec)\s*\(', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] 외부 입력값이 검증 없이 eval() 또는 exec() 함수에 전달되면 임의의 코드가 실행될 수 있습니다. 사전 검증(isalnum 등)을 거치거나 해당 함수 사용을 금지하세요."
    }
]


# 주석 제거 및 원본 줄 번호 추적 전처리 함수 (상태 스위치 방식 적용)
def remove_python_comments_and_docstrings(source_code):
    lines = source_code.splitlines()
    clean_lines_with_info = []
    
    in_docstring = False
    docstring_delim = ''

    for orig_line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # [수정 포인트] 1. 문서화 주석(독스트링) 시작/끝 상태 스위치 감지 
        # (변수 대입 형태인 template = ''' 등은 주석으로 오인하지 않도록 and '=' not in line 추가)
        if not in_docstring:
            if (stripped.startswith('"""') or stripped.startswith("'''")) and '=' not in line:
                docstring_delim = stripped[:3]
                # 한 줄 안에 독스트링이 열리고 닫히지 않은 경우에만 스위치 ON
                if stripped.count(docstring_delim) < 2:
                    in_docstring = True
                continue
        else:
            # 독스트링이 끝나는 기호가 나오면 스위치 OFF
            if docstring_delim in line:
                in_docstring = False
            continue
            
        if in_docstring:
            continue
            
        # 2. 인라인 주석(# 이후 내용) 제거 (문자열 내부의 # 보호)
        line_without_comment = re.sub(r'(?<!["\'])\s*#.*$', '', line)
        
        # 3. 빈 줄이 아닐 경우에만 [원본 줄 번호]와 함께 저장
        if line_without_comment.strip():
            clean_lines_with_info.append((orig_line_num, line_without_comment))
            
    return clean_lines_with_info

uploaded_file = st.file_uploader("검사할 파이썬(.py) 파일을 업로드하세요", type=["py"])

if uploaded_file is not None:
    file_bytes = uploaded_file.read()
    code_text = file_bytes.decode("utf-8")
    
    with st.expander("업로드한 코드 미리보기"):
        st.code(code_text, language="python")

    if st.button("보안 취약점 스캔 시작"):
        st.write("---")
        st.subheader("스캔 결과 리포트")
        
        clean_lines_with_info = remove_python_comments_and_docstrings(code_text)
        detected_count = 0
        
        for orig_line_num, line in clean_lines_with_info:
            for rule in SENSITIVE_PATTERNS:
                if rule["pattern"].search(line):
                    detected_count += 1
                    with st.expander(f"[취약점 발견] {rule['name']} (원본 코드 {orig_line_num}번째 줄)"):
                        st.code(line.strip(), language="python")
                        st.error(f"조치 가이드: {rule['guide']}")
                        
        if detected_count == 0:
            st.success("안전: 업로드한 파일에서 주요 보안 취약점이 발견되지 않았습니다.")
        else:
            st.error(f"총 {detected_count}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")
else:
    st.info("검사할 소스 코드 파일을 업로드해 주세요.")
