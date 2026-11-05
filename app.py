import streamlit as st
import re


st.title("팀 SC: AI 코딩 보안 스캐너")
st.write("바이브 코딩 후 놓치기 쉬운 보안 취약점을 웹에서 즉시 진단하고 KISA 가이드에 따른 조치 방법을 제공합니다.")

st.markdown("test.py")
st.subheader("테스트 파일 다운로드 및 미리보기")
st.write("스캐너 진단 테스트를 위한 샘플 파일(`test.py`)입니다. 파일을 다운로드하거나 아래 미리보기를 통해 코드를 확인하세요.")


#테스트 할 파일
target_test_file = "test.py"

try:
    # 실제 서버 폴더에 있는 test.py 파일을 읽어옴
    with open(target_test_file, "r", encoding="utf-8") as f:
        file_content = f.read()
    
    # 다운로드 버튼 생성
    st.download_button(
        label="테스트 파일(test.py) 다운로드",
        data=file_content,
        file_name=target_test_file,
        mime="text/plain"
    )

    # 다운로드될 파일의 코드를 웹 화면에서 미리 확인할 수 있는 확장 영역
    with st.expander("연동된 test.py 코드 미리보기"):
        st.code(file_content, language="python")

except FileNotFoundError:
    # 같은 폴더에 test.py가 없을 경우 경고 메시지 출력
    st.warning(f"경고: '{target_test_file}' 파일이 동일한 폴더에 존재하지 않습니다. test.py 파일을 생성해 주세요.")

st.markdown("---")

# 3. KISA 가이드 기반 취약점 탐지 룰셋 (정규식 패턴 정의)
SENSITIVE_PATTERNS = [
    {
        "name": "SQL 인젝션 (문자열 + 연산 쿼리 결합)",
        # SQL 문장 안에서 덧셈 연산(+)으로 변수가 곧바로 이어 붙여지는 패턴 감지
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*[a-zA-Z0-9_]+', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 변수가 문자열 연산(+)으로 직접 결합되어 있습니다. 파라미터 바인딩 방식을 사용하세요."
    },
    {
        "name": "SQL 인젝션 (f-string 및 포맷팅 결합)",
        # SQL 문장 안에서 f-string이나 %s 포맷팅 기호로 변수가 결합되는 패턴 감지
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?f?["\'].*?(\{.*?\}|\%s)', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 f-string이나 포맷팅 기호가 포함되어 있습니다. 인자화된 쿼리와 바인딩 인자를 분리하여 사용하세요."
    },
    {
        "name": "코드 삽입 취약점 (위험한 eval/exec 함수 사용)",
        # 코드 내에서 eval() 또는 exec() 함수가 사용된 패턴 감지
        "pattern": re.compile(r'\b(eval|exec)\s*\(', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] 외부 입력값이 검증 없이 eval() 또는 exec() 함수에 전달되면 임의의 코드가 실행될 수 있습니다. 사전 검증(isalnum 등)을 거치거나 해당 함수 사용을 금지하세요."
    }
]

# 4. 주석 및 독스트링 오탐 방지 전처리 함수
def remove_python_comments_and_docstrings(source_code):
   
    # 여러 줄 주석 및 독스트링 제거
    code_no_docstrings = re.sub(r'(""".*?"""|\'\'\'.*?\'\'\')', '', source_code, flags=re.DOTALL)
    
    clean_lines = []
    for line in code_no_docstrings.splitlines():
        # 인라인 주석(# 뒤의 내용) 제거
        line_without_comment = re.sub(r'(?<!["\'])\s*#.*$', '', line)
        # 빈 줄이 아닌 유효한 코드 라인만 리스트에 담음
        if line_without_comment.strip():
            clean_lines.append(line_without_comment)
            
    return clean_lines

# 5. 사용자 파일 업로드 및 스캔 실행 인터페이스
uploaded_file = st.file_uploader("검사할 파이썬(.py) 파일을 업로드하세요", type=["py"])

if uploaded_file is not None:
    # 업로드된 파일 바이트를 읽어 UTF-8 텍스트로 디코딩
    file_bytes = uploaded_file.read()
    code_text = file_bytes.decode("utf-8")
    
    # 업로드한 파일의 전체 코드 미리보기 탭
    with st.expander("업로드한 코드 미리보기"):
        st.code(code_text, language="python")

    # '보안 취약점 스캔 시작' 버튼 클릭 시 동작
    if st.button("보안 취약점 스캔 시작"):
        st.write("---")
        st.subheader("스캔 결과 리포트")
        
        # 주석 제거 전처리 함수를 통과시켜 순수 코드 라인 추출
        clean_lines = remove_python_comments_and_docstrings(code_text)
        detected_count = 0
        
        # 정제된 코드 라인을 한 줄씩 순회하며 패턴 검사 수행
        for line_num, line in enumerate(clean_lines, 1):
            for rule in SENSITIVE_PATTERNS:
                if rule["pattern"].search(line):
                    detected_count += 1
                    # 취약점 발견 시 확장 탭으로 문제 코드와 KISA 조치 가이드 출력
                    with st.expander(f"[취약점 발견] {rule['name']} ({line_num}번째 유효 코드 줄)"):
                        st.code(line.strip(), language="python")
                        st.error(f"조치 가이드: {rule['guide']}")
                        
        # 최종 진단 결과 통계 출력
        if detected_count == 0:
            st.success("안전: 업로드한 파일에서 주요 보안 취약점이 발견되지 않았습니다.")
        else:
            st.error(f"총 {detected_count}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")
else:
    # 파일이 업로드되지 않았을 때의 안내 문구
    st.info("검사할 소스 코드 파일을 업로드해 주세요.")
