import streamlit as st
import re

# 웹 페이지 제목 설정
st.title("팀 박지훈: AI 코딩 보안 스캐너")
st.write("바이브 코딩 후 놓치기 쉬운 보안 취약점을 웹에서 즉시 진단하고 KISA 가이드에 따른 한국어 조치 방법을 확인하세요.")

# KISA 가이드 기반 탐지 룰셋
SENSITIVE_PATTERNS = [
    {
        "name": "API 키 및 토큰 노출",
        "pattern": re.compile(r'(api[_-]?key|token|secret|password|passwd)\s*=\s*["\'][A-Za-z0-9_\-\.]+["\']', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] 소스 코드 내에 API 키 또는 비밀번호가 평문으로 하드코딩되어 있습니다. 환경 변수(.env) 파일로 분리하여 관리하세요."
    },
    {
        "name": "SQL 인젝션 (문자열 직접 결합)",
        # SELECT, INSERT 등 뒤에 따옴표가 닫히고 '+' 기호나 f-string 변수가 곧바로 이어지는 위험한 형태 포착
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?(["\']\s*[\+\%]\s*[a-zA-Z0-9_]+|f[\'"].*?\{)', re.IGNORECASE),
        "guide": "[KISA 보안 가이드] SQL 쿼리에 사용자 입력값이나 변수가 문자열 연산(+)으로 직접 결합되어 있습니다. 파라미터 쿼리(PreparedStatement)를 사용하세요."
    }
]

uploaded_file = st.file_uploader("검사할 파일을 업로드하세요 (예: .py)", type=["py", "txt", "js"])

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
        
        lines = code_text.split("\n")
        detected_count = 0
        
        for line_num, line in enumerate(lines, 1):
            for rule in SENSITIVE_PATTERNS:
                if re.search(rule["pattern"], line):
                    detected_count += 1
                    with st.expander(f"[취약점 발견] {rule['name']} ({line_num}번째 줄)"):
                        st.code(line.strip(), language="python")
                        st.error(f"**조치 가이드:** {rule['guide']}")
                        
        if detected_count == 0:
            st.success("안전함: 업로드한 파일에서 주요 보안 취약점이 발견되지 않았습니다!")
        else:
            st.error(f"총 {detected_count}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")
else:
    st.info("검사할 소스 코드 파일을 업로드해주세요.")
