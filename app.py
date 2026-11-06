import ast
import re
import streamlit as st

SQL_KW = re.compile(r'\b(?:SELECT\b.*\bFROM|INSERT\b.*\bINTO|UPDATE\b.*\bSET|DELETE\b.*\bFROM)\b', re.IGNORECASE | re.DOTALL)
SECRET_NAME = re.compile(r'(password|passwd|pwd|secret|api_key|token)', re.IGNORECASE)

GUIDES = {
    "SQL 인젝션": "[KISA 보안 가이드] SQL 쿼리를 문자열 결합/f-string/포맷팅으로 만들고 있습니다. execute(sql, (값,)) 형태의 파라미터 바인딩을 사용하세요.",
    "코드 삽입 (eval/exec)": "[KISA 보안 가이드] eval()/exec()에 변수가 전달됩니다. 사용을 금지하거나 ast.literal_eval 등 안전한 대안을 사용하세요.",
    "경로 조작": "[KISA 보안 가이드] open()에 검증되지 않은 경로가 전달됩니다. os.path.basename()이나 허용 디렉터리 검증을 적용하세요.",
    "OS 명령어 삽입": "[KISA 보안 가이드] 셸을 통해 명령을 실행합니다. shell=False와 인자 리스트 방식을 사용하세요.",
    "안전하지 않은 역직렬화": "[KISA 보안 가이드] 신뢰할 수 없는 데이터를 pickle/yaml.load로 역직렬화하면 코드가 실행될 수 있습니다. json 또는 yaml.safe_load를 사용하세요.",
    "하드코딩된 중요정보": "[KISA 보안 가이드] 비밀번호/키가 소스에 하드코딩되어 있습니다. 환경변수나 비밀 관리 도구를 사용하세요.",
    "취약한 해시 알고리즘": "[KISA 보안 가이드] md5/sha1은 취약합니다. sha256 이상 또는 bcrypt 등을 사용하세요.",
    "SSL 검증 비활성화": "[KISA 보안 가이드] verify=False로 인증서 검증을 끄면 중간자 공격에 노출됩니다.",
    "디버그 모드 활성화": "[KISA 보안 가이드] debug=True 상태로 배포하면 내부 정보가 노출됩니다.",
}

SQL_EXEC_FUNCS = {"execute", "executemany", "executescript", "raw"}


def _call_name(func):
    """os.system -> 'os.system', eval -> 'eval', cur.execute -> 'cur.execute'"""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _is_str_const(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _has_sql_text(node):
    """노드 안의 문자열 상수들에 SQL 키워드가 있는가"""
    text = " ".join(n.value for n in ast.walk(node) if _is_str_const(n))
    return bool(SQL_KW.search(text))


def _is_dynamic_str(node):
    """변수가 섞여 만들어지는 문자열인가 (f-string / + / % / .format)"""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (_is_str_const(node.left) and _is_str_const(node.right))
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"):
        return True
    return False


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, source):
        self.lines = source.splitlines()
        self.findings = []
        self.tainted_sql = {}   # 위험하게 만든 SQL을 담은 변수명 -> 줄 번호
        self.sql_vars = set()   # SQL 상수 문자열을 담은 변수명 (+= 누적 감시용)

    def report(self, rule, node, extra=""):
        line = self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else ""
        self.findings.append({"rule": rule, "line": node.lineno, "code": line,
                              "guide": GUIDES[rule], "extra": extra})

    # ---- 대입문: SQL 변수 추적 + 하드코딩 비밀값 ----
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                if _is_dynamic_str(node.value) and _has_sql_text(node.value):
                    self.tainted_sql[target.id] = node.lineno
                else:
                    self.tainted_sql.pop(target.id, None)   # 안전한 값으로 덮어쓰면 해제
                if _is_str_const(node.value) and _has_sql_text(node.value):
                    self.sql_vars.add(target.id)
                else:
                    self.sql_vars.discard(target.id)
                if (SECRET_NAME.search(target.id) and _is_str_const(node.value)
                        and len(node.value.value) >= 4):
                    self.report("하드코딩된 중요정보", node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):   # query += user_id
        if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            name = node.target.id
            is_sql_var = name in self.sql_vars or name in self.tainted_sql
            if is_sql_var and not _is_str_const(node.value):
                self.tainted_sql[name] = node.lineno
        self.generic_visit(node)

    # ---- 함수 호출 ----
    def visit_Call(self, node):
        name = _call_name(node.func)
        short = name.split(".")[-1]
        args = node.args
        kw = {k.arg: k.value for k in node.keywords if k.arg}

        # SQL 인젝션: execute(동적 SQL) 또는 execute(위험 변수)
        if short in SQL_EXEC_FUNCS and args:
            q = args[0]
            if _is_dynamic_str(q) and _has_sql_text(q):
                self.report("SQL 인젝션", node)
            elif isinstance(q, ast.Name) and q.id in self.tainted_sql:
                self.report("SQL 인젝션", node,
                            f"변수 '{q.id}'는 {self.tainted_sql[q.id]}번째 줄에서 위험하게 생성됨")

        # eval/exec: 메서드(model.eval)는 제외, 상수 인자도 제외
        if isinstance(node.func, ast.Name) and name in ("eval", "exec"):
            if args and not _is_str_const(args[0]):
                self.report("코드 삽입 (eval/exec)", node)

        # 경로 조작: 내장 open()에 상수가 아닌 경로
        if isinstance(node.func, ast.Name) and name == "open" and args:
            p = args[0]
            if not _is_str_const(p) and not (isinstance(p, ast.Name) and p.id.isupper()):
                self.report("경로 조작", node)

        # OS 명령어 삽입
        if name in ("os.system", "os.popen"):
            self.report("OS 명령어 삽입", node)
        if name.startswith("subprocess.") and isinstance(kw.get("shell"), ast.Constant) \
                and kw["shell"].value is True:
            self.report("OS 명령어 삽입", node)

        # 역직렬화
        if name in ("pickle.load", "pickle.loads"):
            self.report("안전하지 않은 역직렬화", node)
        if name == "yaml.load":
            loader = kw.get("Loader")
            if not (loader is not None and _call_name(loader) in ("yaml.SafeLoader", "SafeLoader")):
                self.report("안전하지 않은 역직렬화", node)

        # 취약한 해시
        if name in ("hashlib.md5", "hashlib.sha1"):
            self.report("취약한 해시 알고리즘", node)

        # verify=False / debug=True
        if isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
            self.report("SSL 검증 비활성화", node)
        if isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
            self.report("디버그 모드 활성화", node)

        self.generic_visit(node)


def scan_source(source):
    """반환: (findings 리스트, 에러메시지 또는 None)"""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [], f"파이썬 문법 오류로 분석할 수 없습니다 ({e.lineno}번째 줄: {e.msg})"
    visitor = SecurityVisitor(source)
    visitor.visit(tree)
    findings = sorted(visitor.findings, key=lambda f: f["line"])
    return findings, None


# ================= Streamlit 웹 화면 =================
TEST_FILE_NAME = "test.py"   # 같은 폴더에 올려둘 테스트 파일 이름


def _decode(file_bytes):
    for enc in ("utf-8", "cp949"):
        try:
            return file_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return file_bytes.decode("utf-8", errors="replace")


def main():
    # 제목 및 설명
    st.title("팀 SC: AI 코딩 보안 스캐너")
    st.write("바이브 코딩 후 놓치기 쉬운 보안 취약점을 웹에서 즉시 진단하고 KISA 가이드에 따른 조치 방법을 제공합니다.")

    # 테스트 파일 다운로드 및 미리보기
    st.markdown("---")
    st.subheader("테스트 파일 다운로드 및 미리보기")
    st.write(f"스캐너 진단 테스트를 위한 샘플 파일({TEST_FILE_NAME})입니다. 파일을 다운로드하거나 아래 미리보기를 통해 코드를 확인하세요.")

    try:
        with open(TEST_FILE_NAME, "r", encoding="utf-8") as f:
            test_content = f.read()
        st.download_button(
            label=f"테스트 파일({TEST_FILE_NAME}) 다운로드",
            data=test_content,
            file_name=TEST_FILE_NAME,
            mime="text/plain",
        )
        with st.expander(f"연동된 {TEST_FILE_NAME} 코드 미리보기"):
            st.code(test_content, language="python")
    except FileNotFoundError:
        st.warning(f"경고: '{TEST_FILE_NAME}' 파일이 동일한 폴더에 존재하지 않습니다. {TEST_FILE_NAME} 파일을 생성해 주세요.")

    st.markdown("---")

    # 검사할 소스 파일 업로드 및 미리보기
    uploaded_file = st.file_uploader("검사할 파이썬(.py) 파일을 업로드하세요", type=["py"])
    if uploaded_file is None:
        st.info("검사할 소스 코드 파일을 업로드해 주세요.")
        return

    code_text = _decode(uploaded_file.read())
    with st.expander("업로드한 코드 미리보기"):
        st.code(code_text, language="python")

    # 스캔
    if st.button("보안 취약점 스캔 시작"):
        st.write("---")
        st.subheader("스캔 결과 리포트")

        findings, error = scan_source(code_text)
        if error:
            st.warning(error)
            return

        for f in findings:
            with st.expander(f"[취약점 발견] {f['rule']} (원본 코드 {f['line']}번째 줄)"):
                st.code(f["code"], language="python")
                if f["extra"]:
                    st.info(f["extra"])
                st.error(f"조치 가이드: {f['guide']}")

        if not findings:
            st.success("안전: 업로드한 파일에서 주요 보안 취약점이 발견되지 않았습니다.")
        else:
            st.error(f"총 {len(findings)}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")


if __name__ == "__main__":   # streamlit run ast_scanner.py 로 실행할 때만 화면 표시
    main()
