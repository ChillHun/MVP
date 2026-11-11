import ast
import builtins
import csv
import io
import re
import textwrap
import tokenize
import streamlit as st

# ================= 탐지 패턴 / 상수 =================
SQL_KW = re.compile(r'\b(?:SELECT\b.*\bFROM|INSERT\b.*\bINTO|UPDATE\b.*\bSET|DELETE\b.*\bFROM)\b', re.IGNORECASE | re.DOTALL)
# 이름 '끝'이 비밀값 단어여야 함 (password_label, token_url 같은 이름은 제외)
SECRET_NAME = re.compile(
    r'(?:^|_)(?:password|passwd|pwd|pw|passphrase|secret|secret_key|api_key|apikey|access_key|'
    r'private_key|auth_key|authenticate_key|token|access_token|auth_token|refresh_token)$',
    re.IGNORECASE)
LDAP_FILTER = re.compile(r'\(\s*[&|!]?\s*\(?\s*[A-Za-z][\w.-]*\s*[~<>]?=')
WEAK_CIPHER = re.compile(r'(?:^|\.)(?:DES|ARC2|ARC4|Blowfish|CAST|XOR)\.new$|(?:^|\.)algorithms\.(?:ARC4|Blowfish|CAST5|IDEA|TripleDES)$')
WEAK_CRYPTO_HASH = re.compile(r'(?:^|\.)(?:MD2|MD4|MD5|SHA1|SHA)\.new$')

GUIDES = {
    # ---- 입력데이터 검증 및 표현 ----
    "SQL 인젝션": "[KISA 보안 가이드 1-1] SQL 쿼리를 문자열 결합/f-string/포맷팅으로 만들고 있습니다. execute(sql, (값,)) 형태의 파라미터 바인딩을 사용하세요.",
    "코드 삽입 (eval/exec)": "[KISA 보안 가이드 1-2] 검증되지 않은 값이 eval()/exec()에 전달됩니다. 사용을 금지하거나 화이트리스트/isalnum() 등으로 사전 검증하세요.",
    "경로 조작": "[KISA 보안 가이드 1-3] 외부 입력값이 파일 경로로 사용됩니다. 경로 조작 문자(/, \\, ..)를 제거하거나 os.path.basename(), 허용 목록 검증을 적용하세요.",
    "자원 삽입": "[KISA 보안 가이드 1-3] 외부 입력값이 소켓 포트 등 자원 식별자로 사용됩니다. 허용 목록(화이트리스트)에 포함된 값만 사용하세요.",
    "크로스사이트 스크립트(XSS)": "[KISA 보안 가이드 1-4] mark_safe/Markup 등으로 이스케이프를 해제했습니다. 신뢰할 수 없는 데이터는 html.escape()로 치환하고 이스케이프 해제를 사용하지 마세요.",
    "OS 명령어 삽입": "[KISA 보안 가이드 1-5] 검증되지 않은 값으로 셸 명령을 실행합니다. shell=False와 인자 리스트 방식을 사용하고 실행 가능한 명령은 화이트리스트로 제한하세요.",
    "신뢰되지 않은 URL 자동접속": "[KISA 보안 가이드 1-7] 외부 입력 URL로 리다이렉트합니다. 허용 URL 목록으로 검증한 뒤 이동하세요.",
    "부적절한 XML 외부 개체 참조": "[KISA 보안 가이드 1-8] XML 외부 엔티티 처리가 활성화되어 있습니다. feature_external_ges=False, resolve_entities=False로 설정하세요.",
    "XML 삽입(XPath)": "[KISA 보안 가이드 1-9] XPath 질의를 문자열 결합으로 생성합니다. xpath(query, 변수명=값) 형태로 인자화하세요.",
    "LDAP 삽입": "[KISA 보안 가이드 1-10] LDAP 필터에 외부 입력값이 그대로 결합됩니다. escape_filter_chars()로 이스케이프한 뒤 사용하세요.",
    "크로스사이트 요청 위조(CSRF)": "[KISA 보안 가이드 1-11] CSRF 보호가 해제되어 있습니다. csrf_exempt 사용을 피하고 CsrfViewMiddleware/CSRFProtect를 활성화하세요.",
    "서버사이드 요청 위조(SSRF)": "[KISA 보안 가이드 1-12] 외부 입력 주소로 서버가 직접 요청을 보냅니다. 허용 서버 목록(화이트리스트)으로 검증하세요.",
    "HTTP 응답분할": "[KISA 보안 가이드 1-13] 외부 입력값이 응답 헤더에 그대로 들어갑니다. \\r, \\n 개행문자를 제거한 뒤 사용하세요.",
    "포맷 스트링 삽입": "[KISA 보안 가이드 1-16] 외부 입력 문자열을 포맷 문자열로 사용합니다. 고정된 포맷 문자열에 값을 바인딩하세요.",
    # ---- 보안기능 ----
    "중요 자원 권한 설정": "[KISA 보안 가이드 2-3] 중요 파일에 그룹/기타 사용자 쓰기 권한을 부여합니다. 0o600/0o700 등 최소 권한만 부여하세요.",
    "취약한 해시 알고리즘": "[KISA 보안 가이드 2-4] md5/sha1은 취약합니다. sha256 이상을 사용하세요.",
    "취약한 암호화 알고리즘": "[KISA 보안 가이드 2-4] DES/RC2/RC4/Blowfish 등은 취약합니다. AES, ARIA, SEED 등 검증된 알고리즘을 사용하세요.",
    "하드코딩된 중요정보": "[KISA 보안 가이드 2-6] 비밀번호/키가 소스에 하드코딩되어 있습니다. 환경변수나 암호화된 별도 설정 파일을 사용하세요.",
    "중요정보 노출(로그/출력)": "[보안 권고] 비밀번호/토큰/키 값을 print 또는 로그로 출력합니다. 콘솔·로그 파일은 여러 사람이 보거나 외부로 수집될 수 있으므로 중요정보는 출력하지 말고, 필요하면 마스킹(****)하세요.",
    "충분하지 않은 키 길이": "[KISA 보안 가이드 2-7] 키 길이가 짧습니다. RSA/DSA는 2048비트 이상, ECC는 224비트 이상을 사용하세요.",
    "적절하지 않은 난수 값": "[KISA 보안 가이드 2-8] 보안 용도(OTP, 토큰, 세션키 등)에 random 모듈을 사용합니다. secrets 모듈을 사용하세요.",
    "SSL 검증 비활성화": "[KISA 보안 가이드 2-11] 인증서 검증을 끄면 중간자 공격에 노출됩니다. PROTOCOL_TLS_CLIENT / verify=True로 인증서를 검증하세요.",
    "영속 쿠키 정보 노출": "[KISA 보안 가이드 2-12] 쿠키 만료시간이 과도하게 깁니다. 만료시간을 최소화하고 secure/httponly 옵션을 설정하세요.",
    # ---- 시간 및 상태 ----
    "종료되지 않는 재귀": "[KISA 보안 가이드 3-2] 재귀 제한을 과도하게 늘리면 스택 오버플로우/자원 고갈이 발생할 수 있습니다. 기본값(1000) 수준을 유지하세요.",
    # ---- 에러처리 ----
    "오류 메시지 정보노출": "[KISA 보안 가이드 4-1] 스택 트레이스를 출력하면 내부 구조가 노출됩니다. 최소 정보만 로깅(logger.error)하세요.",
    "오류상황 대응 부재": "[KISA 보안 가이드 4-2] 예외를 잡고 아무 조치도 하지 않습니다(pass). 적절한 예외 처리를 추가하세요.",
    "부적절한 예외 처리": "[KISA 보안 가이드 4-3] except: 로 모든 예외를 광범위하게 잡고 있습니다. 발생 가능한 예외를 구체적으로 나눠 처리하세요.",
    # ---- 코드오류 / 캡슐화 ----
    "안전하지 않은 역직렬화": "[KISA 보안 가이드 5-3] 신뢰할 수 없는 데이터를 pickle/yaml.load로 역직렬화하면 코드가 실행될 수 있습니다. 서명(HMAC) 검증 후 사용하거나 json / yaml.safe_load를 사용하세요.",
    "디버그 모드 활성화": "[KISA 보안 가이드 6-2] DEBUG 모드로 배포하면 내부 정보가 노출됩니다. 운영 환경에서는 DEBUG=False로 설정하세요.",
}

SQL_EXEC_FUNCS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
# 외부 입력으로 간주하는 request 속성 (request.method 등은 제외)
REQUEST_ATTRS = {"GET", "POST", "FILES", "COOKIES", "META", "body", "data", "form", "args", "values",
                 "json", "get_json", "files", "cookies", "headers", "query_params", "path_params", "referrer"}
ENV_GET_FUNCS = {"os.environ.get", "os.getenv", "os.environ.setdefault"}
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
# 웹 프레임워크 경로 함수: @app.get("/x"), @router.post(...), @app.route("/<name>") 의 매개변수 = 외부 입력
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "head", "options", "route", "api_route",
                    "websocket", "api_view"}
DEPENDENCY_FUNCS = {"Depends", "Security"}   # FastAPI 의존성 주입 값은 서버가 만든 값
SAFE_PARAM_TYPES = {"Request", "WebSocket", "HTTPConnection", "Session", "AsyncSession",
                    "BackgroundTasks", "Response"}
# Streamlit 사용자 입력 위젯 (st.query_params 도 외부 입력)
STREAMLIT_INPUTS = {"text_input", "text_area", "number_input", "chat_input", "file_uploader",
                    "camera_input", "audio_input", "data_editor"}
# 외부 입력이 이 함수들을 거쳐도 여전히 외부 입력 (그 밖의 함수를 거친 값은 가공된 값으로 보고 추적 중단)
TAINT_PASSTHROUGH = ("os.path.", "pathlib.", "posixpath.", "ntpath.", "urllib.parse.", "base64.",
                     "binascii.", "json.", "codecs.", "textwrap.", "string.", "html.unescape", "shlex.split")
BUILTIN_NAMES = set(dir(builtins))
# 반환값을 '검증/치환된 값'으로 보는 함수
SANITIZERS = {"escape", "escape_filter_chars", "escape_dn_chars", "basename", "secure_filename", "quote", "clean"}
GUARD_METHODS = {"isalnum", "isalpha", "isdigit", "isdecimal", "isnumeric", "isidentifier"}
VERIFY_NAME = re.compile(r'verif|valid', re.IGNORECASE)
RESPONSE_FACTORIES = {"HttpResponse", "JsonResponse", "StreamingHttpResponse", "FileResponse",
                      "HttpResponseRedirect", "Response", "make_response"}
PATH_FUNCS = {"io.open", "codecs.open", "os.open", "os.remove", "os.unlink", "os.rmdir",
              "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.move", "flask.send_file"}
SSRF_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
              "requests.patch", "requests.options", "urllib.request.urlopen", "httpx.get", "httpx.post"}
PATH_SINK_SHORT = {"FileResponse", "send_file"}   # FastAPI/Starlette FileResponse, Flask send_file
REDIRECT_FUNCS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"}
DESER_FUNCS = {"pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads",
               "dill.load", "dill.loads", "marshal.load", "marshal.loads", "jsonpickle.decode"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample", "getrandbits",
                "uniform", "shuffle", "randbytes"}
SECURITY_WORDS = {"otp", "token", "session", "password", "passwd", "pwd", "pw", "secret", "salt",
                  "nonce", "csrf", "key", "apikey", "auth", "crypto", "cipher", "iv", "sign",
                  "signature", "verification", "verify"}
EXIT_STMTS = (ast.Return, ast.Raise, ast.Continue, ast.Break)
IGNORED_PASS_EXC = {"ImportError", "ModuleNotFoundError"}
COOKIE_MAX_AGE_LIMIT = 60 * 60 * 24 * 30   # 30일 초과 시 영속 쿠키로 판단
RECURSION_LIMIT_MAX = 10000                 # 이 값을 넘게 설정하면 과도한 재귀 제한으로 판단


# ================= 공통 헬퍼 =================
def _raw_name(func):
    """os.system -> 'os.system', eval -> 'eval', cur.execute -> 'cur.execute'"""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _raw_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _is_str_const(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _all_const_str(node):
    """'a' + 'b' + 'c' 처럼 상수끼리만 결합된 문자열인가"""
    if _is_str_const(node):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _all_const_str(node.left) and _all_const_str(node.right)
    return False


def _is_dynamic_str(node):
    """변수가 섞여 만들어지는 문자열인가 (f-string / + / % / .format)"""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not _all_const_str(node)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"):
        return True
    return False


def _const_text(node):
    return " ".join(n.value for n in ast.walk(node) if _is_str_const(n))


def _const_int(node):
    """60*60*24 같은 정수 상수식을 계산 (계산 불가 시 None)"""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _const_int(node.operand)
        return -v if v is not None else None
    if isinstance(node, ast.BinOp):
        a, b = _const_int(node.left), _const_int(node.right)
        if a is None or b is None:
            return None
        ops = {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
               ast.Pow: lambda: a ** b if b < 64 else None, ast.BitOr: lambda: a | b}
        fn = ops.get(type(node.op))
        return fn() if fn else None
    return None


def _value_names(node):
    """식 안에서 '값'으로 쓰인 변수 이름들 (호출되는 함수 이름은 제외)"""
    if node is None:
        return set()
    skip = {id(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and id(n) not in skip}


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out = []
        for e in target.elts:
            out.extend(_target_names(e))
        return out
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _target_key(target):
    """대입 대상의 '이름' (password / self.password / config['SECRET_KEY'])"""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and _is_str_const(target.slice):
        return target.slice.value
    return None


def _secret_literal(node):
    """하드코딩된 비밀값으로 볼 만한 문자열 상수인가"""
    if not _is_str_const(node):
        return False
    v = node.value
    if len(v) < 4 or not v.isascii() or any(c.isspace() for c in v):
        return False
    if v.startswith(("http://", "https://", "<", "${", "{{", "%(")):
        return False
    if re.fullmatch(r'[A-Z][A-Z0-9_]*', v):   # 'DB_PASSWORD' 같은 환경변수 이름
        return False
    return True


def _output_names(node):
    """출력되는 값 자체의 이름들. print(f"{user.password}") -> ['password']
    함수 호출 결과(len(password), hash(pw) 등)는 원래 값이 아니므로 제외 (str/repr 은 그대로 출력되므로 포함)"""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.Subscript):
        return [node.slice.value] if _is_str_const(node.slice) else []
    if isinstance(node, ast.FormattedValue):
        return _output_names(node.value)
    if isinstance(node, ast.JoinedStr):
        return [n for v in node.values for n in _output_names(v)]
    if isinstance(node, ast.BinOp):
        return _output_names(node.left) + _output_names(node.right)
    if isinstance(node, (ast.Tuple, ast.List)):
        return [n for e in node.elts for n in _output_names(e)]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("str", "repr", "format"):
        return [n for a in node.args for n in _output_names(a)]
    return []


def _name_tokens(name):
    return {t.lower() for t in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+', name or "")}


def _comment_columns(source):
    """줄 번호 -> 주석 시작 컬럼 (리포트 코드에서 주석을 잘라내기 위함)"""
    cols = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                cols[tok.start[0]] = tok.start[1]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return cols   # 토큰화 실패 시 그때까지 찾은 주석 위치만 사용
    return cols


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, source):
        self.lines = source.splitlines()
        self.comment_col = _comment_columns(source)
        self.findings = []
        self._seen = set()
        self.aliases = {}        # import 별칭: Popen -> subprocess.Popen, np -> numpy
        self.func_stack = []     # 현재 함수 이름 (난수 사용 문맥 판단용)
        self.assign_names = set()
        self.local_funcs = set()   # 이 파일에서 정의한 함수 이름 (내장 함수와 구분)
        self.dep_aliases = set()   # DbSession = Annotated[Session, Depends(get_db)] 같은 의존성 타입 별칭
        self._reset_scope()

    # ---------- 스코프 (함수 단위로 변수 상태를 분리) ----------
    def _reset_scope(self):
        self.tainted_sql = {}    # 위험하게 만든 SQL을 담은 변수명 -> 줄 번호
        self.sql_vars = set()    # SQL 상수 문자열을 담은 변수명 (+= 누적, % 포맷 감시용)
        self.tainted = set()     # 외부 입력(request.*, input(), sys.argv)에서 온 변수
        self.safe = set()        # 상수/검증/치환을 거친 변수
        self.dyn_vars = {}       # 검증 안 된 값으로 동적 생성된 문자열 변수 -> 값 노드
        self.response_vars = set()
        self.verified = 0        # hmac.compare_digest / 서명 검증 if 블록 깊이

    def _save_scope(self):
        return (self.tainted_sql, self.sql_vars, self.tainted, self.safe,
                self.dyn_vars, self.response_vars, self.verified)

    def _restore_scope(self, saved):
        (self.tainted_sql, self.sql_vars, self.tainted, self.safe,
         self.dyn_vars, self.response_vars, self.verified) = saved

    # ---------- 리포트 ----------
    def _snippet(self, node, single_line):
        start = node.lineno
        end = start if single_line else min(getattr(node, "end_lineno", None) or start, start + 4)
        out = []
        for ln in range(start, end + 1):
            if ln > len(self.lines):
                break
            text = self.lines[ln - 1]
            col = self.comment_col.get(ln)
            if col is not None:
                text = text[:col]          # 주석은 제외하고 코드만 표시
            if text.strip():
                out.append(text.rstrip())
        return textwrap.dedent("\n".join(out)).strip()

    def report(self, rule, node, extra="", single_line=False):
        key = (rule, node.lineno)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({"rule": rule, "line": node.lineno,
                              "code": self._snippet(node, single_line),
                              "guide": GUIDES[rule], "extra": extra})

    # ---------- 이름 / 오염(taint) 판단 ----------
    def _call_name(self, func):
        raw = _raw_name(func)
        if not raw:
            return ""
        head, _, rest = raw.partition(".")
        full = self.aliases.get(head, head)
        return f"{full}.{rest}" if rest else full

    def _is_request(self, node):
        parts = _raw_name(node).split(".")
        for i, p in enumerate(parts[:-1]):
            if p == "request" and parts[i + 1] in REQUEST_ATTRS:
                return True
        return False

    def _is_sanitizer_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = self._call_name(node.func)
        short = name.split(".")[-1]
        if short in SANITIZERS:
            return True
        # x.replace('..', '') / re.sub(패턴, '', x): 위험 문자 제거
        if short == "replace" and len(node.args) >= 2 and _is_str_const(node.args[1]) \
                and node.args[1].value == "":
            return True
        if name == "re.sub" and len(node.args) >= 2 and _is_str_const(node.args[1]) \
                and node.args[1].value == "":
            return True
        return False

    def _uses_streamlit(self):
        return "streamlit" in self.aliases.values()

    def _is_passthrough(self, func, name):
        """외부 입력을 가공 없이 그대로 전달하는 함수인가 (str(), os.path.join, Path ...)"""
        if isinstance(func, ast.Name) and func.id not in self.aliases and func.id not in self.local_funcs:
            return func.id in BUILTIN_NAMES
        return name.startswith(TAINT_PASSTHROUGH)

    def _tainted(self, node):
        """외부 입력에서 온 (검증되지 않은) 값인가"""
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted and node.id not in self.safe
        if isinstance(node, ast.Call):
            if self._is_sanitizer_call(node):
                return False
            name = self._call_name(node.func)
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return True
            if self._uses_streamlit() and name.split(".")[-1] in STREAMLIT_INPUTS:   # st.text_input(...)
                return True
            if isinstance(node.func, ast.Attribute):
                if self._tainted(node.func):            # 외부입력.get() / request.get_json()
                    return True
                if not _is_str_const(node.func.value) and not self._is_passthrough(node.func, name):
                    return False                        # db.get(User, uid) 처럼 가공된 결과
            elif not self._is_passthrough(node.func, name):
                return False                            # 검증 함수 등 내부 동작을 알 수 없는 함수의 결과
            return (any(self._tainted(a) for a in node.args)
                    or any(self._tainted(k.value) for k in node.keywords))
        if isinstance(node, ast.Attribute):
            name = self._call_name(node)
            if self._is_request(node) or name == "sys.argv" or name.startswith("streamlit.query_params"):
                return True
            return self._tainted(node.value)
        return any(self._tainted(c) for c in ast.iter_child_nodes(node))

    def _is_clean(self, node):
        """상수이거나, 검증/치환을 거친 변수만으로 이뤄진 값인가"""
        if node is None:
            return False
        if self._is_sanitizer_call(node):
            return True
        if self._tainted(node):
            return False
        for n in _value_names(node):
            if not (n in self.safe or n.isupper() or n in self.aliases):
                return False
        return True

    def _is_dyn_unclean(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.dyn_vars
        return _is_dynamic_str(node) and not self._is_clean(node)

    def _has_sql_text(self, node):
        """SQL 키워드가 들어있는 문자열이 쓰였는가 (SQL 상수를 담은 변수 포함)"""
        if SQL_KW.search(_const_text(node)):
            return True
        return any(isinstance(n, ast.Name) and n.id in self.sql_vars for n in ast.walk(node))

    def _security_context(self):
        words = set()
        if self.func_stack:
            words |= _name_tokens(self.func_stack[-1])
        for n in self.assign_names:
            words |= _name_tokens(n)
        return bool(words & SECURITY_WORDS)

    # ---------- import (별칭 추적) ----------
    def visit_Import(self, node):
        for a in node.names:
            if a.asname:
                self.aliases[a.asname] = a.name
            else:
                head = a.name.split(".")[0]
                self.aliases[head] = head

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name

    # ---------- 함수 정의 ----------
    def visit_FunctionDef(self, node):
        for d in node.decorator_list:
            target = d.func if isinstance(d, ast.Call) else d
            if self._call_name(target).split(".")[-1] == "csrf_exempt":
                self.report("크로스사이트 요청 위조(CSRF)", d, single_line=True)
        self.local_funcs.add(node.name)
        saved = self._save_scope()
        self._reset_scope()
        if self._is_route(node):
            self.tainted |= self._route_params(node)
        self.func_stack.append(node.name)
        self.generic_visit(node)
        self.func_stack.pop()
        self._restore_scope(saved)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _is_route(self, node):
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and self._call_name(d.func).split(".")[-1] in ROUTE_DECORATORS:
                return True
        return False

    def _is_dependency(self, node):
        """Depends(...) / Security(...) 이 들어 있거나, 그런 타입 별칭(DbSession 등)인가"""
        if node is None:
            return False
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and self._call_name(n.func).split(".")[-1] in DEPENDENCY_FUNCS:
                return True
            if isinstance(n, ast.Name) and n.id in self.dep_aliases:
                return True
        return False

    def _route_params(self, node):
        """경로 함수 매개변수 중 외부 입력인 것 (의존성 주입, Request/Session 객체는 제외)"""
        a = node.args
        positional = a.posonlyargs + a.args
        defaults = [None] * (len(positional) - len(a.defaults)) + list(a.defaults)
        pairs = list(zip(positional, defaults)) + list(zip(a.kwonlyargs, a.kw_defaults))
        names = set()
        for arg, default in pairs:
            if arg.arg in ("self", "cls"):
                continue
            if self._is_dependency(arg.annotation) or self._is_dependency(default):
                continue
            ann_names = {_raw_name(n).split(".")[-1] for n in ast.walk(arg.annotation)
                         if isinstance(n, (ast.Name, ast.Attribute))} if arg.annotation else set()
            if ann_names & SAFE_PARAM_TYPES:
                continue
            names.add(arg.arg)
        return names

    # ---------- if 문: 화이트리스트/isalnum/서명 검증 가드 ----------
    def _guard(self, test):
        """반환: (검증되는 변수 집합, '+'(참일 때 안전) / '-'(거짓일 때 안전) / None, 서명검증 여부)"""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            names, pol, _ = self._guard(test.operand)
            return names, {"+": "-", "-": "+"}.get(pol), False
        if isinstance(test, ast.BoolOp):
            parts = [self._guard(v) for v in test.values]
            want = "+" if isinstance(test.op, ast.And) else "-"
            hits = [p for p in parts if p[1] == want]
            if not hits:
                return set(), None, False
            names = set().union(*(p[0] for p in hits))
            return names, want, any(p[2] for p in hits)
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, right = test.ops[0], test.comparators[0]
            left = _value_names(test.left)
            if isinstance(op, ast.In):
                return left, "+", False
            if isinstance(op, ast.NotIn):
                return left, "-", False
            if isinstance(op, ast.Eq) and isinstance(right, ast.Constant):
                return left, "+", False
            if isinstance(op, ast.NotEq) and isinstance(right, ast.Constant):
                return left, "-", False
            return set(), None, False
        if isinstance(test, ast.Call):
            name = self._call_name(test.func)
            short = name.split(".")[-1]
            if isinstance(test.func, ast.Attribute) and short in GUARD_METHODS:
                return _value_names(test.func.value), "+", False
            if short == "compare_digest":
                return set(), "+", True
            if short in ("match", "fullmatch"):
                args = test.args[1:] if name.startswith("re.") else test.args
                return set().union(*(_value_names(a) for a in args)) if args else set(), "+", False
            if VERIFY_NAME.search(short):
                return set().union(*(_value_names(a) for a in test.args)) if test.args else set(), "+", True
            return set(), None, False
        if isinstance(test, ast.Name) and VERIFY_NAME.search(test.id):
            return set(), "+", True
        return set(), None, False

    def _visit_block(self, stmts, names, verified):
        added = names - self.safe
        self.safe |= added
        self.verified += 1 if verified else 0
        for s in stmts:
            self.visit(s)
        self.verified -= 1 if verified else 0
        self.safe -= added

    def visit_If(self, node):
        names, pol, verified = self._guard(node.test)
        self.visit(node.test)
        self._visit_block(node.body, names if pol == "+" else set(), verified and pol == "+")
        self._visit_block(node.orelse, names if pol == "-" else set(), False)
        # if x not in ALLOW: return  -> 이후 코드에서 x는 검증된 값
        if pol == "-" and node.body and isinstance(node.body[-1], EXIT_STMTS):
            self.safe |= names
        if pol == "+" and node.orelse and isinstance(node.orelse[-1], EXIT_STMTS):
            self.safe |= names

    # ---------- 반복문 ----------
    def visit_For(self, node):
        if self._tainted(node.iter):
            for n in _target_names(node.target):
                self.tainted.add(n)
                self.safe.discard(n)
        self.generic_visit(node)

    # ---------- 예외 처리 ----------
    def visit_ExceptHandler(self, node):
        only_pass = all(isinstance(s, ast.Pass) or
                        (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                         and s.value.value is Ellipsis) for s in node.body)
        exc_name = _raw_name(node.type).split(".")[-1] if node.type is not None else ""
        if only_pass and exc_name not in IGNORED_PASS_EXC:
            self.report("오류상황 대응 부재", node, single_line=True)
        elif node.type is None:
            self.report("부적절한 예외 처리", node, single_line=True)
        self.generic_visit(node)

    # ---------- 대입문 ----------
    def visit_Assign(self, node):
        self._assign(node.targets, node.value, node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._assign([node.target], node.value, node)

    def _assign(self, targets, value, node):
        self.assign_names = {n for t in targets for n in ([_target_key(t)] + _target_names(t)) if n}
        if not self.func_stack and self._is_dependency(value):
            self.dep_aliases |= {n for t in targets for n in _target_names(t)}
        self.visit(value)
        self.assign_names = set()
        tainted = self._tainted(value)
        clean = self._is_clean(value)
        is_dyn = _is_dynamic_str(value) and not clean
        is_resp = (isinstance(value, ast.Call)
                   and self._call_name(value.func).split(".")[-1] in RESPONSE_FACTORIES)
        for target in targets:
            for n in _target_names(target):
                if tainted:
                    self.tainted.add(n)
                    self.safe.discard(n)
                else:
                    self.tainted.discard(n)
                    (self.safe.add if clean else self.safe.discard)(n)
                if is_dyn:
                    self.dyn_vars[n] = value
                else:
                    self.dyn_vars.pop(n, None)
                (self.response_vars.add if is_resp else self.response_vars.discard)(n)
            if isinstance(target, ast.Name):
                self._track_sql(target.id, value, node)
            self._check_assign(target, value, node)
            self.visit(target)

    def _track_sql(self, name, value, node):
        if _is_dynamic_str(value) and self._has_sql_text(value):
            self.tainted_sql[name] = node.lineno
        else:
            self.tainted_sql.pop(name, None)   # 안전한 값으로 덮어쓰면 해제
        if _all_const_str(value) and SQL_KW.search(_const_text(value)):
            self.sql_vars.add(name)
        else:
            self.sql_vars.discard(name)

    def _check_assign(self, target, value, node):
        key = _target_key(target)
        is_true = isinstance(value, ast.Constant) and value.value is True
        is_false = isinstance(value, ast.Constant) and value.value is False

        # 하드코딩된 중요정보: password = "...", self.secret = "...", config['SECRET_KEY'] = "..."
        if key and SECRET_NAME.search(key) and _secret_literal(value):
            self.report("하드코딩된 중요정보", node)

        # 디버그 모드: DEBUG = True / app.debug = True / app.config['DEBUG'] = True
        if is_true and (key == "DEBUG" or (isinstance(target, ast.Attribute) and target.attr == "debug")):
            self.report("디버그 모드 활성화", node)

        # SSL: ctx.verify_mode = ssl.CERT_NONE / ctx.check_hostname = False
        if isinstance(target, ast.Attribute):
            if target.attr == "verify_mode" and self._call_name(value).endswith("CERT_NONE"):
                self.report("SSL 검증 비활성화", node)
            if target.attr == "check_hostname" and is_false:
                self.report("SSL 검증 비활성화", node)

        # CSRF: Flask-WTF 해제 / Django 미들웨어에서 CsrfViewMiddleware 누락
        if key == "WTF_CSRF_ENABLED" and is_false:
            self.report("크로스사이트 요청 위조(CSRF)", node)
        if key == "MIDDLEWARE" and isinstance(value, (ast.List, ast.Tuple)):
            items = [e.value for e in value.elts if _is_str_const(e)]
            if any(i.startswith("django.") for i in items) and \
                    not any(i.endswith("CsrfViewMiddleware") for i in items):
                self.report("크로스사이트 요청 위조(CSRF)", node, single_line=True,
                            extra="MIDDLEWARE 목록에 'django.middleware.csrf.CsrfViewMiddleware'가 없습니다.")

        # 영속 쿠키: SESSION_COOKIE_AGE 과다
        if key == "SESSION_COOKIE_AGE":
            age = _const_int(value)
            if age is not None and age > COOKIE_MAX_AGE_LIMIT:
                self.report("영속 쿠키 정보 노출", node)

        # HTTP 응답분할: res['Header'] = 외부입력 / response.headers['X'] = 외부입력
        if isinstance(target, ast.Subscript):
            obj = target.value
            is_header = ((isinstance(obj, ast.Name) and obj.id in self.response_vars)
                         or (isinstance(obj, ast.Attribute) and obj.attr == "headers"))
            if is_header and self._tainted(value):
                self.report("HTTP 응답분할", node)

    def visit_AugAssign(self, node):   # query += user_id
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            name = node.target.id
            if isinstance(node.op, ast.Add):
                is_sql_var = name in self.sql_vars or name in self.tainted_sql
                if is_sql_var and not _is_str_const(node.value):
                    self.tainted_sql[name] = node.lineno
            if self._tainted(node.value):
                self.tainted.add(name)
                self.safe.discard(name)

    # ---------- 딕셔너리: {"password": "1234"} ----------
    def visit_Dict(self, node):
        for k, v in zip(node.keys, node.values):
            if k is not None and _is_str_const(k) and SECRET_NAME.search(k.value) and _secret_literal(v):
                self.report("하드코딩된 중요정보", v, single_line=True)
        self.generic_visit(node)

    # ---------- 함수 호출 ----------
    def visit_Call(self, node):
        name = self._call_name(node.func)
        short = name.split(".")[-1]
        args = node.args
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        builtin = isinstance(node.func, ast.Name) and node.func.id not in self.aliases
        first = args[0] if args else None

        # SQL 인젝션: execute(동적 SQL) 또는 execute(위험 변수). SQLAlchemy text(...) 도 같은 방식으로 검사
        is_sa_text = short == "text" and name.startswith("sqlalchemy")
        if (short in SQL_EXEC_FUNCS or is_sa_text) and first is not None:
            if _is_dynamic_str(first) and self._has_sql_text(first):
                self.report("SQL 인젝션", node)
            elif isinstance(first, ast.Name) and first.id in self.tainted_sql:
                self.report("SQL 인젝션", node,
                            f"변수 '{first.id}'는 {self.tainted_sql[first.id]}번째 줄에서 위험하게 생성됨")

        # 코드 삽입: 검증되지 않은 값이 eval/exec로 (메서드 model.eval 제외)
        if builtin and name in ("eval", "exec") and first is not None:
            if not self._is_clean(first) and not self.verified:
                self.report("코드 삽입 (eval/exec)", node)

        # 경로 조작: 외부 입력값이 파일 경로로
        if ((builtin and name == "open") or name in PATH_FUNCS) and self._tainted(first):
            self.report("경로 조작", node)
        if short in PATH_SINK_SHORT and self._tainted(kw.get("path", first)):
            self.report("경로 조작", node)

        # 자원 삽입: 외부 입력값이 포트/주소로
        if short in ("bind", "connect", "connect_ex", "create_connection") and \
                isinstance(first, ast.Tuple) and any(self._tainted(e) for e in first.elts):
            self.report("자원 삽입", node)

        # OS 명령어 삽입
        if name in ("os.system", "os.popen") and first is not None and not self._is_clean(first):
            self.report("OS 명령어 삽입", node)
        if name.startswith("subprocess.") and isinstance(kw.get("shell"), ast.Constant) \
                and kw["shell"].value is True and first is not None and not self._is_clean(first):
            self.report("OS 명령어 삽입", node)

        # 역직렬화 (HMAC/서명 검증 블록 안은 제외)
        if not self.verified:
            if name in DESER_FUNCS or name == "yaml.unsafe_load":
                self.report("안전하지 않은 역직렬화", node)
            if name in ("yaml.load", "yaml.load_all"):
                loader = kw.get("Loader") or (args[1] if len(args) > 1 else None)
                if loader is None or self._call_name(loader).split(".")[-1] not in SAFE_YAML_LOADERS:
                    self.report("안전하지 않은 역직렬화", node)

        # 취약한 해시 (usedforsecurity=False 는 비보안 용도로 제외)
        non_security = isinstance(kw.get("usedforsecurity"), ast.Constant) and kw["usedforsecurity"].value is False
        weak_new = (name == "hashlib.new" and _is_str_const(first)
                    and first.value.lower() in ("md5", "sha1", "md4", "md2"))
        if not non_security and (name in ("hashlib.md5", "hashlib.sha1") or weak_new
                                 or WEAK_CRYPTO_HASH.search(name)):
            self.report("취약한 해시 알고리즘", node)

        # 취약한 암호화 알고리즘
        if WEAK_CIPHER.search(name):
            self.report("취약한 암호화 알고리즘", node)

        # 충분하지 않은 키 길이
        self._check_key_length(node, name, short, first, kw)

        # 적절하지 않은 난수: 보안 문맥(otp/token/session/key...)에서 random 사용
        if name.startswith("random.") and short in RANDOM_FUNCS and self._security_context():
            self.report("적절하지 않은 난수 값", node)

        # 중요 자원 권한: 그룹/기타 쓰기 권한
        mode = None
        if name in ("os.chmod", "os.lchmod", "os.fchmod") and len(args) > 1:
            mode = args[1]
        elif short == "chmod" and not name.startswith("os.") and len(args) == 1:
            mode = args[0]
        mode = kw.get("mode", mode)
        if mode is not None:
            m = _const_int(mode)
            stat_bits = {n.attr for n in ast.walk(mode) if isinstance(n, ast.Attribute)}
            if (m is not None and m & 0o022) or stat_bits & {"S_IWOTH", "S_IRWXO", "S_IWGRP", "S_IRWXG"}:
                self.report("중요 자원 권한 설정", node)

        # SSL 검증 비활성화
        if isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
            self.report("SSL 검증 비활성화", node)
        if name == "ssl._create_unverified_context" or \
                (kw.get("cert_reqs") is not None and self._call_name(kw["cert_reqs"]).endswith("CERT_NONE")):
            self.report("SSL 검증 비활성화", node)

        # 디버그 모드
        if isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
            self.report("디버그 모드 활성화", node)

        # XSS: 이스케이프 해제 함수에 동적 값
        if short in ("mark_safe", "Markup", "SafeString", "render_template_string") and \
                first is not None and not self._is_clean(first):
            self.report("크로스사이트 스크립트(XSS)", node)
        # FastAPI HTMLResponse(외부입력) / Streamlit st.html(외부입력)
        if (short == "HTMLResponse" or (name.startswith("streamlit") and short == "html")) and \
                self._tainted(kw.get("content", first)):
            self.report("크로스사이트 스크립트(XSS)", node)
        # Streamlit st.markdown(동적 값, unsafe_allow_html=True)
        unsafe_html = kw.get("unsafe_allow_html")
        if isinstance(unsafe_html, ast.Constant) and unsafe_html.value is True and \
                first is not None and not self._is_clean(first):
            self.report("크로스사이트 스크립트(XSS)", node)

        # 신뢰되지 않은 URL 자동접속
        if short in REDIRECT_FUNCS and self._tainted(first):
            self.report("신뢰되지 않은 URL 자동접속", node)

        # XXE
        if short == "setFeature" and len(args) >= 2 and \
                self._call_name(args[0]).endswith(("feature_external_ges", "feature_external_pes")) and \
                isinstance(args[1], ast.Constant) and args[1].value is True:
            self.report("부적절한 XML 외부 개체 참조", node)
        if short == "XMLParser":
            re_ent, no_net = kw.get("resolve_entities"), kw.get("no_network")
            if (isinstance(re_ent, ast.Constant) and re_ent.value is True) or \
                    (isinstance(no_net, ast.Constant) and no_net.value is False):
                self.report("부적절한 XML 외부 개체 참조", node)

        # XPath 삽입
        if short == "xpath" and first is not None and (self._is_dyn_unclean(first) or self._tainted(first)):
            self.report("XML 삽입(XPath)", node)

        # LDAP 삽입
        if short in ("search", "search_s", "search_st", "search_ext", "search_ext_s"):
            flt = kw.get("search_filter") or kw.get("filterstr")
            if flt is None:
                idx = 1 if short == "search" else 2
                flt = args[idx] if len(args) > idx else None
            if flt is not None and self._is_dyn_unclean(flt):
                src = self.dyn_vars.get(flt.id) if isinstance(flt, ast.Name) else flt
                if LDAP_FILTER.search(_const_text(src)):
                    self.report("LDAP 삽입", node)

        # SSRF
        url = kw.get("url", args[1] if name == "requests.request" and len(args) > 1 else first)
        if (name in SSRF_FUNCS or name == "requests.request") and self._tainted(url):
            self.report("서버사이드 요청 위조(SSRF)", node)

        # 포맷 스트링 삽입: 외부입력.format(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "format_map") \
                and self._tainted(node.func.value):
            self.report("포맷 스트링 삽입", node)

        # 영속 쿠키
        if short == "set_cookie":
            age = _const_int(kw["max_age"]) if "max_age" in kw else None
            if age is not None and age > COOKIE_MAX_AGE_LIMIT:
                self.report("영속 쿠키 정보 노출", node)

        # 오류 메시지 정보노출
        if name in ("traceback.print_exc", "traceback.print_exception", "traceback.print_tb",
                    "traceback.print_stack"):
            self.report("오류 메시지 정보노출", node)

        # 재귀 제한 과다
        if name == "sys.setrecursionlimit":
            limit = _const_int(first) if first is not None else None
            if limit is not None and limit > RECURSION_LIMIT_MAX:
                self.report("종료되지 않는 재귀", node)

        # 함수 키워드 인자로 하드코딩된 비밀값: connect(passwd='1234')
        for k in node.keywords:
            if k.arg and SECRET_NAME.search(k.arg) and _secret_literal(k.value):
                self.report("하드코딩된 중요정보", k.value, single_line=True)

        # 환경변수 기본값으로 하드코딩된 비밀값: os.environ.get("ADMIN_PASSWORD", "admin1234")
        if name in ENV_GET_FUNCS and _is_str_const(first):
            default = args[1] if len(args) > 1 else kw.get("default")
            secret_named = SECRET_NAME.search(first.value) or any(SECRET_NAME.search(n) for n in self.assign_names)
            if secret_named and _secret_literal(default):
                self.report("하드코딩된 중요정보", node,
                            f"환경변수 {first.value} 가 없으면 소스에 적힌 기본값이 그대로 비밀번호/키로 사용됩니다.")

        # 중요정보 출력: print(password) / logger.info(f"token={token}")
        is_log = (builtin and name == "print") or (
            short in LOG_METHODS and isinstance(node.func, ast.Attribute)
            and "log" in _raw_name(node.func.value).lower())
        if is_log:
            leaked = sorted({n for a in list(args) + [k.value for k in node.keywords]
                             for n in _output_names(a) if SECRET_NAME.search(n)})
            if leaked:
                self.report("중요정보 노출(로그/출력)", node, f"출력되는 값: {', '.join(leaked)}")

        self.generic_visit(node)

    def _check_key_length(self, node, name, short, first, kw):
        if name.endswith(("RSA.generate", "DSA.generate")) and first is not None:
            bits = _const_int(first)
            if bits is not None and bits < 2048:
                self.report("충분하지 않은 키 길이", node)
        if short == "generate_private_key" and "key_size" in kw:
            bits = _const_int(kw["key_size"])
            if bits is not None and bits < 2048:
                self.report("충분하지 않은 키 길이", node)
        curve = None
        if short == "get_curve" and _is_str_const(first):
            curve = first.value
        elif name.endswith("ECC.generate") and _is_str_const(kw.get("curve")):
            curve = kw["curve"].value
        elif re.fullmatch(r'SEC[PT]\d+[RK]\d', short):
            curve = short
        if curve:
            m = re.search(r'(\d{3})', curve)
            if m and int(m.group(1)) < 224:
                self.report("충분하지 않은 키 길이", node)


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

    tab_file, tab_folder = st.tabs(["파일 검사", "폴더 검사"])
    with tab_file:
        _single_file_tab()
    with tab_folder:
        _folder_tab()


def _render_finding(f, in_expander=True):
    """탐지 결과 1건 출력. Streamlit 은 expander 중첩이 안 되므로 폴더 검사에서는 평문으로 출력."""
    title = f"[취약점 발견] {f['rule']} (원본 코드 {f['line']}번째 줄)"
    if in_expander:
        with st.expander(title):
            _render_finding_body(f)
    else:
        st.markdown(f"**{title}**")
        _render_finding_body(f)


def _render_finding_body(f):
    st.code(f["code"], language="python")
    if f["extra"]:
        st.info(f["extra"])
    st.error(f"조치 가이드: {f['guide']}")


def _single_file_tab():
    uploaded_file = st.file_uploader("검사할 파이썬(.py) 파일을 업로드하세요", type=["py"], key="single_file")
    if uploaded_file is None:
        st.info("검사할 소스 코드 파일을 업로드해 주세요.")
        return

    code_text = _decode(uploaded_file.read())
    with st.expander("업로드한 코드 미리보기"):
        st.code(code_text, language="python")

    if st.button("보안 취약점 스캔 시작", key="scan_single"):
        st.write("---")
        st.subheader("스캔 결과 리포트")

        findings, error = scan_source(code_text)
        if error:
            st.warning(error)
            return

        for f in findings:
            _render_finding(f)

        if not findings:
            st.success("안전: 업로드한 파일에서 주요 보안 취약점이 발견되지 않았습니다.")
        else:
            st.error(f"총 {len(findings)}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")


# 폴더 검사 시 건너뛸 디렉터리 (가상환경, 캐시, 외부 라이브러리 등)
SKIP_DIRS = {"venv", ".venv", "env", ".env", "__pycache__", "site-packages", "dist-packages",
             ".git", "node_modules", ".idea", ".vscode", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist"}


def _is_skipped(path):
    # 첫 번째는 사용자가 고른 폴더 자신(이름이 build, env 여도 검사), 마지막은 파일명
    parts = path.replace("\\", "/").split("/")[1:-1]
    return any(p in SKIP_DIRS for p in parts)


def _scan_folder(files):
    """반환: [{"path", "findings", "error"}, ...]"""
    progress = st.progress(0.0, text="검사 준비 중...")
    results = []
    for i, uf in enumerate(files, 1):
        progress.progress(i / len(files), text=f"{i} / {len(files)} 파일 검사 중: {uf.name}")
        try:
            findings, error = scan_source(_decode(uf.getvalue()))
        except Exception as e:   # 스캐너 내부 오류가 나도 다른 파일 검사는 계속
            findings, error = [], f"스캐너 내부 오류: {type(e).__name__}: {e}"
        results.append({"path": uf.name, "findings": findings, "error": error})
    progress.empty()
    return results


def _results_to_csv(results):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["파일", "줄", "취약점", "코드", "추가 정보", "조치 가이드"])
    for r in results:
        for f in r["findings"]:
            writer.writerow([r["path"], f["line"], f["rule"], f["code"], f["extra"] or "", f["guide"]])
    return buf.getvalue().encode("utf-8-sig")   # 엑셀에서 한글 깨짐 방지


def _folder_tab():
    uploaded = st.file_uploader(
        "검사할 폴더를 선택하세요 (하위 폴더의 .py 파일까지 모두 검사)",
        type=["py"], accept_multiple_files="directory", key="folder_files",
    )
    if not uploaded:
        st.info("검사할 프로젝트 폴더를 업로드해 주세요.")
        return

    targets = sorted((f for f in uploaded if not _is_skipped(f.name)), key=lambda f: f.name)
    skipped = len(uploaded) - len(targets)
    msg = f"검사 대상 파이썬 파일 {len(targets)}개"
    if skipped:
        msg += f" (가상환경·캐시 등 {skipped}개 제외)"
    st.write(msg)
    if not targets:
        st.warning("검사할 .py 파일이 없습니다.")
        return

    signature = tuple((f.name, f.size) for f in targets)
    if st.button("폴더 전체 스캔 시작", key="scan_folder"):
        st.session_state["folder_scan"] = {"signature": signature, "results": _scan_folder(targets)}

    saved = st.session_state.get("folder_scan")
    if not saved or saved["signature"] != signature:   # 업로드가 바뀌면 이전 결과는 숨김
        return
    _render_folder_report(saved["results"])


def _render_folder_report(results):
    st.write("---")
    st.subheader("폴더 스캔 결과 리포트")

    vulnerable = [r for r in results if r["findings"]]
    failed = [r for r in results if r["error"]]
    clean = [r for r in results if not r["findings"] and not r["error"]]
    total = sum(len(r["findings"]) for r in results)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("검사한 파일", len(results))
    c2.metric("취약 파일", len(vulnerable))
    c3.metric("총 취약점", total)
    c4.metric("분석 실패", len(failed))

    if total == 0:
        st.success("안전: 폴더 내 파일에서 주요 보안 취약점이 발견되지 않았습니다.")
    else:
        st.error(f"{len(vulnerable)}개 파일에서 총 {total}개의 보안 취약점이 발견되었습니다. 조치 가이드에 따라 코드를 수정하세요.")

        counts = {}
        for r in vulnerable:
            for f in r["findings"]:
                counts[f["rule"]] = counts.get(f["rule"], 0) + 1
        st.markdown("#### 취약점 유형별 집계")
        st.dataframe(
            [{"취약점": k, "건수": v} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])],
            hide_index=True, width="stretch",
        )

        st.download_button(
            "결과 CSV 다운로드", data=_results_to_csv(results),
            file_name="scan_report.csv", mime="text/csv",
        )

        st.markdown("#### 파일별 상세 결과")
        for r in sorted(vulnerable, key=lambda r: (-len(r["findings"]), r["path"])):
            with st.expander(f"{r['path']} — {len(r['findings'])}건"):
                for idx, f in enumerate(r["findings"]):
                    if idx:
                        st.markdown("---")
                    _render_finding(f, in_expander=False)

    if failed:
        with st.expander(f"분석 실패 파일 {len(failed)}개"):
            for r in failed:
                st.markdown(f"- `{r['path']}` — {r['error']}")

    if clean:
        with st.expander(f"취약점이 발견되지 않은 파일 {len(clean)}개"):
            for r in clean:
                st.markdown(f"- `{r['path']}`")


if __name__ == "__main__":   # streamlit run ast_scanner.py 로 실행할 때만 화면 표시
    main()
