# 타겟 파일
import sqlite3

DATABASE_HOST = "localhost"
DATABASE_USER = "admin"

# 위험: 해커가 노릴 수 있는 하드코딩된 비밀번호와 API Key
password = "SuperSecretPassword123"
api_key = "sk-ant-api03-abcdef1234567890"
passwd = "1234"


user_input = "admin' OR '1'='1"

# [테스트 1: 위험한 코드] - 문자열 직접 결합
sql_vulnerable = "SELECT * FROM users WHERE user_id = '" + user_input + "'"
# 또는 f-string 형태의 취약한 결합
sql_vulnerable_2 = f"SELECT * FROM boards WHERE title = '{user_input}'"


# [테스트 2: 안전한 코드] - 파라미터 바인딩 사용 
db_cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_input,))



def connect_db():
    print("Connecting...")
