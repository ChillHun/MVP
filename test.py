# [테스트용 파이썬 샘플 파일]
from django.shortcuts import render
from django.db import connection

def vulnerable_test_view(request):
    dbconn = connection
    
    with dbconn.cursor() as curs:
        # 1. 외부 입력값 가져오기
        name = request.POST.get('name', '')
        user_id = request.POST.get('user_id', '')
        message = request.POST.get('message', '')
        
        # ----------------------------------------------------
        # [테스트 1] SQL 인젝션: 문자열 덧셈(+) 연산 결합 취약점
        # ----------------------------------------------------
        sql_query_1 = "update board set name=" + name + " where content_id=1"
        curs.execute(sql_query_1)
        
        # ----------------------------------------------------
        # [테스트 2] SQL 인젝션: f-string 및 포맷팅 결합 취약점
        # ----------------------------------------------------
        sql_query_2 = f"SELECT * FROM users WHERE id = '{user_id}'"
        curs.execute(sql_query_2)
        
        # ----------------------------------------------------
        # [테스트 3] 코드 삽입(Code Injection): 위험한 eval() 함수 사용
        # ----------------------------------------------------
        # 검증 없이 사용자 입력을 eval()에 바로 전달
        ret = eval(message)
        
    return render(request, 'success.html', {'data': ret})
