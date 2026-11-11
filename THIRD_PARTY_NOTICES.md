# Third-Party Notices

이 프로젝트의 API 키/비밀값 유출 검사(sc.py 의 `_PROVIDER_RULES`)는 아래 오픈소스 프로젝트의
탐지 규칙(정규식) 일부를 참고하여 작성되었습니다.

## gitleaks

- 출처: https://github.com/gitleaks/gitleaks (config/gitleaks.toml)
- 참고한 규칙: openai-api-key, anthropic-api-key, anthropic-admin-api-key, gcp-api-key,
  huggingface-access-token, perplexity-api-key, aws-access-token, github-pat, github-oauth,
  github-fine-grained-pat, npm-access-token, pypi-upload-token, stripe-access-token, slack-bot-token,
  slack-webhook-url, sendgrid-api-token, notion-api-token, heroku-api-key-v2, telegram-bot-api-token,
  discord-api-token, private-key, jwt
- 라이선스: MIT License

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 기타 참고 자료 (사실 정보만 참고, 문서 내용은 복사하지 않음)

- 토스페이먼츠 API 키 문서: https://docs.tosspayments.com/reference/using-api/api-keys
- 카카오 디벨로퍼스 앱 설정 문서: https://developers.kakao.com/docs/latest/ko/app-setting/app
- Supabase API 키 문서: https://supabase.com/docs/guides/api/api-keys
- KISA Python 시큐어코딩 가이드 (2023년 개정본): https://www.kisa.or.kr/2060204/form?postSeq=13
