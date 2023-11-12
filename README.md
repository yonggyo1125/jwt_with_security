# JWT(Json Web Token)
> JWT는 RFC7519 웹 표준으로 JSON 객체를 이용해 데이터를 주고 받을 수 있도록한 웹 토큰

- JWT는 <code>header</code>, <code>payload</code>, <code>signature</code>로 구성되어 있습니다.
- <code>header</code> : <code>signature</code>를 해싱하기 위한 알고리즘 정보
- <code>payload</code> : 실제로 사용될 데이터
- <code>signature</code> : 토큰의 유효성 검증을 위한 문자열로 이 문자열을 통해 이 토큰이 유효한 토큰인지 검증

```
aaaaaa(header).bbbbbb(payload).cccccc(signature)
```

# 의존성 설정
|jwt 의존성 - build.gradle에 다음 의존성을 jjwt-api, jjwt-impl, jjwt-jackson 추가
```groovy
dependency {
  ...
  
  implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
  implementation 'io.jsonwebtoken:jjwt-impl:0.12.3'
  implementation 'io.jsonwebtoken:jjwt-jackson:0.12.3'
  
  ...
}
```

# application.yml 설정 추가

> secret는 base64 생성기를 이용해서 만든다

[https://www.base64encode.org](https://www.base64encode.org)


```yaml
# JSON WebToken 설정
jwt:
  header: Authorization
  secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd6eXoxMjMxMjMxMjMxMjMxMjMxMzEyMzEyMzEzMTIzMTIzMTIzMTMxMjMxMzEzMTMxMjM
  accessTokenValidityInSeconds: 3600 # 60 min
```


- <code>jwt.secret</code>는 base64로 인코딩한 값 사용, 일정 길이 이상이 되지 않으면 exception이 발생하므로 충분히 길게 설정
- <code>access-token-validity-in-seconds</code> : 발급할 액세스토큰의 유효기간(초 단위) 예) - 3600 - 60분

