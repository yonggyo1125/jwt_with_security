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


# 회원가입 구현하기

## 엔티티 구성하기

> configs/MvcConfig.java

```java
package org.koreait.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableJpaAuditing
public class MvcConfig implements WebMvcConfigurer {
    
}
```
> configs/SecurityConfig.java

```java
package org.koreait.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

> commons/constants/MemberType.java

```java
package org.koreait.commons.constants;

public enum MemberType {
    USER, // 일반회원
    ADMIN // 관리자
}
```

> entities/BaseEntity.java 

```java
package org.koreait.entities;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@MappedSuperclass @Getter @Setter
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {
    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(insertable = false)
    private LocalDateTime modifiedAt;
}
```

> entities/Member.java

```java
package org.koreait.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.koreait.commons.constants.MemberType;
import org.springframework.data.annotation.Id;

@Entity
@Data @Builder
@NoArgsConstructor @AllArgsConstructor
public class Member extends BaseEntity {
    @Id
    @GeneratedValue
    private Long seq;
    @Column(length=60, unique = true, nullable = false)
    private String email;

    @Column(length=65, nullable = false)
    private String password;

    @Column(length=30, nullable = false)
    private String name;

    private String mobile;

    @Enumerated(EnumType.STRING)
    @Column(length=30, nullable = false)
    private MemberType type = MemberType.USER;
}
```

> repositories/MemberRepository.java

```java
package org.koreait.repositories;

import org.koreait.entities.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);
}
```

