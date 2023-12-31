# 학습 순서

- [초기설정](https://github.com/yonggyo1125/jwt_with_security/tree/initialSetting)
- [회원가입구현](https://github.com/yonggyo1125/jwt_with_security/tree/join)
- [JWT 설정](https://github.com/yonggyo1125/jwt_with_security/tree/jwtSetting)
- [스프링 시큐리티 설정](https://github.com/yonggyo1125/jwt_with_security/tree/securitySetting)
- [API 구현](https://github.com/yonggyo1125/jwt_with_security/tree/apiImpl)

> [동영상강의](https://drive.google.com/drive/folders/1Ki68eH-pJnhr7MYlZtWT8pSQWAiLbf7v?usp=sharing)

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
import org.koreait.commons.constants.MemberType;;

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

> api/members/dto/RequestJoin.java

```java
package org.koreait.api.members.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RequestJoin(
        @NotBlank @Email
        String email,

        @NotBlank
        String password,

        @NotBlank
        String confirmPassword,

        @NotBlank
        String name,

        @NotBlank
        String mobile,

        @AssertTrue
        boolean agree
) {}
```

> models/member/MemberJoinService.java

```java
package org.koreait.models.member;

import lombok.RequiredArgsConstructor;
import org.koreait.api.members.dto.RequestJoin;
import org.koreait.commons.constants.MemberType;
import org.koreait.entities.Member;
import org.koreait.repositories.MemberRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberJoinService {
    private final MemberRepository repository;
    private final PasswordEncoder passwordEncoder;

    public void save(RequestJoin join) {
        String password = passwordEncoder.encode(join.password());
        Member member = Member.builder()
                .email(join.email())
                .password(password)
                .name(join.name())
                .mobile(join.mobile())
                .type(MemberType.USER)
                .build();
        save(member);
    }

    public void save(Member member) {
        
        repository.saveAndFlush(member);
    }
}
```

> models/member/MemberInfo.java

```java
package org.koreait.models.member;

import lombok.Builder;
import lombok.Data;
import org.koreait.entities.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
@Builder
public class MemberInfo implements UserDetails {

    private String email;
    private String name;
    private Member member;

    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        if (member != null)
            return member.getPassword();

        return null;
    }

    @Override
    public String getUsername() {
       return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

> models/member/MemberInfoService.java

```java
package org.koreait.models.member;

import lombok.RequiredArgsConstructor;
import org.koreait.commons.constants.MemberType;
import org.koreait.entities.Member;
import org.koreait.repositories.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class MemberInfoService implements UserDetailsService {
    private final MemberRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = repository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException(username));

        MemberType type = Objects.requireNonNullElse(member.getType(), MemberType.USER);
        List<? extends GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority(type.name()));

        return MemberInfo.builder()
                .email(member.getEmail())
                .name(member.getName())
                .member(member)
                .authorities(authorities)
                .build();
    }
}
```

# JWT 설정

> configs/jwt/JwtProperties.java

```java
package org.koreait.configs.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String header;
    private String secret;
    private Long accessTokenValidityInSeconds;
}
```

> configs/jwt/TokenProvider.java

```java
package org.koreait.configs.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.koreait.models.member.MemberInfo;
import org.koreait.models.member.MemberInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;


@Slf4j
public class TokenProvider {
    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;
    private final long tokenValidityInSeconds;

    private Key key;

    @Autowired
    private MemberInfoService memberInfoService;

    public TokenProvider(String secret, long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInSeconds = tokenValidityInSeconds;

        // 시크릿 값을 복호화(decode) 하여 키 변수에 할당
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInSeconds * 1000);
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512) // HMAC + SHA512
                .setExpiration(validity)
                .compact();
    }

    /**
     * 토큰을 받아 클레임을 생성
     * 클레임에서 권한 정보를 가져와서 시큐리티 UserDetails 객체를 만들고
     * Authentication 객체 반환
     *
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getPayload();

        List<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        MemberInfo memberInfo = (MemberInfo)memberInfoService.loadUserByUsername(claims.getSubject());
        memberInfo.setAuthorities(authorities);

        return new UsernamePasswordAuthenticationToken(memberInfo, token, authorities);
    }

    /**
     * 토큰 유효성 체크
     *
     * @param token
     * @return
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(key).build().parseClaimsJws(token).getBody();
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
            e.printStackTrace();
        }

        return false;
    }
}
```
> <code>TokenProvider</code> : 토큰을 생성하고 검증하며 토큰에서 정보를 꺼내 스프링 시큐리티 <code>Authentication</code> 객체를 생성하는 역할을 수행

> HMAC
> 해싱과 공유키를 사용한 MAC 기술이 바로 HMAC
> HMAC(Hash based Message Authentication Code)은 RFC2104로 발표된 MAC 기술의 일종으로,
원본 메시지가 변하면 그 해시값도 변하는 해싱(Hashing)의 특징을 활용하여 메시지의 변조 여부를 확인(인증) 하여 무결성과 기밀성을 제공하는 기술입니다.
일반 해싱 알고리즘과 HMAC의 공통점은 해싱 알고리즘이 적용된 해싱 함수를 사용한다는 것이고,
> 가장 큰 차이는, HMAC은 해시 암호 키를 송신자와 수신자가 미리 나눠가지고 이를 사용한다는 것입니다.
> 송수신 자만 공유하고 있는 키와 원본 메시지를 혼합하여 해시값을 만들고 이를 비교하는 방식입니다.

```
HMAC = Hash(Message, key) + Message
※ hash() 함수는 sha1, sha2, md5등의 알고리즘 사용 
```

> configs/jwt/JwtConfig.java

```java
package org.koreait.configs.jwt;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {
    @Bean
    public TokenProvider tokenProvider(JwtProperties jwtProperties) {
        return new TokenProvider(jwtProperties.getSecret(), jwtProperties.getAccessTokenValidityInSeconds());
    }
}
```

> <code>JwtConfig</code> : JWT 설정파일로 TokenProvider에 의존성을 주입하고 빈을 생성하는 역할


> configs/jwt/CustomJwtFilter.java

```java
package org.koreait.configs.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomJwtFilter extends GenericFilterBean {
    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String jwt = resolveToken(req);
        String requestURI = req.getRequestURI();

        // 토큰 유효성 검사
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) { // 토큰에 이상이 없는 경우
          // 토큰에서 사용자명, 권한을 추출하여 스프링 시큐리티 사용자를 만들어 Authentication 반환
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Security Context에 %s 인증 정보를 저장했습니다. URI : %s", authentication.getName(), requestURI);
        } else {
            log.debug("유효한 JWT 토큰이 없습니다. URI: %s", requestURI);
        }

        chain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }
}
```

- 액세스토큰을 검증하는 역할을 수행하는 <code>GenericFilterBean</code>을 상속받아 <code>CustomJwtFilter</code>를 작성합니다.
- <code>doFilter</code> 메서드 영역 : 토큰의 유효성을 검증하고, 토큰에서 식별자인 <code>username</code>과 해당 토큰에 부여된 권한을 스프링 시큐리티 <code>Authentication</code> 객체를 생성하고 <code>Security Context</code>에 저장
- 즉, 토큰 검증을 하고 데이터 베이스에 사용자가 있는지를 조회한다는 것

# 시큐리티 설정 추가 

> configs/jwt/CorsFilterConfig.java

```java
package org.koreait.configs.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsFilterConfig {
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");

        source.registerCorsConfiguration("/api/**", config);
        
        return new CorsFilter(source);
    }
}
```

-  <code>config.addAllowedOrigin("*");</code> : 실제 서비스에서는 *가 아니라 연동할 도메인으로 한정한다(보안 강화)

> configs/jwt/JwtAuthenticationEntryPoint.java

```java
package org.koreait.configs.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        // 자격증명 없이 페이지 접근시 접근권한 없음(401)
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
```

- <code>AuthenticationEntryPoint</code> 인터페이스 : 인증 실패 시 동작하도록 시큐리티 설정파일 작성 시 지정, 상속을 통해 구현
 
> configs/SecurityConfig.java

```java
package org.koreait.configs;

import org.koreait.configs.jwt.CustomJwtFilter;
import org.koreait.configs.jwt.JwtAccessDeniedHandler;
import org.koreait.configs.jwt.JwtAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity // 기본 웹 보안 활성화
@EnableMethodSecurity // @PreAuthorize 애노테이션 활성화
public class SecurityConfig {

    @Autowired
    private CorsFilter corsFilter;

    @Autowired
    private CustomJwtFilter customJwtFilter;

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(c -> c.disable())
                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(customJwtFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(c -> {
                    c.authenticationEntryPoint(jwtAuthenticationEntryPoint).accessDeniedHandler(jwtAccessDeniedHandler);
                })
                .authorizeHttpRequests(c -> {
                   c.requestMatchers("/api/v1/member",
                           "/api/v1/member/token",
                           "/api/v1/member/login",
                           "/api/v1/member/exists/**").permitAll()
                           .anyRequest().authenticated();
                });
        
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }
}
```

- <code>@EnableMethodSecurity</code> : <code>@PreAuthorize</code> 애노테이션 사용을 위해 선언
- <code>@EnableWebSecurity</code> : 기본적인 웹보환을 활성화하는 애노테이션

> 스프링 시큐리티 세션 정책(Session Creation Policy)
> SessionCreationPolicy

- <code>ALWAYS</code> : 스프링 시큐리티가 항상 세션을 생성
- <code>IF_REQUIRED</code> : 스프링 시큐리티가 필요시 생성(기본값)
- <code>NEVER</code> : 스프링 시큐리티가 생성하지 않지만 기존에 존재하면 사용
- <code>STATELESS</code> : 스프링 시큐리티가 생성하지도 않고 기존의 것을 사용하지도 않음(JWT와 같은 토큰 방식을 쓸때 사용)


# 액세스토큰 인증 API 구현

> api/members/dto/RequestJoin.java

```java
package org.koreait.api.members.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RequestLogin(
        @NotBlank @Email
        String email,

        @NotBlank
        String password
) {}
```

> api/members/dto/ResponseLogin.java

```java
package org.koreait.api.members.dto;

import lombok.Builder;

@Builder
public record ResponseLogin(
        String accessToken
) {}
```

> models/member/MemberLoginService.java

```java
package org.koreait.models.member;

import lombok.RequiredArgsConstructor;
import org.koreait.api.members.dto.ResponseLogin;
import org.koreait.configs.jwt.TokenProvider;
import org.koreait.repositories.MemberRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberLoginService {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final MemberRepository repository;

    public ResponseLogin authenticate(String email, String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 인증 정보를 가지고 JWT AccessToken 발급
        String accessToken = tokenProvider.createToken(authentication);

        return ResponseLogin.builder()
                .accessToken(accessToken)
                .build();
    }
}
```

> commons/exceptions/CommonException.java : 공통 예외

```java
package org.koreait.commons.exceptions;

import org.springframework.http.HttpStatus;

public class CommonException extends RuntimeException {
    private HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
    public CommonException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
```

> commons/exceptions/BadRequestException.java : 잘못된 요청 관련 예외, 응답 코드를 400으로 고정

```java
package org.koreait.commons.exceptions;

import org.springframework.http.HttpStatus;

public class BadRequestException extends CommonException {
    public BadRequestException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
```

> api/commons/JSONData.java : JSON 형식 출력의 통일성을 위해 추가 

```java
package org.koreait.api.commons;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
@RequiredArgsConstructor
public class JSONData<T> {
    private boolean success = true;

    @NonNull
    private T data;

    private String message;
    private HttpStatus status = HttpStatus.OK;
}
```

> api/ApiCommonController.java : 예외를 JSONData 형식으로 공통 처리 

```java
package org.koreait.api;

import org.koreait.api.commons.JSONData;
import org.koreait.commons.exceptions.CommonException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice("org.koreait.api")
public class ApiCommonController {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<JSONData<Object>> errorHandler(Exception e) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        if (e instanceof CommonException) {
            CommonException commonException = (CommonException)e;
            status = commonException.getStatus();
        } else if (e instanceof BadCredentialsException) {
            status = HttpStatus.UNAUTHORIZED;
        } else if (e instanceof AccessDeniedException) {
            status = HttpStatus.FORBIDDEN;
        }

        JSONData<Object> data = new JSONData<>();
        data.setSuccess(false);
        data.setMessage(e.getMessage());
        data.setStatus(status);

        e.printStackTrace();

        return ResponseEntity.status(status).body(data);
    }
}
```
> src/main/resoureces/messages 디렉토리에 다음과 같이 3개 메세지 파일을 추가 
> commons.properties

```properties
Email=이메일 형식이 아닙니다.
Mobile=휴대전화번호 형식이 아닙니다.
NotBlank.email=이메일을 입력하세요.
NotBlank.password=비밀번호를 입력하세요.

NotBlank.confirmPassword=비밀번호를 확인하세요.
NotBlank.requestJoin.name=회원명을 입력하세요.
AssertTrue.requestJoin.agree=회원가입 약관에 동의하세요.

Duplicate.email=이미 등록된 이메일 주소 입니다.
Mismatch.confirmPassword=비밀번호가 일치하지 않습니다.
Complexity.password=비밀번호는 숫자, 대문자와 소문자로 구성된 알파벳, 특수문자로 구성하세요.
Size.requestJoin.password=비밀번호는 8자리 이상 입력하세요.

Fail.join=회원가입에 실패하였습니다.
```

> errors.properties
> validations.properties

> commons/Utils.java : 메세지 코드 조회 편의 클래스

```java
package org.koreait.commons;

import org.springframework.validation.Errors;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;

public class Utils {
    private static ResourceBundle validationsBundle;
    private static ResourceBundle errorsBundle;

    static {
        validationsBundle = ResourceBundle.getBundle("messages.validations");
        errorsBundle = ResourceBundle.getBundle("messages.errors");
    }

    public static String getMessage(String code, String bundleType) {
        bundleType = Objects.requireNonNullElse(bundleType, "validation");
        ResourceBundle bundle = bundleType.equals("error")? errorsBundle:validationsBundle;
        try {
            return bundle.getString(code);
        } catch (Exception e) {
            return null;
        }
    }

    public static List<String> getMessages(Errors errors) {
        return errors.getFieldErrors()
                .stream()
                .flatMap(f -> Arrays.stream(f.getCodes()).sorted(Comparator.reverseOrder())
                        .map(c -> getMessage(c, "validation")))
                .filter(s -> s != null && !s.isBlank()).toList();
    }
}
```

> commons/validators/MobileValidator : 휴대폰번호 형식 검증

```java
package org.koreait.commons.validators;

public interface MobileValidator {
    default boolean mobileNumCheck(String mobile) {
        /**
         * 010-3481-2101
         * 010_3481_2101
         * 010 3481 2101
         *
         * 1. 형식의 통일화 - 숫자가 아닌 문자 전부 제거 -> 숫자
         * 2. 패턴 생성 체크
         */
        mobile = mobile.replaceAll("\\D", "");
        String pattern = "^01[016]\\d{3,4}\\d{4}$";

        return mobile.matches(pattern);
    }
}
```

> commons/validators/PasswordValidator : 비밀번호 복잡성 체크 편의 인터페이스

```java
package org.koreait.commons.validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public interface PasswordValidator {
    /**
     * 비밀번호 복잡성 체크 - 알파벳 체크
     *
     * @param password
     * @param caseIncentive
     *          false : 소문자 + 대문자가 반드시 포함되는 패턴
     *          true : 대소문자 상관없이 포함되는 패턴
     * @return
     */
    default boolean alphaCheck(String password, boolean caseIncentive) {
        if (caseIncentive) { // 대소문자 구분없이 체크
            Pattern pattern = Pattern.compile("[a-z]+", Pattern.CASE_INSENSITIVE);
            return pattern.matcher(password).find();
        }

        // 대문자, 소문자 각각 체크
        Pattern pattern1 = Pattern.compile("[a-z]+");
        Pattern pattern2 = Pattern.compile("[A-Z]+");
        return pattern1.matcher(password).find() && pattern2.matcher(password).find();
    }
    /**
     * 숫자가 포함된 패턴인지 체크
     *
     * @param password
     * @return
     */
    default boolean numberCheck(String password) {
        Pattern pattern = Pattern.compile("\\d+");
        Matcher matcher = pattern.matcher(password);
        return matcher.find();
    }

    /**
     * 특수문자가 포함된 패턴인지 체크
     * @param password
     * @return
     */
    default boolean specialCharsCheck(String password) {
        Pattern pattern = Pattern.compile("[`~!#$%\\^&\\*()-_+=]+");
        Matcher matcher = pattern.matcher(password);
        return matcher.find();
    }
}
```

> repositories/MemberRepository.java - 소스 추가 
> extends ... , QuerydslPredicateExecutor<Member>
> exists 메서드 추가 

```java
...

public interface MemberRepository extends JpaRepository<Member, Long>, QuerydslPredicateExecutor<Member> {
    Optional<Member> findByEmail(String email);

    default boolean exists(String email) {
        return exists(QMember.member.email.eq(email));
    }
}
```

> api/members/validator/JoinValidator.java : 회원가입 추가 유효성 검사

```java
package org.koreait.api.members.validator;

import lombok.RequiredArgsConstructor;
import org.koreait.api.members.dto.RequestJoin;
import org.koreait.commons.validators.MobileValidator;
import org.koreait.commons.validators.PasswordValidator;
import org.koreait.repositories.MemberRepository;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

/**
 * 회원 가입 추가 유효성 검사
 *
 */
@Component
@RequiredArgsConstructor
public class JoinValidator implements Validator, PasswordValidator, MobileValidator {

    private final MemberRepository repository;

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(RequestJoin.class);
    }

    @Override
    public void validate(Object target, Errors errors) {
        RequestJoin form = (RequestJoin)target;

        /**
         * 1. 아이디 중복 여부 체크
         * 2. 비밀번호 복잡성 체크
         * 3. 비밀번호 및 비밀번호 확인 일치 여부
         * 4. 휴대전화번호 형식 체크
         */

        String email = form.email();
        String password = form.password();
        String confirmPassword = form.confirmPassword();
        String mobile = form.mobile();

        // 1. 아이디 중복 여부 체크
        if (email != null && !email.isBlank() && repository.exists(email)) {
            errors.rejectValue("email", "Duplicate");
        }

        // 2. 비밀번호 복잡성 체크
        if (password != null && !password.isBlank() && (!alphaCheck(password, false) || !numberCheck(password) || !specialCharsCheck(password))) {
            errors.rejectValue("password", "Complexity");
        }

        // 3. 비밀번호 및 비밀번호 확인 일치 여부
        if (password != null && !password.isBlank() && confirmPassword != null && !confirmPassword.isBlank() && !password.equals(confirmPassword)) {
            errors.rejectValue("confirmPassword", "Mismatch");
        }

        // 4. 휴대전화번호 형식 체크
        if (mobile != null && !mobile.isBlank() && !mobileNumCheck(mobile)) {
            errors.rejectValue("mobile", "Mobile");
        }
    }
}
```

> models/member/MemberJoinService.java : 추가 유효성 검사 코드 추가 

```java

...

@Service
@RequiredArgsConstructor
public class MemberJoinService {
    private final MemberRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JoinValidator validator; // 추가 

    // 추가 
    public void save(RequestJoin join, Errors errors) {
        validator.validate(join, errors);
        if (errors.hasErrors()) {
            return;
        }

        save(join);
    }

    ...
}
```

> api/members/MemberController.java

```java
package org.koreait.api.members;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.koreait.api.commons.JSONData;
import org.koreait.api.members.dto.RequestJoin;
import org.koreait.api.members.dto.RequestLogin;
import org.koreait.api.members.dto.ResponseLogin;
import org.koreait.commons.Utils;
import org.koreait.commons.exceptions.BadRequestException;
import org.koreait.configs.jwt.CustomJwtFilter;
import org.koreait.models.member.MemberInfoService;
import org.koreait.models.member.MemberJoinService;
import org.koreait.models.member.MemberLoginService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/v1/member")
@RequiredArgsConstructor
public class MemberController {
    private final MemberLoginService loginService;
    private final MemberInfoService infoService;
    private final MemberJoinService joinService;

    /**
     * accessToken 발급
     *
     */
    @PostMapping("/token")
    public ResponseEntity<JSONData<ResponseLogin>> authorize(@Valid @RequestBody RequestLogin requestLogin, Errors errors) {
        // 유효성 검사 처리
        errorProcess(errors);

        ResponseLogin token = loginService.authenticate(requestLogin.email(), requestLogin.password());

        HttpHeaders headers = new HttpHeaders();
        headers.add(CustomJwtFilter.AUTHORIZATION_HEADER, "Bearer " + token.accessToken());

        JSONData<ResponseLogin> data = new JSONData<>(token);

        return ResponseEntity.status(data.getStatus())
                .headers(headers)
                .body(data);
    }


    /**
     * 회원가입 처리
     *
     * @return
     */
    @PostMapping
    public ResponseEntity<JSONData<Object>> join(@RequestBody @Valid RequestJoin form, Errors errors) {

        joinService.save(form, errors);

        // 유효성 검사 처리
        errorProcess(errors);

        HttpStatus status = HttpStatus.CREATED;
        JSONData<Object> data = new JSONData<>();
        data.setSuccess(true);
        data.setStatus(status);

        return ResponseEntity.status(status).body(data);
    }

    private void errorProcess(Errors errors) {
        if (errors.hasErrors()) {
            List<String> errorMessages = Utils.getMessages(errors);
            throw new BadRequestException(errorMessages.stream().collect(Collectors.joining("||")));
        }
    }


    @GetMapping("/member_only")
    public void MemberOnlyUrl() {
        log.info("회원 전용 URL 접근 테스트");
    }

    @GetMapping("/admin_only")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    public void adminOnlyUrl() {
        log.info("관리자 전용 URL 접근 테스트");
    }
}
```
