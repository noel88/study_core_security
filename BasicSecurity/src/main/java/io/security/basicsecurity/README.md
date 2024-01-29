### Authentication
- 사용자의 인증 정보를 저장하는 토큰개념.
- 인증 시 id와 password를 담고 인증 검증을 위해 전달되어야 한다.
- 인증 후 최종 인증결과 (user, 권한정보)를 담고 SecurityContext에 저장되어 전역적으로 참조가 가능하다.

```java
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
```

#### 구조
1. principal: 사용자 아이디 혹은 User 객체를 저장
2. credentials: 사용자 비밀번호
3. authorities: 인증된 사용자의 권한 목록
4. details: 인증 부가 정보
5. authenticated: 인증 여부


### SecurityContext
- Authentication 객체가 저장되는 보관소로 필요 시 언제든지 Authentication 객체를 꺼내어 쓸 수 있도록 제공되는 클래스
- ThreadLocal에 저장되어 아무 곳에서나 참조가 가능하도록 설계
- 인증이 완료되면 HttpSession에 저장되어 어플리케이션 전반에 걸처 전역적인 참조가 가능

### SecurityContextHolder
- SecurityContext 객체 저장 방식
  - MODE_THREADLOCAL: 스레드당 SecurityContext 객체를 할당, 기본값
  - MODE_INHERITABLEDTHREADLOCAL: 메인 스레드와 자식 스레드에 관하여 동일한 SecurityContext를 유지
  - MODE_GLOBAL: 응용 프로그램에서 단 하나의 SecurityContext를 저장한
- SecurityContextHolder.clearContext() : SecurityContext 정보 초기화


### SecurityContextPersistenceFilter
#### securityContext 객체의 생성, 저장, 조회
- 익명 사용자
  - 새로운 SecurityContext 객체에 생성하여 securityContextHolder에 저장
  - AnonymousAuthenticationFilter에서 AnonymousAuthenticationToken 객체를 SecurityContext 에 저장
- 인증 시
  - 새로운 SecurityContext 객체를 생성하여 securityContextHolder에 저장
  - UsernamePasswordAuthenticationFilter(FormLogin) 에서 인증 성공 후 SecurityContext에 UsernamePasswordAuthenticationToken 객체를 SecurityContext에 저장
  - 인증이 최종 완료되면 Session에 SecurityContext를 저장
- 인증 후
  - Session 에서 SecurityContext에 꺼내어 SecurityContextHolder에서 저장
  - SecurityContext 안에 Authentication 객체가 존재하면 계속 인증을 유지한다.
- 최종 응답 시 공통
  - SecurityContextHolder.clearContext()를 이용하여 제거한다.
  - 매 요청마다 저장하므로 제거하고 저장한다.


### Authentication Flow
![flow.jpg](flow.jpg)

### AuthenticationManager
- AuthenticationProvider 목록 중에서 인증 처리 요건에 맞는 AuthenticationProvider를 찾아 인증처리를 위임한다.
- 부모 ProviderManager를 설정하여 AuthencationProvider를 계속 탐색할 수 있다.

### Authorization
- 당신에게 무엇이 허가 되었는지 증명하는 것. (인가)

#### 스프링 시큐리티가 지원하는 권한 계층
- 웹 계층: URL 요청에 따른 메뉴 혹은 화면단위의 레벨 보안
- 서비스 계층: 화면 단위가 아닌 메소드 같은 기능 단위의 레벨 보안
- 도메인 계층(ACL, 접근 제어목록): 객체 단위의 레벨 보안

### FilterSecurityInterceptor
- 마지막에 위치한 필터로써 인증된 사용자에 대해여 특정 요청의 승인/거부 여부를 최종적으로 결정
- 인증객체 없이 보호자원에 접근을 시도할 경우 AuthenticationException을 발생
- 인증 후 자원에 접근 가능한 권한이 존재하지 않을 경우 AccessDeniedException을 발생
- 권한 제어 방식 중 HTTP 자원의 보안을 처리하는 필터
- 권한 처리를 AccessDecisionManager에게 맡김.

### AccessDecisionManager
- 인증정보, 요청정보, 권한정보를 이용해서 사용자의 자원접근을 허용할 것인지 거부할 것인지를 최종 결정하는 주체 
- 여러개의 voter들을 가질 수 있으며 voter들로부터 접근허용, 거부, 보류에 해당하는 각각의 리터받고 판단 및 결정
- 최종 접근 거부 시 예외 발생
- 접근 결정의 세가지 유형
  - AffirmativeBased: 여러개의 voter 클래스 중 하나라도 접근 허가로 결론을 내면 접근허가로 판단
  - ConsensusBased: 
    - 다수표(승인 및 거부)에 의해 최종 결정을 판단한다.
    - 동수일 경우 기본은 접근허가이나 AllowIfEqualGrantedDeniedDecisions을 false로 설정할 경우 접근 거부로 결정된다.
  - UnanimousBased: 모든 voter가 만장일치로 접근을 승인해야 하면 그렇지 않은 경우 접근을 거부한다.

### AccessDecisionVoter
- 판단을 심사하는 것(위원)
- Voter가 권한 부여 과정에서 판단하는 자료
  - Authentication - 인증정보(User)
  - FilterInvocation - 요청정보(antMatcher("/user"))
  - ConfigAttributes - 권한정보(hasRole("USER"))
- 결정방식
  - ACCESS_GRANTED: 접근 허용(1)
  - ACCESS_DENIED: 접근 거부(-1)
  - ACCESS_ABSTAIN: 접근 보류(0)
    - Voter가 해당 타입의 요청에 대해 결정을 내릴 수 없는 경우


