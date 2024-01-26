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
