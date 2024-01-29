# study_core_spring_security
## 인프런 Core Spring Security를 보고 예제 실습을 합니다


##### 섹션 1

- [x] 1 프로젝트 구성 및 의존성 추가
- [x] 2 사용자 정의 보안 기능 구현
- [x] 3 Form Login 인증
- [x] 4 Form Login 인증 필터 : UsernamePasswordAuthenticationFilter
- [x] 5 Logout 처리, LogoutFilter
- [x] 6 Remember Me 인증
- [x] 7 Remember Me 인증 필터 : RememberMeAuthenticationFilter
- [x] 8 익명사용자 인증 필터 : AnonymousAuthenticationFilter
- [x] 9 동시 세션 제어, 세션 고정 보호, 세션 정책
- [x] 10 세션 제어 필터 : SessionManagementFilter, ConcurrentSessionFilter
- [x] 11 권한설정과 표현식
- [x] 12 예외 처리 및 요청 캐시 필터 : ExceptionTranslationFilter, RequestCacheAwareFilter
- [x] 13 사이트 간 요청 위조 - CSRF, CsrfFilter

#### 섹션 2

- [x] 1 위임 필터 및 필터 빈 초기화 - DelegatingProxyChain, FilterChainProxy
- [x] 2 필터 초기화와 다중 보안 설정
- [x] 3 인증 개념 이해 - Authentication
- [x] 4 인증 저장소 - SecurityContextHolder, SecurityContext 
- [x] 5 인증 저장소 필터 - SecurityContextPersistenceFilter
- [x] 6 인증 흐름 이해 - Authentication Flow
- [x] 7 인증 관리자 : AuthenticationManager
- [x] 8인증 처리자 - AuthenticationProvider 
- [x] 9 인가 개념 및 필터 이해 : Authorization, FilterSecurityInterceptor
- [ ] 10 인가 결정 심의자 - AccessDecisionManager, AccessDecisionVoter 
- [ ] 11 스프링 시큐리티 필터 및 아키텍처 정리

#### 섹션 3

- [ ] 1 실전 프로젝트 생성
- [ ] 2 정적 자원 관리 - WebIgnore 설정
- [ ] 3 사용자 DB 등록 및 PasswordEncoder
- [ ] 4 DB 연동 인증 처리(1) : CustomUserDetailsService
- [ ] 5 DB 연동 인증 처리(2) : CustomAuthenticationProvider
- [ ] 6 커스텀 로그인 페이지 생성하기
- [ ] 7 로그아웃 및 인증에 따른 화면 보안 처리
- [ ] 8 인증 부가 기능 - WebAuthenticationDetails, AuthenticationDetailsSource
- [ ] 9 인증 성공 핸들러 : CustomAuthenticationSuccessHandler
- [ ] 10 인증 실패 핸들러 : CustomAuthenticationFailureHandler
- [ ] 11 인증 거부 처리 - Access Denied

#### 섹션 4

- [ ] 1 흐름 및 개요
- [ ] 2 인증 필터 - AjaxAuthenticationFilter
- [ ] 3 인증 처리자 - AjaxAuthenticationProvider
- [ ] 4 인증 핸들러 - AjaxAuthenticationSuccessHandler, AjaxAuthenticationFailureHandler
- [ ] 5 인증 및 인가 예외 처리 - AjaxLoginUrlAuthenticationEntryPoint, AjaxAccessDeniedHandler
- [ ] 6 Ajax Custom DSLs 구현하기
- [ ] 7 Ajax 로그인 구현 & CSRF 설정


#### 섹션 5

- [ ] 1 스프링 시큐리티 인가 개요
- [ ] 2 관리자 시스템 - 권한 도메인, 서비스, 리포지토리 구성
- [ ] 3 웹 기반 인가처리 DB 연동 - 주요 아키텍처 이해
- [ ] 4 웹 기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource (1)
- [ ] 5 웹 기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource (2)
- [ ] 6 웹 기반 인가처리 실시간 반영하기
- [ ] 7 인가처리 허용 필터 - PermitAllFilter 구현
- [ ] 8 계층 권한 적용하기- RoleHierarchy
- [ ] 9 아이피 접속 제한하기 - CustomIpAddressVoter

#### 섹션 6

- [ ] 1 Method 방식 개요
- [ ] 2 어노테이션 권한 설정 - @PreAuthorize, @PostAuthorize, @Secured, @RolesAllowed
- [ ] 3 AOP Method 기반 DB 연동 - 주요 아키텍처 이해
- [ ] 4 AOP Method 기반 DB 연동 - MapBasedSecurityMetadataSource (1)
- [ ] 5 AOP Method 기반 DB 연동 - MapBasedSecurityMetadataSource (2)
- [ ] 6 AOP Method 기반 DB 연동 - MapBasedSecurityMetadataSource (3)
- [ ] 7 AOP Method 기반 DB 연동 - ProtectPointcutPostProcessor

#### 섹션 7

- [ ] 번외편 - 메소드 보안 실시간 DB 연동 구현
- [ ] ProxyFactory 를 활용한 실시간 메소드 보안 구현

#### 강좌 마무리

- [ ] 정리