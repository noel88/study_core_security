package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가 API
        //NOTE: 설정 시 구체적인 경로가 먼저 오고 그것보다 큰 범위의 경로가 뒤에 오도록 해야 한다.

        /**
         * 인가 API
         * authenticated() 인증된 사용자의 접근을 허용
         * fullyAuthenticated() 인증된 사용자의 접근을 허용, rememberMe 인증 제외
         * permitAll()  무조건 조건을 허용
         * denyAll() 무조건 접근을 허용하지 않음
         * anonymous() 익명 사용자가 접근을 허용
         * rememberMe() 기억하기를 통해 인증된 사용자의 접근을 허용
         * access(String)  주어진 SpEL 표현식의 평가 결과가 true이면 접근을 허용
         * hasRole(String) 사용자가 주어진 역할이 있다면 접근을 허용
         * hasAuthority(String ...) 사용자가 주어진 권한이 있다면 접근을 허용
         * hasAnyRole(String ...) 사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용
         * hasAnyAuthority(String ...) 사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용
         * hasIpAddress(String) 주어진 IP로부터 요청이 왔다면 접근을 허용
         */

        http
                .authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .antMatchers("/user").hasRole("USER")
                    .antMatchers("/admin/pay").access("hasRole('ADMIN')")
                    .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                    .anyRequest().authenticated();


        //인증 API
//        http
//                .formLogin()
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication:" + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception:" + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll();

        http
                .logout()
                .logoutUrl("/logout") //POST 방식으로 처리된다.
                .logoutSuccessUrl("login")
                .deleteCookies("JSESSIONID", "remember-me")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                });

        http
                .rememberMe()
                .rememberMeParameter("remember") //기본 파라메터는 remember-me
                .tokenValiditySeconds(3600) //Default 14일, 만료계정
//                .alwaysRemember(true) //리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);


        // NOTE: 동시 세션 제어
        http
                .sessionManagement()
                .invalidSessionUrl("/invalid") // expiredUrl과 함께 사용될 경우는 우선적으로 호출
                .maximumSessions(1) //최대 허용 가능 세션 수, -1: 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) // 동시 로그인 차단, false: 기존 세션 만료 (Default)
                .expiredUrl("/expired"); // 세션이 만료된 경우 이동할 페이지

        //NOTE: 세션 고정 보호
        http.sessionManagement()
                .sessionFixation()
                .changeSessionId(); // 기본값. 다른 속성(none, migrateSession, newSession)

        //NOTE: 세션정책

        /**
         * Always: 스프링 시큐리티가 항상 세션필요
         * If_Required: 스프링 시큐리티가 필요시 생성 (기본값)
         * Never: 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
         * Stateless: 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음. (ex. JWT)
         */

        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        //인증/인가 API
        http
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        //인증실패 시 처리
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        //인가실패 시 처리
                        response.sendRedirect("/denied");
                    }
                });

        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        //인증 성공 후 사용자가 원래 가고자 했던 곳으로 이동하게 함.
                        HttpSessionRequestCache httpSessionRequestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = httpSessionRequestCache.getRequest(request, response);
                        String requestURL = savedRequest.getRedirectUrl();
                        response.sendRedirect(requestURL);
                    }
                });
    }
}
