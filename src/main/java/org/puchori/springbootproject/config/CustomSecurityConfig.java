package org.puchori.springbootproject.config;



import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.puchori.springbootproject.security.CustomOAuth2UserService;
import org.puchori.springbootproject.security.CustomUserDetailsService;
import org.puchori.springbootproject.security.handler.Custom403Handler;
import org.puchori.springbootproject.security.handler.CustomSocialLoginSuccessHandller;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;
import java.security.Security;

@Log4j2
@Configuration
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CustomSecurityConfig {
  //주입 필요
  private final DataSource dataSource;
  private final CustomUserDetailsService userDetailsService;


  private final CustomOAuth2UserService customOAuth2UserService;

  private final PasswordEncoder passwordEncoder;

/*  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }*/

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    log.info("-----------------configure-------------");

    http
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/css/**", "/js/**", "images/**",   "/favicon.ico").permitAll() // 정적 리소스 혀용
          .requestMatchers("/member/login").permitAll()                    // 로그인 페이지
          .requestMatchers("/member/join").permitAll()                    // 회원가입 페이지
          .anyRequest().authenticated() // 나머지는 인증필요
        )
      .formLogin(form -> form
              .loginPage("/member/login")
              .defaultSuccessUrl("/board/list", true)
      )
      // oAuth2 로그인 추가부분
      .oauth2Login(oauth2 -> oauth2
              .loginPage("/member/login")       // 소셜 로그인 진입 시 사용할 로그인 페이지
              .userInfoEndpoint(userInfo ->
                              userInfo.userService(customOAuth2UserService)) // 여기로 등록
              .successHandler(authenticationSuccessHandler())
/*
              .defaultSuccessUrl("/board/list",true) // 로그인 성공 후 이동할 url
*/


      )
      // 로그아웃
            .logout(logout -> logout
                    .logoutUrl("/member/logout")
                    .logoutSuccessUrl("/member/login?logout") // 로그아웃 성공 시 이동
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
            )
      .csrf(csrf -> csrf.disable())
      .rememberMe(rememberMe -> rememberMe
      .key("12345678")
      .tokenRepository(persistentTokenRepository())
      .userDetailsService(userDetailsService)
      .tokenValiditySeconds(60*60*24*30)
      )
      .exceptionHandling(except ->
          except.accessDeniedHandler(accessDeniedHandler()));






    //http.formLogin();

    return http.build();

  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    log.info("------------- web configure-------------------");

    return (web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()));
  }

  @Bean
  public PersistentTokenRepository persistentTokenRepository() {
      JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
      repo.setDataSource(dataSource);
      // repo.setCreateTableOnStartup(true); // 처음 실행 시 테이블 생성 가능
      return repo;
  }


  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    return new Custom403Handler();
  }


  @Bean
  public AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new CustomSocialLoginSuccessHandller(passwordEncoder);
  }

}
