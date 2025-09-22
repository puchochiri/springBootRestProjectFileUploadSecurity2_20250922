package org.puchori.springbootproject.config;



import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.puchori.springbootproject.security.CustomUserDetailsService;
import org.puchori.springbootproject.security.handler.Custom403Handler;
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




  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    log.info("-----------------configure-------------");

    http
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/css/**", "/js/**", "images/**",   "/favicon.ico").permitAll() // 정적 리소스 혀용
          .requestMatchers("/member/login").permitAll()                    // 로그인 페이지
          .anyRequest().authenticated() // 나머지는 인증필요
        )
      .formLogin(form -> form
              .loginPage("/member/login")
              .defaultSuccessUrl("/board/list", true)
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



}
