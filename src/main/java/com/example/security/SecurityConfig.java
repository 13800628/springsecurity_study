package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
  
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
      // 認可
      http
          .authorizeHttpRequests(auth -> auth
              // 認可ルール
              .requestMatchers("/").permitAll()
              .requestMatchers("/admin/**").hasRole("ADMIN")
              .anyRequest().authenticated())

          // セッション管理。後出し
          .sessionManagement(session -> session
              // 同接の限度
              .maximumSessions(1)
              // 本来はfalseがデフォなので不要だが提示する
              .maxSessionsPreventsLogin(false)
              // 追い出され側のURL
              .expiredUrl("/login?exprired"))

          .formLogin(login -> login
              // 成功
              .defaultSuccessUrl("/mypage", true)
              // 失敗
              .failureHandler(customAuthenticationFailureHandler()))

          .exceptionHandling(exception -> exception
              .accessDeniedHandler(customAccessDeniedHandler()))

          .logout(logout -> logout
              .logoutSuccessUrl("/"));

      return http.build();
    }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  // 認証
  @Bean
  public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder, AuthenticationEvents events) {
    return username -> {
      // ★まず、メモリ上のロック状態をチェック
      if (events.isLocked(username)) {
        System.err.println("SECURITY: ロック中のユーザー [" + username + "] によるアクセスを拒否しました。");
        throw new LockedException("このアカウントはロックされています。");
      }

      // ユーザー情報の照合（本来はDB、今回はメモリ内の固定値）
      if ("user".equals(username)) {
        return User.withUsername("user")
            .password(passwordEncoder.encode("password"))
            .roles("USER")
            .build();
      } else if ("admin".equals(username)) {
        return User.withUsername("admin")
            .password(passwordEncoder.encode("admin123"))
            .roles("ADMIN")
            .build();
      }

      throw new UsernameNotFoundException("User not found");
    };
  }

  // 例外ハンドラー
  @Bean
  public AuthenticationFailureHandler customAuthenticationFailureHandler() {
    return (request, response, exception) -> {
      System.out.println("DEBUG: FailureHandlerが呼ばれました");
      response.sendRedirect("/login?error");
    };
  }

  @Bean
  public AccessDeniedHandler customAccessDeniedHandler() {
    return (request, response, accessDeniedException) -> {
      String username = (request.getUserPrincipal() != null) ? request.getUserPrincipal().getName() : "匿名ユーザー";
      System.err.println("ACCESS DENIED: " + username + " がアクセスを拒否されました。理由: " + accessDeniedException.getMessage());

      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response.setContentType("application/json;charset=UTF-8");
      response.getWriter().write("{\"error\": \"Access Denied\", \"message\": \"管理者権限が必要です\"}");
    };
  }

  @Bean
  public HttpSessionEventPublisher HttpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
  }
}

