package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

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
  public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    String encodedUserPassword = passwordEncoder.encode("password");
    String encodedAdminPassword = passwordEncoder.encode("admin123");
    // 名簿の作成
    UserDetails user = User.withUsername("user")
      .password(encodedUserPassword)
      .roles("USER")
      .build();

    UserDetails adminUser = User.withUsername("admin")
      .password(encodedAdminPassword)
      .roles("ADMIN")
      .build();

    return new InMemoryUserDetailsManager(user, adminUser);
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
}

