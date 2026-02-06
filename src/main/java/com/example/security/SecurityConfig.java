package com.example.security;

import javax.lang.model.element.ModuleElement.UsesDirective;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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
        .anyRequest().authenticated()
      )
      .formLogin(login -> login
        .defaultSuccessUrl("/mypage", true)
      )
      .logout(logout -> logout
        .logoutSuccessUrl("/")
      );
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
}

