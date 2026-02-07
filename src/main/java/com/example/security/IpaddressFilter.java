package com.example.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter; // もしConfig側で使うなら
import java.io.IOException;
import java.util.List;

public class IpaddressFilter extends OncePerRequestFilter {
  private static final List<String> ALLOWED_IPS = List.of("127.0.0.1", "0:0:0:0:0:0:0:1");
  
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    String requestUrl = request.getRequestURI();
    String remoteAddr = request.getRemoteAddr();

  if (requestUrl.startsWith("/admin")) {
    if (!ALLOWED_IPS.contains(remoteAddr)) {
      System.err.println("BLOCK: 未許可IP [\" + remoteAddr + \"] からの管理画面アクセスを遮断しました");

      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response.setContentType("application/json;charset=UTF-8");
      response.getWriter().write("{\"error\": \"IP Restricted\", \"message\": \"この場所からはアクセスできません\"}");
      return;
    }
  }
  filterChain.doFilter(request, response);
}
}
