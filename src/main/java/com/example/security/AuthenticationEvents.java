package com.example.security;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {

  private final Map<String, Integer> attemptsMap = new ConcurrentHashMap<>();
  private static final int MAX_ATTEMPTS = 5;
  
  @EventListener
  public void onSuccess(AuthenticationSuccessEvent success) {
    String username = success.getAuthentication().getName();
    attemptsMap.remove(username);
    System.out.println("SUCCESS: ユーザー [" + username + "] がログインしました。");
  }

  @EventListener
  public void onFailure(AbstractAuthenticationFailureEvent failure) {
    String username = failure.getAuthentication().getName();
    int attempts = attemptsMap.getOrDefault(username, 0) + 1;
    attemptsMap.put(username, attempts);

    System.out.println("FAILURE: ユーザー [" + failure.getAuthentication().getName() + "] がログインを失敗しました。理由: " + failure.getException().getMessage());

    if (attempts >= MAX_ATTEMPTS) {
      System.err.println("ALERT [CRITICAL]: ユーザー [" + username + "] が連続失敗によりロック条件に達しました。");
    }
  }

  public boolean isLocked(String username) {
    return attemptsMap.getOrDefault(username, 0) >= MAX_ATTEMPTS;
  }
}
