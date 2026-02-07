package com.example.security;

import java.util.concurrent.ConcurrentHashMap;
import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {

  private record LoginAttempt(int count, LocalDateTime lastModified) {}
  private final Map<String, LoginAttempt> attemptsMap = new ConcurrentHashMap<>();
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
    LoginAttempt current = attemptsMap.getOrDefault(username, new LoginAttempt(0, LocalDateTime.now()));
   
    attemptsMap.put(username, new LoginAttempt(current.count() + 1, LocalDateTime.now()));

    System.out.println("FAILURE: ユーザー [" + failure.getAuthentication().getName() + "] がログインを失敗しました。理由: " + failure.getException().getMessage());

    if (current.count() + 1 >= MAX_ATTEMPTS) {
      System.err.println("ALERT [CRITICAL]: ユーザー [" + username + "] が連続失敗によりロック条件に達しました。");
    }
  }

  public boolean isLocked(String username) {
    // 現状はロック解除は形だけ、実際は時間を比較して規定時間以上で解除
    System.out.println("INFO: ユーザー [" + username + "] のロック時間が経過したので解除します");
    attemptsMap.remove(username);
    return false;
  }
}
