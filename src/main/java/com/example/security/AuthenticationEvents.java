package com.example.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {
  
  @EventListener
  public void onSuccess(AuthenticationSuccessEvent success) {
    System.out.println("SUCCESS: ユーザー [" + success.getAuthentication().getName() + "] がログインしました。");
  }

  @EventListener
  public void onFailure(AbstractAuthenticationFailureEvent failure) {
    System.out.println("FAILURE: ユーザー [" + failure.getAuthentication().getName() + "] がログインを失敗しました。理由: " + failure.getException().getMessage());
  }
}
