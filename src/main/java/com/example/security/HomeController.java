package com.example.security;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class HomeController {
  
  @GetMapping("/")
  public String index() {
      return "index";
  }

  @GetMapping("/mypage")
  public String mypage(Principal principal, Model model) {
     if (principal != null) {
      model.addAttribute("username", principal.getName());
     }
     return "mypage";
  }
  
  @GetMapping("/admin/dashboard")
  public String adminDashboard(Principal principal, Model model) {
    model.addAttribute("username", principal.getName());
    return "admin";
  }
}
