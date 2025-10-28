package org.puchori.springbootproject.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.puchori.springbootproject.dto.MemberJoinDTO;
import org.puchori.springbootproject.service.MemberService;
import org.puchori.springbootproject.service.MemberServiceImpl;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.beans.factory.annotation.Value;

@Controller
@RequestMapping("/member")
@Log4j2
@RequiredArgsConstructor
public class MemberController {
  //의존성 주입
  private final MemberService memberService;
  @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
  private String kakaoClientId;


  // ✅ 로그아웃 리다이렉트 URL 따로 주입
  @Value("${org.puchori.kakao-logout-success-redirect-url}")
  private String kakaoLogoutRedirectUrl;

  @GetMapping("/login")
  public void loginGET(String errorCode, String logout) {
    log.info("login get..................");
    log.info("logout: " + logout);

    if (logout != null) {
      log.info("user logout....");
    }

  }

  @GetMapping("/join")
  public void joinGET(){
    log.info("join get...");

  }

  @PostMapping("/join")
  public String joinPost(MemberJoinDTO memberJoinDTO, RedirectAttributes redirectAttributes){

    log.info("join post.......");
    log.info(memberJoinDTO);

    try {
      memberService.join(memberJoinDTO);
    } catch (MemberService.MidExistException e){
      redirectAttributes.addFlashAttribute("error","mid");
      return "redirect:/member/join";
    }

    redirectAttributes.addFlashAttribute("result","success");

    return "redirect:/member/login"; //회원가입 후 로그인

  }

@GetMapping("/logout/kakao")
  public String kakaoLogout(){
    String kakaoLogoutUrl =
            "https://kauth.kakao.com/oauth/logout" +
            "?client_id=" + kakaoClientId +
              "&logout_redirect_uri=" + kakaoLogoutRedirectUrl;

    return "redirect:" + kakaoLogoutUrl;

  }

}
