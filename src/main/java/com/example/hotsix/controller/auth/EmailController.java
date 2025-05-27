package com.example.hotsix.controller.auth;

import com.example.hotsix.dto.auth.EmailResponse;
import com.example.hotsix.dto.auth.SignUpRequest;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.service.auth.LoginService;
import com.example.hotsix.service.auth.MailLinkService;
import com.example.hotsix.service.auth.SignUpService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

@RestController
@Slf4j
@RequiredArgsConstructor
public class EmailController {

    private final MailLinkService mailLinkService;
    private final LoginService loginService;
    private final SignUpService signUpService;
    private final JWTUtil jwtUtil;


    @Value("${client.host}")
    private String clinetHost;

    @PostMapping("/email-link")
    public EmailResponse emailLink(@RequestBody String email) {
        String type = mailLinkService.choiceLoginOrRegister(email);
        String link = mailLinkService.createLink(type, email);
        mailLinkService.sendMail(email,type,link);

       return EmailResponse.builder()
                .link(link)
                .type(type)
                .build();
    }

    @GetMapping("/email-login")
    public void emailLogin(@RequestParam("code") String code, HttpServletResponse response){
        try{
            jwtUtil.validateToken(code);
            String email = jwtUtil.getEmail(code);

            if(email != null) {
                Map<String, Cookie> cookies = loginService.issueAuthTokensAndCookies(email);

                response.addCookie(cookies.get("access"));
                response.addCookie(cookies.get("refresh"));
                redirect(response,clinetHost+"/afterlogin");
            }
        }catch (BuiltInException e){
            throw e;
        }
    }

    @GetMapping("/register")
    public void register(@RequestParam("code") String code, HttpServletResponse response){
        try{
            jwtUtil.validateToken(code);
            String email = jwtUtil.getEmail(code);
            redirect(response, "/register?email=" + email.replace("\"", ""));
        }catch (BuiltInException e){
            log.info(e.getMessage());
            redirect(response, "");
        }
    }

    private void redirect(HttpServletResponse response, String address){
        try {
            response.sendRedirect(clinetHost + address);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping(value = "/signup", consumes = "application/json;charset=UTF-8")
    public MemberDto signupByEmail(@RequestBody SignUpRequest signUpRequest){
        return signUpService.signUpByEmail(signUpRequest);
    }



}
