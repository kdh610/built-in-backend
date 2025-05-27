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

    /**
     * Handles email-based login by validating the provided code, issuing authentication cookies, and redirecting the user after successful login.
     *
     * @param code the access token received via email for authentication
     * @param response the HTTP response used to set authentication cookies and perform the redirect
     */
    @GetMapping("/email-login")
    public void emailLogin(@RequestParam("code") String code, HttpServletResponse response){
        try{
            jwtUtil.validateAccessToken(code);
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

    /**
     * Handles email-based registration by validating the provided code and redirecting the user.
     *
     * Validates the access token from the code parameter, extracts the associated email, and redirects the client to the registration page with the email as a query parameter. If validation fails, logs the exception and redirects to the root path.
     *
     * @param code the access token received via email for registration
     * @param response the HTTP response used for redirection
     */
    @GetMapping("/register")
    public void register(@RequestParam("code") String code, HttpServletResponse response){
        try{
            jwtUtil.validateAccessToken(code);
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
