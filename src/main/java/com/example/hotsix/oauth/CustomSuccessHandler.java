package com.example.hotsix.oauth;

import com.example.hotsix.oauth.dto.CustomOAuth2User;
import com.example.hotsix.service.auth.LoginService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Value("${client.host}")
    private String clinetHost;
    private final LoginService loginService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("[CustomSuccessHandler]");
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();
        String email = customUserDetails.getEmail();

        Map<String, Cookie> cookies = loginService.issueAuthTokensAndCookies(email);

        response.addCookie(cookies.get("access"));
        response.addCookie(cookies.get("refresh"));
        response.sendRedirect(clinetHost+"/afterlogin");
    }

}
