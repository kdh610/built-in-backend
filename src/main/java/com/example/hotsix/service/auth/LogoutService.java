package com.example.hotsix.service.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService {
    private final RedisTokenService redisTokenService;

    public void logout(HttpServletResponse response, String refreshToken){
        redisTokenService.deleteRefreshToken(refreshToken);

        Cookie cookie = new Cookie("refresh",null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
