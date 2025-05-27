package com.example.hotsix.jwt.filter;

import com.example.hotsix.dto.common.APIResponse;
import com.example.hotsix.dto.common.ErrorResponse;
import com.example.hotsix.dto.common.ProcessResponse;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.jwt.TokenType;
import com.example.hotsix.service.auth.RedisTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RedisTokenService redisTokenService;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        doFilter((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain );
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if(!request.getRequestURI().matches("^/.*logout$")){
            filterChain.doFilter(request, response);
            return;
        }
        if(!request.getMethod().equals("POST")){
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = request.getHeader("Authorization");
        if(accessToken != null){
            jwtUtil.validateAccessToken(accessToken);
            long remainingTime = jwtUtil.getRemainingTime(accessToken);
            redisTokenService.blacklistAccessToken(accessToken, remainingTime);
        }

        String refreshToken = jwtUtil.getTokenFromCookie(request, TokenType.REFRESH)
                .orElseThrow(() -> new BuiltInException(Process.INVALID_TOKEN));
        jwtUtil.validateRefreshToken(refreshToken);

        redisTokenService.deleteRefreshToken(jwtUtil.getId(refreshToken).toString());

        Cookie cookie = new Cookie("refresh",null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        log.info("로그아웃 완료");
        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }



}
