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

    /**
     * Delegates filtering to the HTTP-specific doFilter method by casting the generic servlet request and response.
     *
     * @param servletRequest the incoming servlet request
     * @param servletResponse the outgoing servlet response
     * @param filterChain the filter chain for invoking the next filter or resource
     * @throws IOException if an I/O error occurs during filtering
     * @throws ServletException if a servlet error occurs during filtering
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        doFilter((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain );
    }

    /**
     * Handles logout requests by invalidating access and refresh tokens.
     *
     * Processes POST requests to endpoints ending with `/logout` by validating and blacklisting the access token, deleting the refresh token from Redis, and clearing the refresh token cookie. For non-logout or non-POST requests, the filter chain proceeds without modification.
     *
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @param filterChain the filter chain to pass control to the next filter
     * @throws IOException if an I/O error occurs during processing
     * @throws ServletException if a servlet error occurs during processing
     */
    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        log.info("로그아웃 필터");
        log.info("request url: {}", request.getRequestURI());

        if(!request.getRequestURI().matches("^/.*logout$")){
            log.info("/logout 요청이 아님");
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
