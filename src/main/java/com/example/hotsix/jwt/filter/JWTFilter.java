package com.example.hotsix.jwt.filter;

import com.example.hotsix.dto.common.APIResponse;
import com.example.hotsix.dto.common.ErrorResponse;
import com.example.hotsix.dto.common.ProcessResponse;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.jwt.TokenType;
import com.example.hotsix.oauth.dto.CustomOAuth2User;
import com.example.hotsix.oauth.dto.UserDTO;
import com.example.hotsix.service.auth.RedisTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final RedisTokenService redisTokenService;

    /**
     * Processes incoming HTTP requests to authenticate users based on JWT access and refresh tokens.
     *
     * This filter intercepts requests, bypassing authentication for WebSocket and API documentation endpoints.
     * It extracts JWT tokens from headers or cookies, validates access tokens when present, and sets the Spring Security context for authenticated requests.
     * If no valid tokens are found, or for specific endpoints, the request proceeds without authentication.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param filterChain the filter chain to continue processing
     * @throws ServletException if an error occurs during filtering
     * @throws IOException if an I/O error occurs during filtering
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JWT 필터");
        log.info("request url: {}", request.getRequestURI());
        log.info("request cookies: {}", (Object[]) request.getCookies());
        if(request.getRequestURI().startsWith("/ws/log") || request.getRequestURI().startsWith("/ws/chat")){
            System.out.println("WebSocket 전용 처리 구간 도달. doFilter 호출");
            filterChain.doFilter(request,response);
            return;
        }
        String requestURL = request.getRequestURI();
        if (requestURL.startsWith("/hot6man/swagger-ui.html") ||
                requestURL.startsWith("/hot6man/swagger-ui/") ||
                requestURL.startsWith("/hot6man/v3/api-docs")) {
            filterChain.doFilter(request, response);
            return;
        }


        String refreshToken = jwtUtil.getTokenFromCookie(request, TokenType.REFRESH).orElse(null);
        String accessToken = getAccessTokenFromHeader(request);
        log.info("accessToken: {}", accessToken);
        log.info("refreshToken: {}", refreshToken);

        if(isGeneralRequest(accessToken, refreshToken)){
            jwtUtil.validateAccessToken(accessToken);
            setSecurityContext(request, response, filterChain, accessToken);
            return;
        }
        else if(isReissueRequest(refreshToken, accessToken)){
            filterChain.doFilter(request, response);
            return;
        }
        else if(refreshToken != null && accessToken != null){
            jwtUtil.validateAccessToken(accessToken);
            setSecurityContext(request, response, filterChain, accessToken);
            return;
        }

        // 처음 로그인시 accessToken을 쿠키에서 헤더로 이동
        accessToken = jwtUtil.getTokenFromCookie(request,TokenType.ACCESS).orElse(null);
        if(accessToken!=null){
            log.info("처음 로그인 JWT 필터 끝");
            setSecurityContext(request, response, filterChain, accessToken);
            return;
        }

        if(isLoginOrSignUpRequest(accessToken, refreshToken)){
            log.info("가입, 로그인 JWT 필터 끝");
            filterChain.doFilter(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Retrieves the access token from the "Authorization" header of the HTTP request.
     *
     * @param request the incoming HTTP request
     * @return the value of the "Authorization" header, or null if not present
     */
    private String getAccessTokenFromHeader(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    /**
     * Determines if the request is a general authenticated request based on token presence.
     *
     * @param authorization the access token from the Authorization header, or null if absent
     * @param refreshToken the refresh token from cookies, or null if absent
     * @return true if only the access token is present and the refresh token is absent
     */
    private static boolean isGeneralRequest(String authorization, String refreshToken) {
        return authorization != null && refreshToken == null;
    }

    private static boolean isReissueRequest(String refreshToken, String authorization) {
        return refreshToken != null && authorization == null;
    }

    /**
     * Determines whether the request is for login or signup based on the absence of both access and refresh tokens.
     *
     * @param accessToken the access token, or null if not present
     * @param refreshToken the refresh token, or null if not present
     * @return true if both tokens are absent, indicating a login or signup request; false otherwise
     */
    private static boolean isLoginOrSignUpRequest(String accessToken, String refreshToken) {
        return accessToken == null && refreshToken == null;
    }

    /**
     * Sets the Spring Security context with authentication details extracted from the provided access token and continues the filter chain.
     *
     * @param accessToken the JWT access token used to extract user authentication information
     * @throws IOException if an input or output error occurs during filter processing
     * @throws ServletException if the filter chain fails
     */
    private void setSecurityContext(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String accessToken) throws IOException, ServletException {
        log.info("인증완료 SecurityContextHolder 설정");

        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);
        Long id = jwtUtil.getId(accessToken);
        String name = jwtUtil.getName(accessToken);

        UserDTO userDTO = UserDTO.builder()
                .username(username)
                .role(role)
                .id(id)
                .name(name)
                .build();

        //UserDetails에 회원 정보 객체 담기
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);
        log.info("customOAuth2User: {}", customOAuth2User);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
        log.info("authToken: {}", authToken.getPrincipal().toString());

        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }


}