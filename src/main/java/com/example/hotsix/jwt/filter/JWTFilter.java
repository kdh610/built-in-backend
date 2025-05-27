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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JWT 필터");
        log.info("request url: {}", request.getRequestURI());
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
        String accessToken = jwtUtil.getTokenFromCookie(request,TokenType.ACCESS).orElse(getAccessTokenFromHeader(request));

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

        // 처음 로그인시 accessToken을 쿠키에서 헤더로 이동
        if(accessToken!=null){
            log.info("처음 로그인 JWT 필터 끝");
            setSecurityContext(request, response, filterChain, accessToken);
            return;
        }

        log.info("가입, 로그인 JWT 필터 끝");
        filterChain.doFilter(request, response);
    }

    private String getAccessTokenFromHeader(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    private static boolean isGeneralRequest(String authorization, String refreshToken) {
        return authorization != null && refreshToken == null;
    }

    private static boolean isReissueRequest(String refreshToken, String authorization) {
        return refreshToken != null && authorization == null;
    }

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