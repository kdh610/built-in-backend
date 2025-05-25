package com.example.hotsix.jwt;

import com.example.hotsix.dto.common.APIResponse;
import com.example.hotsix.dto.common.ErrorResponse;
import com.example.hotsix.dto.common.ProcessResponse;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.oauth.dto.CustomOAuth2User;
import com.example.hotsix.oauth.dto.UserDTO;
import com.example.hotsix.service.auth.RedisTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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


        String refreshToken = getRefreshToken(request);
        String accessToken = getAccessTokenFromHeader(request);
        log.info("accessToken: {}", accessToken);
        log.info("refreshToken: {}", refreshToken);

        if(isGeneralRequest(accessToken, refreshToken)){
            if (validateAccessToken(response, accessToken)) return;
            setSecurityContext(request, response, filterChain, accessToken);
            return;
        }
        else if(isReissueRequest(refreshToken, accessToken)){
            filterChain.doFilter(request, response);
            return;
        }
        else if(refreshToken != null && accessToken != null){
            try {
                if (jwtUtil.validateToken(accessToken)) {
                    setSecurityContext(request, response, filterChain, accessToken);
                    return;
                }
            } catch (BuiltInException e) {
                jwtExceptionHandler(response,e);
                return;
            }
        }

        // 처음 로그인시 accessToken을 쿠키에서 헤더로 이동
        accessToken = getAccessToeknFromCookie(request);
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

    private boolean validateAccessToken(HttpServletResponse response, String accessToken) {
        try{
            isBlackListToken(accessToken);
            jwtUtil.validateToken(accessToken);
            jwtUtil.isTokenTypeAccess(accessToken);
        }catch (BuiltInException e){
            jwtExceptionHandler(response,e);
            return true;
        }
        return false;
    }

    private void isBlackListToken(String accessToken) {
        if(redisTokenService.isTokenInRedis(accessToken)) {
            throw new BuiltInException(Process.INVALID_TOKEN);
        }
    }

    private static boolean isGeneralRequest(String authorization, String refreshToken) {
        return authorization != null && refreshToken == null;
    }

    private static boolean isReissueRequest(String refreshToken, String authorization) {
        return refreshToken != null && authorization == null;
    }

    private static boolean isLoginOrSignUpRequest(String accessToken, String refreshToken) {
        return accessToken == null && refreshToken == null;
    }

    private String getAccessTokenFromHeader(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    private String getAccessToeknFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("access")) {
                    String accessToekn = cookie.getValue();
                    log.info("accessToekn token: {}", accessToekn);
                    return accessToekn;
                }
            }
        }
        return null;
    }

    private String getRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refresh")) {
                    String refreshToken = cookie.getValue();
                    return refreshToken;
                }
            }
        }
        return null;
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

    public void jwtExceptionHandler(HttpServletResponse response, BuiltInException error) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .process(error.getProcess())
                .build();

        APIResponse<Object> apiResponse = APIResponse.builder()
                .process(ProcessResponse.from(errorResponse.getProcess()))
                .build();


        response.setStatus(errorResponse.getProcess().getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        try {
            String json = new ObjectMapper().writeValueAsString(apiResponse);
            response.getWriter().write(json);

        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }

}