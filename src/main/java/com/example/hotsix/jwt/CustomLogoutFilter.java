package com.example.hotsix.jwt;

import com.example.hotsix.dto.common.APIResponse;
import com.example.hotsix.dto.common.ErrorResponse;
import com.example.hotsix.dto.common.ProcessResponse;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.service.auth.RedisTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
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

        
        //  access토큰 redis에 블랙리스트 처리
        String access = request.getHeader("Authorization");
        log.info("access: {}", access);
        if(access != null){
            log.info("access토큰 블랙리스트 처리");
            try{
                jwtUtil.validateToken(access);
                long remainingTime = jwtUtil.getRemainingTime(access);
                redisTokenService.blacklistAccessToken(access, remainingTime);
            }catch (BuiltInException e){
                log.info("Access 토큰 만료");
                jwtExceptionHandler(response,e);
                return;
            }
        }


        String refresh = jwtUtil.getTokenFromCookie(request,TokenType.REFRESH).orElse(null);

        if(refresh==null){
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        if(!redisTokenService.isTokenInRedis(jwtUtil.getId(refresh).toString())){
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        // 리프레시 토큰 삭제
        log.info("Redis refresh토큰 삭제");
        redisTokenService.deleteRefreshToken(jwtUtil.getId(refresh).toString());

        //리프레시 토큰 쿠키 값 0
        Cookie cookie = new Cookie("refresh",null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        log.info("로그아웃 완료");
        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
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
