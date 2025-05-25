
package com.example.hotsix.controller.auth;


import com.example.hotsix.dto.auth.ReissueResponse;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.service.auth.RedisTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ReissueController {


    private final JWTUtil jwtUtil;
    private final RedisTokenService redisTokenService;

    @Value("${jwt.access-token.expiretime}")
    private Long accessExpiretime;

    @PostMapping("/reissue")
    public ReissueResponse reissue(HttpServletRequest request, HttpServletResponse response) {
        log.info("reissue");
        String refresh = getToeknFromCookie(request).orElseThrow(() -> new BuiltInException(Process.INVALID_TOKEN));
        validateRefreshToken(refresh);

        String newAccess = reissueAcessToken(refresh);
        response.setHeader("Authorization", "Bearer " + newAccess);

        return ReissueResponse.builder()
                .token(newAccess)
                .build();
    }

    private String reissueAcessToken(String refresh) {
        String role = jwtUtil.getRole(refresh);
        Long id= jwtUtil.getId(refresh);
        String name = jwtUtil.getName(refresh);
        String email = jwtUtil.getEmail(refresh);

        MemberDto memberDto = MemberDto.builder()
                .id(id)
                .email(email)
                .name(name)
                .role(role)
                .build();

        return jwtUtil.createAccessToken(memberDto, accessExpiretime);
    }

    private void validateRefreshToken(String refresh) {
        try {
            jwtUtil.validateToken(refresh);
            jwtUtil.isTokenTypeRefresh(refresh);
            isAleadyLogoutToken(refresh);
        }catch (BuiltInException e){
            throw e;
        }
    }

    private void isAleadyLogoutToken(String refresh) {
        if(!redisTokenService.isTokenInRedis(jwtUtil.getId(refresh).toString()))
            throw new BuiltInException(Process.INVALID_TOKEN);

    }

    private static Optional<String> getToeknFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")){
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

}