package com.example.hotsix.service.auth;

import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.model.Member;
import com.example.hotsix.repository.member.MemberRepository;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginService {

    @Value("${jwt.access-token.expiretime}")
    private Long accessExpiretime;
    @Value("${jwt.refresh-token.expiretime}")
    private Long refreshExpiretime;

    private final MemberRepository memberRepository;
    private final JWTUtil jwtUtil;
    private final RedisTokenService redisTokenService;

    public Map<String, Cookie> issueAuthTokensAndCookies(String email) {
        Member member = memberRepository.findByEmail(email);
        MemberDto memberDto = member.toDto();

        String accessToken = jwtUtil.createAccessToken(memberDto, accessExpiretime);
        String refreshToken = jwtUtil.createRefreshToken(memberDto, refreshExpiretime);
        redisTokenService.saveRefreshToken(member.getId().toString(), refreshToken, refreshExpiretime);

        Map<String, Cookie> cookieMap = new HashMap<>();
        Cookie accessCookie = createCookie("access", accessToken, accessExpiretime);
        Cookie refreshCookie = createCookie("refresh", refreshToken, refreshExpiretime);
        cookieMap.put("access",accessCookie);
        cookieMap.put("refresh",refreshCookie);
        return cookieMap;
    }

    private Cookie createCookie(String key, String value, Long expiretime){
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(expiretime.intValue());
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }
}
