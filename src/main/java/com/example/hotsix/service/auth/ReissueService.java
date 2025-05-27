package com.example.hotsix.service.auth;

import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ReissueService {
    private final JWTUtil jwtUtil;
    private final RedisTokenService redisTokenService;
    @Value("${jwt.access-token.expiretime}")
    private Long accessExpiretime;

    public String reissueAcessToken(String refresh) {
        validateRefreshToken(refresh);

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
            isLoggedOutToken(refresh);
        }catch (BuiltInException e){
            throw e;
        }
    }

    private void isLoggedOutToken(String refresh) {
        if(!redisTokenService.isTokenInRedis(jwtUtil.getId(refresh).toString()))
            throw new BuiltInException(Process.INVALID_TOKEN);
    }

}
