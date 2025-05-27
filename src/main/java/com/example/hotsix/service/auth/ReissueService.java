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
    @Value("${jwt.access-token.expiretime}")
    private Long accessExpiretime;

    /**
     * Issues a new access token based on a valid refresh token.
     *
     * Validates the provided refresh token, extracts user information, and generates a new access token with the configured expiration time.
     *
     * @param refresh the refresh token used to authenticate and extract user details
     * @return a newly generated access token
     */
    public String reissueAcessToken(String refresh) {
        jwtUtil.validateRefreshToken(refresh);

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

}
