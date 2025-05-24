
package com.example.hotsix.controller.auth;


import com.example.hotsix.dto.auth.ReissueResponse;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.service.auth.RedisTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ReissueController {


    private final JWTUtil jwtUtil;
    private final RedisTokenService logoutService;

    @Value("${jwt.access-token.expiretime}")
    private Long accessExpiretime;

    @PostMapping("/reissue")
    public ReissueResponse reissue(HttpServletRequest request, HttpServletResponse response) {
        log.info("reissue");
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")){
                refresh = cookie.getValue();
            }
        }
        log.info("refresh: {}", refresh);

        if(refresh ==null){
            log.info("refresh is null");
            throw new BuiltInException(Process.INVALID_TOKEN);
        }

        try {
            jwtUtil.validateToken(refresh);
        }catch (ExpiredJwtException e){
            log.info("refresh token is expired");
            throw new BuiltInException(Process.EXPIRED_TOKEN);
        }

        String category = jwtUtil.getCategory(refresh);
log.info("category: {}", category);
        if(!category.equals("refresh")){
            log.info("refresh token is invalid");
            throw new BuiltInException(Process.INVALID_TOKEN);
        }

        // 레디스에 리프레시토큰없을때
        if( !logoutService.isTokenInRedis(jwtUtil.getId(refresh).toString())){
            log.info("만료된 리프레시토큰");
            throw new BuiltInException(Process.EXPIRED_TOKEN);
        }


        log.info("Access토큰 재발행");
        String username = jwtUtil.getUsername(refresh);
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


        String newAccess = jwtUtil.createAccessToken(memberDto, accessExpiretime);
log.info("newAccess: {}", newAccess);
        response.setHeader("Authorization", "Bearer " + newAccess);


        return ReissueResponse.builder()
                .token(newAccess)
                .build();
    }


}