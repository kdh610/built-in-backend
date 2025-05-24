package com.example.hotsix.jwt;

import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${jwt.salt}")String secret){
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getName(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("name", String.class);
    }

    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Long getId(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("id", Long.class);
    }

    public String getEmail(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("email", String.class)
                .replace("\"", "");
    }



    public Boolean validateToken(String token) {
        log.info("[JWTUtil] 토큰 만료 검증");
        try {
            if (token != null) {
                Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
                return true;
            }
        }catch (SecurityException | MalformedJwtException e) {
            log.error("유효하지 않는 JWT 토큰 입니다. {}",e.getMessage());
            throw new BuiltInException(Process.INVALID_TOKEN);
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 토큰 입니다.");
            throw new BuiltInException(Process.EXPIRED_TOKEN);
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 JWT 토큰 입니다.");
            throw new BuiltInException(Process.INVALID_TOKEN);
        } catch (IllegalArgumentException e) {
            log.error("잘못된 JWT 토큰 입니다.");
            throw new BuiltInException(Process.INVALID_TOKEN);
        }catch (SignatureException e){
            throw new BuiltInException(Process.INVALID_TOKEN);
        }
        return false;
    }

    public Boolean isTokenTypeAccess(String token){
        String category = getCategory(token);

        if(!category.equals("access")) {
            log.info("카테고리가 access가 아니다");
            throw new BuiltInException(Process.INVALID_TOKEN);
        }
        return true;
    }

    public long getRemainingTime(String token) {
        Date expiration1 = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration();

        long currentTimeMillis = System.currentTimeMillis();

        // 남은 시간 계산 (밀리초 단위)
        long remainingTimeMillis = expiration1.getTime() - currentTimeMillis;

        return remainingTimeMillis;
    }

    public String getCategory(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }


    //토큰 생성
    public String createJwt(MemberDto memberDto, String category, Long expiredMs) {
        log.info("[JWTUtil] JWT토큰 생성");
        Long id = memberDto.getId();
        String role = memberDto.getRole();
        String name = memberDto.getName();
        String email = memberDto.getEmail();

        return Jwts.builder()
                .claim("name",name)
                .claim("email",email)
                .claim("id", id)
                .claim("category",category)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }


    public String createEmailJwt(String email){
        return Jwts.builder()
                .claim("email",email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 259200000))
                .signWith(secretKey)
                .compact();
    }


    public String createAccessToken(MemberDto memberDto, Long expiredMs) {
        return createJwt(memberDto, "access", expiredMs);
    }

    public String createRefreshToken(MemberDto memberDto, Long expiredMs) {
        return createJwt(memberDto, "refresh", expiredMs);
    }




}
