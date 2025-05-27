package com.example.hotsix.jwt;

import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.service.auth.RedisTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;

@Component
@Slf4j
public class JWTUtil {

    private final RedisTokenService redisTokenService;
    private final SecretKey secretKey;

    /****
     * Constructs a JWT utility with the specified secret key and Redis token service.
     *
     * @param secret the secret string used to generate the cryptographic signing key
     * @param redisTokenService the service for managing token state in Redis
     */
    public JWTUtil(@Value("${jwt.salt}")String secret, RedisTokenService redisTokenService){
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
        this.redisTokenService = redisTokenService;
    }

    /**
     * Extracts the "username" claim from the provided JWT.
     *
     * @param token the JWT from which to extract the username
     * @return the username claim value, or null if not present
     */
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    /**
     * Extracts the "name" claim from the provided JWT.
     *
     * @param token the JWT from which to extract the name
     * @return the value of the "name" claim, or null if not present
     */
    public String getName(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("name", String.class);
    }

    /****
     * Extracts the "role" claim from the provided JWT.
     *
     * @param token the JWT from which to extract the role
     * @return the value of the "role" claim, or null if not present
     */
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    /**
     * Extracts the "id" claim as a Long from the specified JWT.
     *
     * @param token the JWT from which to extract the "id" claim
     * @return the value of the "id" claim, or null if not present
     */
    public Long getId(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("id", Long.class);
    }

    /**
     * Extracts the "email" claim from the given JWT, removing any surrounding quotes.
     *
     * @param token the JWT from which to extract the email claim
     * @return the email address contained in the token, without quotes
     */
    public String getEmail(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("email", String.class)
                .replace("\"", "");
    }

    /**
     * Validates an access token by checking if it is not blacklisted, structurally valid, and of type "access".
     *
     * @param accessToken the JWT access token to validate
     * @throws BuiltInException if the token is blacklisted, invalid, expired, or not an access token
     */
    public void validateAccessToken(String accessToken) {
        isBlackListToken(accessToken);
        validateToken(accessToken);
        isTokenTypeAccess(accessToken);
    }

    /**
     * Validates a refresh token by checking its structure, type, and logout status.
     *
     * This method ensures the provided token is a valid, unexpired JWT of type "refresh" and has not been logged out (i.e., is present in Redis).
     *
     * @param refresh the refresh token to validate
     * @throws BuiltInException if the token is invalid, expired, not a refresh token, or has been logged out
     */
    public void validateRefreshToken(String refresh) {
        validateToken(refresh);
        isTokenTypeRefresh(refresh);
        isLoggedOutRefreshToken(refresh);
    }

    /****
     * Checks if the provided refresh token is present in Redis, indicating it is not logged out.
     *
     * @param refresh the refresh token to check
     * @throws BuiltInException if the token is not found in Redis, indicating it has been logged out or is invalid
     */
    private void isLoggedOutRefreshToken(String refresh) {
        if(!redisTokenService.isTokenInRedis(getId(refresh).toString()))
            throw new BuiltInException(Process.INVALID_TOKEN);
    }

    /****
     * Checks if the provided access token is blacklisted in Redis and throws an exception if it is.
     *
     * @param accessToken the JWT access token to check
     * @throws BuiltInException if the token is found in the Redis blacklist
     */
    private void isBlackListToken(String accessToken) {
        if(redisTokenService.isTokenInRedis(accessToken))
            throw new BuiltInException(Process.INVALID_TOKEN);
    }

    /**
     * Validates the structure, signature, and expiration of a JWT token.
     *
     * @param token the JWT token to validate
     * @return true if the token is valid; false if the token is null
     * @throws BuiltInException if the token is invalid, expired, unsupported, or malformed
     */
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
        }
        return false;
    }

    public Boolean isTokenTypeAccess(String token){
        String category = getCategory(token);
        if(!category.equals("access")) {
            throw new BuiltInException(Process.INVALID_TOKEN);
        }
        return true;
    }

    public Boolean isTokenTypeRefresh(String token){
        String category = getCategory(token);
        if(!category.equals("refresh")) {
            throw new BuiltInException(Process.INVALID_TOKEN);
        }
        return true;
    }

    public String getCategory(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public long getRemainingTime(String token) {
        Date expiration1 = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration();
        long currentTimeMillis = System.currentTimeMillis();
        long remainingTimeMillis = expiration1.getTime() - currentTimeMillis;

        return remainingTimeMillis;
    }

    public String createAccessToken(MemberDto memberDto, Long expiredMs) {
        return createJwt(memberDto, "access", expiredMs);
    }

    public String createRefreshToken(MemberDto memberDto, Long expiredMs) {
        return createJwt(memberDto, "refresh", expiredMs);
    }

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

    /**
     * Creates a JWT containing only the email claim with a fixed expiration of 3 days.
     *
     * @param email the email address to include in the token
     * @return a signed JWT string with the email claim and 3-day validity
     */
    public String createEmailJwt(String email){
        return Jwts.builder()
                .claim("email",email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 259200000))
                .signWith(secretKey)
                .compact();
    }

    /**
     * Retrieves a token value from the HTTP request cookies that matches the specified token type.
     *
     * @param request the HTTP servlet request containing cookies
     * @param cookieName the token type to search for in the cookies
     * @return an {@code Optional} containing the token value if found, or empty if not present
     */
    public Optional<String> getTokenFromCookie(HttpServletRequest request, TokenType cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (cookieName.getTokenType().equals(cookie.getName())) {
                return Optional.ofNullable(cookie.getValue());
            }
        }
        return Optional.empty();
    }


}
