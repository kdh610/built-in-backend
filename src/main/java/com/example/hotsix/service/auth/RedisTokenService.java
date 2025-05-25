package com.example.hotsix.service.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    public void saveRefreshToken(String keyName, String refreshToken, Long refreshExpiretime) {
        redisTemplate.opsForValue().set(keyName, refreshToken, refreshExpiretime, TimeUnit.MILLISECONDS);
    }

    public void blacklistAccessToken(String accessToken, Long remainingTime){
        redisTemplate.opsForValue().set(accessToken,"logout", remainingTime, TimeUnit.MILLISECONDS);
    }

    public void deleteRefreshToken(String refreshKey){
        redisTemplate.delete(refreshKey);
    }

    public boolean isTokenInRedis(String key){
        return redisTemplate.hasKey(key);
    }


}
