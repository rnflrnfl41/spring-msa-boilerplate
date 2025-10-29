package com.example.webbffserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RedisConnectionChecker implements CommandLineRunner {

    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    public void run(String... args) {
        try {
            redisTemplate.opsForValue().set("redis:test", "OK");
            Object result = redisTemplate.opsForValue().get("redis:test");
            System.out.println("✅ Redis 연결 성공: " + result);
        } catch (Exception e) {
            System.err.println("❌ Redis 연결 실패: " + e.getMessage());
        }
    }
}
