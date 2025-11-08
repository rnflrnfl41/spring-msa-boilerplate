package com.example.authserver.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private static final String BLACKLIST_PREFIX = "oauth2:blacklist:";

    private final RedisTemplate<String, Object> redisTemplate;

    public void blacklist(String accessToken, Duration ttl) {
        if (!StringUtils.hasText(accessToken) || ttl == null) {
            return;
        }

        Duration effectiveTtl = ttl.isNegative() || ttl.isZero()
                ? Duration.ofSeconds(1)
                : ttl;

        redisTemplate.opsForValue()
                .set(BLACKLIST_PREFIX + accessToken, Boolean.TRUE, effectiveTtl);

        log.debug("✅ accessToken 블랙리스트 등록 (남은 TTL: {}초)", effectiveTtl.toSeconds());
    }

    public boolean isBlacklisted(String accessToken) {
        if (!StringUtils.hasText(accessToken)) {
            return false;
        }
        Boolean value = (Boolean) redisTemplate.opsForValue()
                .get(BLACKLIST_PREFIX + accessToken);
        return Boolean.TRUE.equals(value);
    }
}

