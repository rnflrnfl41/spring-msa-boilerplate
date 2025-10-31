package com.example.authserver.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository clientRepository;

    private static final String KEY_PREFIX = "oauth2:authorization:";

    @Override
    public void save(OAuth2Authorization authorization) {
        String key = KEY_PREFIX + authorization.getId();
        redisTemplate.opsForValue().set(key, authorization);
        log.debug("✅ Saved OAuth2Authorization: {}", key);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        String key = KEY_PREFIX + authorization.getId();
        redisTemplate.delete(key);
        log.debug("❌ Removed OAuth2Authorization: {}", key);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        String key = KEY_PREFIX + id;
        Object obj = redisTemplate.opsForValue().get(key);
        return (obj instanceof OAuth2Authorization) ? (OAuth2Authorization) obj : null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (token == null) return null;

        Set<String> keys = redisTemplate.keys(KEY_PREFIX + "*");
        if (keys == null) return null;

        for (String key : keys) {
            OAuth2Authorization auth = (OAuth2Authorization) redisTemplate.opsForValue().get(key);
            if (auth != null) {
                if (hasToken(auth, token, tokenType)) {
                    return auth;
                }
            }
        }
        return null;
    }

    private boolean hasToken(OAuth2Authorization auth, String token, OAuth2TokenType type) {
        if (type == null) {
            return matchesToken(auth.getAccessToken(), token) ||
                    matchesToken(auth.getRefreshToken(), token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(type)) {
            return matchesToken(auth.getAccessToken(), token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(type)) {
            return matchesToken(auth.getRefreshToken(), token);
        }
        return false;
    }

    private boolean matchesToken(OAuth2Authorization.Token<?> token, String value) {
        return token != null && token.getToken().getTokenValue().equals(value);
    }
}
