package com.example.authserver.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@RequiredArgsConstructor
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository clientRepository;

    private static final String KEY_PREFIX = "oauth2:consent:";

    @Override
    public void save(OAuth2AuthorizationConsent consent) {
        String key = KEY_PREFIX + consent.getRegisteredClientId() + ":" + consent.getPrincipalName();
        redisTemplate.opsForValue().set(key, consent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent consent) {
        String key = KEY_PREFIX + consent.getRegisteredClientId() + ":" + consent.getPrincipalName();
        redisTemplate.delete(key);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String clientId, String principalName) {
        String key = KEY_PREFIX + clientId + ":" + principalName;
        Object obj = redisTemplate.opsForValue().get(key);
        return (obj instanceof OAuth2AuthorizationConsent) ? (OAuth2AuthorizationConsent) obj : null;
    }
}
