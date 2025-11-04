package com.example.authserver.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Slf4j
@RequiredArgsConstructor
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository clientRepository;

    private static final String KEY_PREFIX = "oauth2:consent:";

    @Override
    public void save(OAuth2AuthorizationConsent consent) {
        String key = KEY_PREFIX + consent.getRegisteredClientId() + ":" + consent.getPrincipalName();
        redisTemplate.opsForValue().set(key, consent);
        log.debug("✅ Saved OAuth2AuthorizationConsent for {} / {}", consent.getPrincipalName(), consent.getRegisteredClientId());
    }

    @Override
    public void remove(OAuth2AuthorizationConsent consent) {
        String key = KEY_PREFIX + consent.getRegisteredClientId() + ":" + consent.getPrincipalName();
        redisTemplate.delete(key);
        log.debug("🗑️ Removed OAuth2AuthorizationConsent for {} / {}", consent.getPrincipalName(), consent.getRegisteredClientId());
    }

    @Override
    public OAuth2AuthorizationConsent findById(String clientId, String principalName) {
        String key = KEY_PREFIX + clientId + ":" + principalName;
        Object obj = redisTemplate.opsForValue().get(key);

        if (obj instanceof OAuth2AuthorizationConsent consent) {
            return consent;
        } else if (obj == null) {
            return null;
        } else {
            log.warn("⚠️ Unexpected object type for consent key {}: {}", key, obj.getClass());
            return null;
        }
    }
}
