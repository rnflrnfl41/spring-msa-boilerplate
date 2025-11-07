package com.example.authserver.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
@Slf4j
public class CustomAuthorizationService implements OAuth2AuthorizationService {

    private final ConcurrentMap<String, OAuth2Authorization> store = new ConcurrentHashMap<>();
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
            new OAuth2TokenType(OAuth2ParameterNames.CODE);

    @Override
    public void save(OAuth2Authorization authorization) {
        // 1️⃣ Authorization Code 발급 단계
        if (authorization.getToken(OAuth2AuthorizationCode.class) != null
                && authorization.getToken(OAuth2AccessToken.class) == null) {
            store.put(authorization.getId(), authorization);
            log.debug("✅ [CODE-STAGE] Saved authorization temporarily: {}", authorization.getId());
            return;
        }

        // 2️⃣ AccessToken 발급까지 완료된 경우 → 삭제
        if (authorization.getToken(OAuth2AccessToken.class) != null) {
            store.remove(authorization.getId());
            log.debug("🧹 [TOKEN-STAGE] Removed authorization after token issued: {}", authorization.getId());
            return;
        }

        // 3️⃣ 그 외 상태는 무시
        log.debug("⚠️ [UNKNOWN-STAGE] save() called but no code or token found: {}", authorization.getId());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        store.remove(authorization.getId());
        log.debug("🧹 Removed authorization: {}", authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return store.get(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (!AUTHORIZATION_CODE_TOKEN_TYPE.equals(tokenType)) {
            return null;
        }
        return store.values().stream()
                .filter(a -> {
                    OAuth2Authorization.Token<OAuth2AuthorizationCode> code = a.getToken(OAuth2AuthorizationCode.class);
                    return code != null && code.getToken().getTokenValue().equals(token);
                })
                .findFirst()
                .orElse(null);
    }
}
