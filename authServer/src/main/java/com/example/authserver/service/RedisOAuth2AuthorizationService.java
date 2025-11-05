package com.example.authserver.service;

import com.example.authserver.entity.AuthCodeEntity;
import com.example.authserver.entity.TokenEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.security.Principal;
import java.time.Duration;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository clientRepository;
    private final ObjectMapper objectMapper;

    private static final String AUTHORIZATION_PREFIX = "oauth2:authorization:";      // 메인
    private static final String AUTHORIZATION_CODE_PREFIX = "oauth2:authorization:code:"; // 인덱스
    private static final Duration TTL = Duration.ofMinutes(10);
    private static final String AUTHORIZATION_ACCESS_TOKEN_PREFIX = "oauth2:access_token:";
    private static final String AUTHORIZATION_REFRESH_TOKEN_PREFIX = "oauth2:authorization:refresh_token:";


    @Override
    public void save(OAuth2Authorization authorization) {
        // 1️⃣ 먼저 어떤 단계인지 판별
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);

        // ─────────────────────────────
        // 단계 1: Authorization Code 발급 직후 (/oauth2/authorize)
        // ─────────────────────────────
        if (codeToken != null && accessToken == null) {

            OAuth2AuthorizationCode code = codeToken.getToken();

            OAuth2AuthorizationRequest authRequest =
                    authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
            Authentication principal =
                    authorization.getAttribute(Principal.class.getName());

            if (principal == null || authRequest == null) {
                throw new IllegalStateException("Missing principal or OAuth2AuthorizationRequest");
            }

            AuthCodeEntity entity = AuthCodeEntity.builder()
                    .authorizationId(authorization.getId())
                    .registeredClientId(authorization.getRegisteredClientId())
                    .principalName(authorization.getPrincipalName())
                    .principal(principal)
                    .authorizationRequest(authRequest)
                    .scopes(authorization.getAuthorizedScopes())
                    .code(code.getTokenValue())
                    .issuedAt(code.getIssuedAt())
                    .expiresAt(code.getExpiresAt())
                    .build();

            // ID → AuthCodeEntity
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_PREFIX + entity.getAuthorizationId(),
                    entity,
                    TTL
            );
            // code → authorizationId (인덱스)
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_CODE_PREFIX + entity.getCode(),
                    entity.getAuthorizationId(),
                    TTL
            );

            log.debug("✅ [CODE-STAGE] Saved AuthCodeEntity id={}, code={}",
                    entity.getAuthorizationId(), entity.getCode());
            return;
        }

        // ─────────────────────────────
        // 단계 2: AccessToken (그리고 RefreshToken)까지 발급된 후 (/oauth2/token)
        // ─────────────────────────────
        if (accessToken != null) {
            // 여기서는 SAS가 authorization 안에 accessToken/refreshToken을 넣은 걸 다시 save()로 넘겨줌
            // 우리는 이걸 안전한 형태로 변환해서 저장하면 됨

            TokenEntity.TokenEntityBuilder builder = TokenEntity.builder()
                    .authorizationId(authorization.getId())
                    .registeredClientId(authorization.getRegisteredClientId())
                    .principalName(authorization.getPrincipalName())
                    .scopes(authorization.getAuthorizedScopes())
                    .accessTokenValue(accessToken.getToken().getTokenValue())
                    .accessTokenIssuedAt(accessToken.getToken().getIssuedAt())
                    .accessTokenExpiresAt(accessToken.getToken().getExpiresAt());

            // refresh token 있으면 같이
            if (refreshToken != null) {
                builder.refreshTokenValue(refreshToken.getToken().getTokenValue())
                        .refreshTokenIssuedAt(refreshToken.getToken().getIssuedAt())
                        .refreshTokenExpiresAt(refreshToken.getToken().getExpiresAt());
            }

            TokenEntity tokenEntity = builder.build();

            // ID → TokenEntity
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_PREFIX + authorization.getId(),
                    tokenEntity,
                    TTL
            );

            // access token → authorizationId (조회용 인덱스)
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_ACCESS_TOKEN_PREFIX + tokenEntity.getAccessTokenValue(),
                    authorization.getId(),
                    TTL
            );

            // refresh token도 있으면 인덱스 저장
            if (tokenEntity.getRefreshTokenValue() != null) {
                redisTemplate.opsForValue().set(
                        AUTHORIZATION_REFRESH_TOKEN_PREFIX + tokenEntity.getRefreshTokenValue(),
                        authorization.getId(),
                        TTL
                );
            }

            log.debug("✅ [TOKEN-STAGE] Saved TokenEntity id={}, accessToken=***{}",
                    authorization.getId(),
                    last6(tokenEntity.getAccessTokenValue()));
            return;
        }

        // 그 외 상태는 일단 로그만
        log.debug("⚠️ save(OAuth2Authorization) called with unsupported state: id={}", authorization.getId());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        // 1️⃣ AuthCodeEntity 제거
        redisTemplate.delete(AUTHORIZATION_PREFIX + authorization.getId());

        // 2️⃣ Authorization Code 인덱스 제거
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);

        if (codeToken != null) {
            String codeValue = codeToken.getToken().getTokenValue();
            redisTemplate.delete(AUTHORIZATION_CODE_PREFIX + codeValue);
            log.debug("🗑️ Removed AuthCodeEntity (id={}, code={})", authorization.getId(), codeValue);
        } else {
            // code가 null인 경우도 존재 (이미 AccessToken 단계일 수 있음)
            // 인덱스 키 전체를 스캔해서 authorizationId로 일치하는 항목 제거
            Set<String> keys = redisTemplate.keys(AUTHORIZATION_CODE_PREFIX + "*");
            if (keys != null) {
                for (String key : keys) {
                    String storedId = (String) redisTemplate.opsForValue().get(key);
                    if (authorization.getId().equals(storedId)) {
                        redisTemplate.delete(key);
                        log.debug("🧹 Cleaned up index key {}", key);
                    }
                }
            }
        }
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Object obj = redisTemplate.opsForValue().get(AUTHORIZATION_PREFIX + id);
        if (obj == null) return null;

        AuthCodeEntity entity = (obj instanceof AuthCodeEntity e)
                ? e
                : objectMapper.convertValue(obj, AuthCodeEntity.class);

        RegisteredClient client = clientRepository.findById(entity.getRegisteredClientId());
        if (client == null) return null;

        OAuth2AuthorizationCode authCode = new OAuth2AuthorizationCode(
                entity.getCode(), entity.getIssuedAt(), entity.getExpiresAt()
        );

        return OAuth2Authorization.withRegisteredClient(client)
                .id(entity.getAuthorizationId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(entity.getScopes())
                .attribute(OAuth2AuthorizationRequest.class.getName(), entity.getAuthorizationRequest())
                .attribute(Principal.class.getName(), entity.getPrincipal())
                .token(authCode)
                .build();
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (!OAuth2ParameterNames.CODE.equals(tokenType.getValue())) return null;

        // code → authorizationId 매핑 조회
        String authorizationId = (String) redisTemplate.opsForValue().get(AUTHORIZATION_CODE_PREFIX + token);
        if (authorizationId == null) return null;

        // authorizationId로 AuthCodeEntity 복원
        Object obj = redisTemplate.opsForValue().get(AUTHORIZATION_PREFIX + authorizationId);
        if (obj == null) return null;

        AuthCodeEntity entity = (obj instanceof AuthCodeEntity e)
                ? e
                : objectMapper.convertValue(obj, AuthCodeEntity.class);

        RegisteredClient client = clientRepository.findById(entity.getRegisteredClientId());
        if (client == null) return null;

        OAuth2AuthorizationCode authCode = new OAuth2AuthorizationCode(
                entity.getCode(), entity.getIssuedAt(), entity.getExpiresAt()
        );

        return OAuth2Authorization.withRegisteredClient(client)
                .id(entity.getAuthorizationId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(entity.getScopes())
                .attribute(OAuth2AuthorizationRequest.class.getName(), entity.getAuthorizationRequest())
                .attribute(Principal.class.getName(), entity.getPrincipal())
                .token(authCode)
                .build();
    }

    private String last6(String v) {
        if (v == null || v.length() <= 6) return v;
        return v.substring(v.length() - 6);
    }

}
