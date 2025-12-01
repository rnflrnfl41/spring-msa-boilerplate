package com.example.authserver.service;

import com.example.authserver.entity.AuthCodeEntity;
import com.example.authserver.entity.TokenEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    //TODO: 만약 redis에서 TTL 만료로 authorization이 사라진다?
    // 그럼 어떻게 처리 되야하는지도 확인해야함 (로그인창으로 리다이렉트 던가 등)
    // 그리고 httpOnly쿠키에 들어가 있는 토큰 값도 날려줘야함

    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper;

    // 메인 저장
    private static final String AUTHORIZATION_PREFIX = "oauth2:auth:";           // id → AuthCodeEntity or TokenEntity
    // 인덱스
    private static final String AUTHORIZATION_CODE_PREFIX = "oauth2:code:"; // code → id
    private static final String AUTHORIZATION_ACCESS_TOKEN_PREFIX = "oauth2:access_token:"; // accessToken → id
    private static final String AUTHORIZATION_REFRESH_TOKEN_PREFIX = "oauth2:refresh_token:"; // refreshToken → id

    // 전체 TTL (단, accessToken / refreshToken은 만료 시간에 맞춰 별도로 TTL 줌)
    private static final Duration TTL = Duration.ofMinutes(10);

    // code 토큰 타입 상수
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
            new OAuth2TokenType(OAuth2ParameterNames.CODE);

    @Override
    public void save(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);

        // ① 코드 단계 (Authorization Code 발급 시점)
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

            // id → entity
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_PREFIX + entity.getAuthorizationId(),
                    entity,
                    TTL
            );
            // code → id
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_CODE_PREFIX + entity.getCode(),
                    entity.getAuthorizationId(),
                    TTL
            );

            log.debug("✅ [CODE-STAGE] Saved AuthCodeEntity id={}, code={}",
                    entity.getAuthorizationId(), entity.getCode());
            return;
        }

        // ② 토큰 단계 (AccessToken / RefreshToken 발급 시점)
        if (accessToken != null) {
            // 기존 데이터 가져오기 (code 단계 또는 token 단계)
            Object oldObj = redisTemplate.opsForValue().get(AUTHORIZATION_PREFIX + authorization.getId());
            AuthCodeEntity oldEntity = null;
            TokenEntity oldTokenEntity = null;
            
            if (oldObj instanceof AuthCodeEntity e) {
                oldEntity = e;
            } else if (oldObj instanceof TokenEntity te) {
                oldTokenEntity = te;
            } else if (oldObj != null) {
                // 방어적 변환 시도
                try {
                    oldEntity = objectMapper.convertValue(oldObj, AuthCodeEntity.class);
                } catch (Exception ex) {
                    try {
                        oldTokenEntity = objectMapper.convertValue(oldObj, TokenEntity.class);
                    } catch (Exception ex2) {
                        log.warn("⚠️ cannot convert prev auth to AuthCodeEntity/TokenEntity: {}", ex2.getMessage());
                    }
                }
            }

            Authentication principal = (oldEntity != null)
                    ? (Authentication) oldEntity.getPrincipal()
                    : (oldTokenEntity != null)
                    ? (Authentication) oldTokenEntity.getPrincipal()
                    : authorization.getAttribute(Principal.class.getName());

            OAuth2AuthorizationRequest authRequest = (oldEntity != null)
                    ? oldEntity.getAuthorizationRequest()
                    : (oldTokenEntity != null)
                    ? oldTokenEntity.getAuthorizationRequest()
                    : authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

            Set<String> scopes = (oldEntity != null)
                    ? oldEntity.getScopes()
                    : (oldTokenEntity != null)
                    ? oldTokenEntity.getScopes()
                    : authorization.getAuthorizedScopes();

            // ✅ AccessToken 자체의 scope (UserInfo에서 보는 scope는 이거다!)
            Set<String> accessTokenScopes = accessToken.getToken().getScopes();

            TokenEntity.TokenEntityBuilder builder = TokenEntity.builder()
                    .authorizationId(authorization.getId())
                    .registeredClientId(authorization.getRegisteredClientId())
                    .principalName(authorization.getPrincipalName())
                    .principal(principal)
                    .authorizationRequest(authRequest)
                    .scopes(scopes)
                    .accessTokenScopes(accessTokenScopes)
                    .accessTokenValue(accessToken.getToken().getTokenValue())
                    .accessTokenIssuedAt(accessToken.getToken().getIssuedAt())
                    .accessTokenExpiresAt(accessToken.getToken().getExpiresAt());

            if (refreshToken != null) {
                builder.refreshTokenValue(refreshToken.getToken().getTokenValue())
                        .refreshTokenIssuedAt(refreshToken.getToken().getIssuedAt())
                        .refreshTokenExpiresAt(refreshToken.getToken().getExpiresAt());
            }

            OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
            if (idToken != null) {
                builder.idTokenValue(idToken.getToken().getTokenValue())
                        .idTokenIssuedAt(idToken.getToken().getIssuedAt())
                        .idTokenExpiresAt(idToken.getToken().getExpiresAt())
                        .idTokenClaims(idToken.getClaims());
            }

            TokenEntity tokenEntity = builder.build();

            // 🔴 기존 code 인덱스(code → id) 삭제
            if (oldEntity != null && oldEntity.getCode() != null) {
                redisTemplate.delete(AUTHORIZATION_CODE_PREFIX + oldEntity.getCode());
            }

            // 🔴 기존 access token 인덱스 삭제 (refresh grant인 경우 이전 토큰 무효화)
            if (oldTokenEntity != null && oldTokenEntity.getAccessTokenValue() != null) {
                redisTemplate.delete(AUTHORIZATION_ACCESS_TOKEN_PREFIX + oldTokenEntity.getAccessTokenValue());
                log.debug("🗑️ Deleted old access token index: {}", oldTokenEntity.getAccessTokenValue());
            }

            // 🔴 기존 refresh token 인덱스 삭제 (새 refresh token이 발급되는 경우)
            if (oldTokenEntity != null && oldTokenEntity.getRefreshTokenValue() != null 
                    && tokenEntity.getRefreshTokenValue() != null
                    && !oldTokenEntity.getRefreshTokenValue().equals(tokenEntity.getRefreshTokenValue())) {
                redisTemplate.delete(AUTHORIZATION_REFRESH_TOKEN_PREFIX + oldTokenEntity.getRefreshTokenValue());
                log.debug("🗑️ Deleted old refresh token index: {}", oldTokenEntity.getRefreshTokenValue());
            }

            // ✅ 메인 authorization 객체 TTL 설정: refreshToken이 있으면 refreshToken 만료 시간에 맞춤
            // refreshToken이 없으면 기본 TTL 사용 (accessToken 만료 시간은 너무 짧음)
            Duration mainTtl;
            if (tokenEntity.getRefreshTokenValue() != null && tokenEntity.getRefreshTokenExpiresAt() != null) {
                // refreshToken이 있으면 refreshToken 만료 시간에 맞춤
                long refreshTtlSeconds = calcTtlSeconds(tokenEntity.getRefreshTokenExpiresAt());
                mainTtl = Duration.ofSeconds(refreshTtlSeconds);
            } else {
                // refreshToken이 없으면 기본 TTL 사용 (일반적으로 refreshToken은 항상 발급됨)
                mainTtl = TTL;
            }

            // id → tokenEntity 로 덮어쓰기
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_PREFIX + authorization.getId(),
                    tokenEntity,
                    mainTtl
            );

            // accessTokenValue → id 인덱스
            long accessTtlSeconds = calcTtlSeconds(tokenEntity.getAccessTokenExpiresAt());
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_ACCESS_TOKEN_PREFIX + tokenEntity.getAccessTokenValue(),
                    authorization.getId(),
                    Duration.ofSeconds(accessTtlSeconds)
            );

            // refreshTokenValue → id 인덱스
            if (tokenEntity.getRefreshTokenValue() != null && tokenEntity.getRefreshTokenExpiresAt() != null) {
                long refreshTtlSeconds = calcTtlSeconds(tokenEntity.getRefreshTokenExpiresAt());
                redisTemplate.opsForValue().set(
                        AUTHORIZATION_REFRESH_TOKEN_PREFIX + tokenEntity.getRefreshTokenValue(),
                        authorization.getId(),
                        Duration.ofSeconds(refreshTtlSeconds)
                );
            }

            log.debug("✅ [TOKEN-STAGE] Saved TokenEntity (id={}, hasRefreshToken={})",
                    authorization.getId(),
                    tokenEntity.getRefreshTokenValue() != null);
            return;
        }

        log.debug("⚠️ save(OAuth2Authorization) called with unsupported state: id={}", authorization.getId());
    }

    private long calcTtlSeconds(Instant expiresAt) {
        if (expiresAt == null) return TTL.getSeconds();
        long diff = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
        return Math.max(diff, 1);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        String id = authorization.getId();
        String key = AUTHORIZATION_PREFIX + id;
        Object obj = redisTemplate.opsForValue().get(key);
        if (obj == null) {
            return;
        }

        // code 단계일 수도 있고, token 단계일 수도 있음
        if (obj instanceof AuthCodeEntity authCodeEntity) {
            if (authCodeEntity.getCode() != null) {
                redisTemplate.delete(AUTHORIZATION_CODE_PREFIX + authCodeEntity.getCode());
            }
        } else if (obj instanceof TokenEntity tokenEntity) {
            if (tokenEntity.getAccessTokenValue() != null) {
                redisTemplate.delete(AUTHORIZATION_ACCESS_TOKEN_PREFIX + tokenEntity.getAccessTokenValue());
            }
            if (tokenEntity.getRefreshTokenValue() != null) {
                redisTemplate.delete(AUTHORIZATION_REFRESH_TOKEN_PREFIX + tokenEntity.getRefreshTokenValue());
            }
        }

        redisTemplate.delete(key);

        log.debug("🗑️ remove() called: id={}", id);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Object obj = redisTemplate.opsForValue().get(AUTHORIZATION_PREFIX + id);
        if (obj == null) {
            return null;
        }

        if (obj instanceof AuthCodeEntity authCodeEntity) {
            return convertToAuthorizationFromCode(authCodeEntity);
        }

        if (obj instanceof TokenEntity tokenEntity) {
            return convertToAuthorizationFromToken(tokenEntity);
        }

        // 혹시 예전 형식으로 들어간 경우 방어적으로 처리
        try {
            AuthCodeEntity authCodeEntity = objectMapper.convertValue(obj, AuthCodeEntity.class);
            return convertToAuthorizationFromCode(authCodeEntity);
        } catch (Exception e) {
            try {
                TokenEntity tokenEntity = objectMapper.convertValue(obj, TokenEntity.class);
                return convertToAuthorizationFromToken(tokenEntity);
            } catch (Exception ex) {
                log.error("❌ findById: cannot convert stored object to AuthCodeEntity/TokenEntity: {}", ex.getMessage());
                return null;
            }
        }
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (token == null) return null;

        // 1) 토큰 타입 없으면 AccessToken부터 시도
        if (tokenType == null || OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            String authId = (String) redisTemplate.opsForValue()
                    .get(AUTHORIZATION_ACCESS_TOKEN_PREFIX + token);
            if (authId != null) {
                return findById(authId);
            }
            // tokenType == null 인 경우, code/refresh 도 추가로 확인
            if (tokenType == null) {
                OAuth2Authorization byCode = findByToken(token, AUTHORIZATION_CODE_TOKEN_TYPE);
                if (byCode != null) return byCode;

                OAuth2Authorization byRefresh = findByToken(token, new OAuth2TokenType(OAuth2TokenType.REFRESH_TOKEN.getValue()));
                if (byRefresh != null) return byRefresh;
            }
        }

        // 2) Authorization Code
        if (AUTHORIZATION_CODE_TOKEN_TYPE.equals(tokenType)) {
            String authId = (String) redisTemplate.opsForValue()
                    .get(AUTHORIZATION_CODE_PREFIX + token);
            if (authId != null) {
                return findById(authId);
            }
        }

        // 3) RefreshToken
        if (tokenType != null && OAuth2TokenType.REFRESH_TOKEN.getValue().equals(tokenType.getValue())) {
            String authId = (String) redisTemplate.opsForValue()
                    .get(AUTHORIZATION_REFRESH_TOKEN_PREFIX + token);
            if (authId != null) {
                return findById(authId);
            }
        }

        return null;
    }

    // ==========================================
    // Entity → OAuth2Authorization 변환 메서드들
    // ==========================================

    private OAuth2Authorization convertToAuthorizationFromCode(AuthCodeEntity entity) {
        RegisteredClient registeredClient =
                registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            log.warn("⚠️ RegisteredClient not found for id={}", entity.getRegisteredClientId());
            return null;
        }

        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(
                entity.getCode(),
                entity.getIssuedAt(),
                entity.getExpiresAt()
        );

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getAuthorizationId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), entity.getPrincipal())
                .attribute(OAuth2AuthorizationRequest.class.getName(), entity.getAuthorizationRequest())
                .authorizedScopes(entity.getScopes())
                .token(code);

        return builder.build();
    }

    private OAuth2Authorization convertToAuthorizationFromToken(TokenEntity entity) {
        RegisteredClient registeredClient =
                registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            log.warn("⚠️ RegisteredClient not found for id={}", entity.getRegisteredClientId());
            return null;
        }

        // ✅ accessTokenScopes가 중요
        Set<String> accessTokenScopes = entity.getAccessTokenScopes();
        if (accessTokenScopes == null || accessTokenScopes.isEmpty()) {
            // fallback: 전체 scopes라도 넣어줌 (openid 포함되어야 userinfo 가능)
            accessTokenScopes = entity.getScopes();
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                entity.getAccessTokenValue(),
                entity.getAccessTokenIssuedAt(),
                entity.getAccessTokenExpiresAt(),
                accessTokenScopes
        );

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getAuthorizationId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), entity.getPrincipal())
                .attribute(OAuth2AuthorizationRequest.class.getName(), entity.getAuthorizationRequest())
                .authorizedScopes(entity.getScopes())
                .token(accessToken);

        // RefreshToken 있으면 추가
        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt()
            );
            builder.refreshToken(refreshToken);
        }

        // ===== ID Token (OIDC 핵심 부분) =====
        if (entity.getIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.getIdTokenValue(),
                    entity.getIdTokenIssuedAt(),
                    entity.getIdTokenExpiresAt(),
                    entity.getIdTokenClaims()
            );

            builder.token(idToken, metadata -> {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, entity.getIdTokenClaims());
            });
        }


        return builder.build();
    }
}
