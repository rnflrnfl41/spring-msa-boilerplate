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
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.time.Duration;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    //TODO: 현재 token refresh가 안됌 이유는 openid를 참조하기 때문 scope를 폼로그인일때는 openId를 주면 안되는대 클라이언트가 고정되어있어서 그럼 수정 필요(test.http로 테스트 해보면 됌)

    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository clientRepository;
    private final ObjectMapper objectMapper;

    private static final String AUTHORIZATION_PREFIX = "oauth2:authorization:";      // 메인
    private static final String AUTHORIZATION_CODE_PREFIX = "oauth2:authorization:code:"; // code → id 인덱스
    private static final Duration TTL = Duration.ofMinutes(10);

    @Override
    public void save(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);

        // ① 코드 단계
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

        // ② 토큰 단계
        if (accessToken != null) {
            // 기존 code 단계 데이터 가져오기
            Object oldObj = redisTemplate.opsForValue().get(AUTHORIZATION_PREFIX + authorization.getId());
            AuthCodeEntity oldEntity = null;
            if (oldObj instanceof AuthCodeEntity e) {
                oldEntity = e;
            } else if (oldObj != null) {
                try {
                    oldEntity = objectMapper.convertValue(oldObj, AuthCodeEntity.class);
                } catch (Exception ex) {
                    log.warn("⚠️ cannot convert prev auth to AuthCodeEntity: {}", ex.getMessage());
                }
            }

            Authentication principal = (oldEntity != null)
                    ? (Authentication) oldEntity.getPrincipal()
                    : authorization.getAttribute(Principal.class.getName());

            OAuth2AuthorizationRequest authRequest = (oldEntity != null)
                    ? oldEntity.getAuthorizationRequest()
                    : authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

            Set<String> scopes = (oldEntity != null)
                    ? oldEntity.getScopes()
                    : authorization.getAuthorizedScopes();

            TokenEntity.TokenEntityBuilder builder = TokenEntity.builder()
                    .authorizationId(authorization.getId())
                    .registeredClientId(authorization.getRegisteredClientId())
                    .principalName(authorization.getPrincipalName())
                    .principal(principal)
                    .authorizationRequest(authRequest)
                    .scopes(scopes)
                    .accessTokenValue(accessToken.getToken().getTokenValue())
                    .accessTokenIssuedAt(accessToken.getToken().getIssuedAt())
                    .accessTokenExpiresAt(accessToken.getToken().getExpiresAt());

            if (refreshToken != null) {
                builder.refreshTokenValue(refreshToken.getToken().getTokenValue())
                        .refreshTokenIssuedAt(refreshToken.getToken().getIssuedAt())
                        .refreshTokenExpiresAt(refreshToken.getToken().getExpiresAt());
            }

            TokenEntity tokenEntity = builder.build();

            // 🔴 여기서 기존 code 인덱스는 "code 값" 으로 지워야 함
            if (oldEntity != null && oldEntity.getCode() != null) {
                redisTemplate.delete(AUTHORIZATION_CODE_PREFIX + oldEntity.getCode());
            }

            // id → tokenEntity 로 덮어쓰기
            redisTemplate.opsForValue().set(
                    AUTHORIZATION_PREFIX + authorization.getId(),
                    tokenEntity,
                    TTL
            );

            log.debug("✅ [TOKEN-STAGE] Saved TokenEntity (id={}, hasRefreshToken={})",
                    authorization.getId(),
                    tokenEntity.getRefreshTokenValue() != null);
            return;
        }

        log.debug("⚠️ save(OAuth2Authorization) called with unsupported state: id={}", authorization.getId());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        // 메인 삭제
        redisTemplate.delete(AUTHORIZATION_PREFIX + authorization.getId());

        // code 인덱스도 삭제
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);

        if (codeToken != null) {
            String codeValue = codeToken.getToken().getTokenValue();
            redisTemplate.delete(AUTHORIZATION_CODE_PREFIX + codeValue);
            log.debug("🗑️ Removed AuthCodeEntity (id={}, code={})", authorization.getId(), codeValue);
        } else {
            // 토큰 단계에서 호출된 경우: 인덱스 전체 스캔해서 이 id인 것만 지움
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

        // 🔹 토큰 단계인지 코드 단계인지 구분
        if (obj instanceof TokenEntity tokenEntity) {
            return toAuthorizationFromToken(tokenEntity);
        }

        AuthCodeEntity entity = (obj instanceof AuthCodeEntity e)
                ? e
                : objectMapper.convertValue(obj, AuthCodeEntity.class);

        return toAuthorizationFromCode(entity);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {

        // 1) 코드로 찾는 경우
        if (tokenType != null && OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            String authorizationId = (String) redisTemplate.opsForValue().get(AUTHORIZATION_CODE_PREFIX + token);
            if (authorizationId == null) return null;

            Object obj = redisTemplate.opsForValue().get(AUTHORIZATION_PREFIX + authorizationId);
            if (obj == null) return null;

            if (obj instanceof AuthCodeEntity e) {
                return toAuthorizationFromCode(e);
            } else if (obj instanceof TokenEntity te) {
                return toAuthorizationFromToken(te);
            } else {
                // fallback
                return toAuthorizationFromCode(objectMapper.convertValue(obj, AuthCodeEntity.class));
            }
        }

        // 2) access token / refresh token 으로 찾는 경우
        if (tokenType != null &&
                (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)
                        || OAuth2TokenType.REFRESH_TOKEN.equals(tokenType))) {

            Set<String> keys = redisTemplate.keys(AUTHORIZATION_PREFIX + "*");
            if (keys != null) {
                for (String key : keys) {
                    Object obj = redisTemplate.opsForValue().get(key);
                    if (obj instanceof TokenEntity te) {
                        if (token.equals(te.getAccessTokenValue())
                                || token.equals(te.getRefreshTokenValue())) {
                            return toAuthorizationFromToken(te);
                        }
                    }
                }
            }
        }

        return null;
    }

    // ================== 변환 메서드 ==================

    private OAuth2Authorization toAuthorizationFromCode(AuthCodeEntity e) {
        RegisteredClient client = clientRepository.findById(e.getRegisteredClientId());
        if (client == null) return null;

        OAuth2AuthorizationCode authCode = new OAuth2AuthorizationCode(
                e.getCode(), e.getIssuedAt(), e.getExpiresAt()
        );

        return OAuth2Authorization.withRegisteredClient(client)
                .id(e.getAuthorizationId())
                .principalName(e.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(e.getScopes())
                .attribute(OAuth2AuthorizationRequest.class.getName(), e.getAuthorizationRequest())
                .attribute(Principal.class.getName(), e.getPrincipal())
                .token(authCode)
                .build();
    }

    private OAuth2Authorization toAuthorizationFromToken(TokenEntity e) {
        RegisteredClient client = clientRepository.findById(e.getRegisteredClientId());
        if (client == null) return null;

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(e.getAuthorizationId())
                .principalName(e.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // 최초 grant는 code였으므로
                .authorizedScopes(e.getScopes())
                .attribute(OAuth2AuthorizationRequest.class.getName(), e.getAuthorizationRequest())
                .attribute(Principal.class.getName(), e.getPrincipal());

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                e.getAccessTokenValue(),
                e.getAccessTokenIssuedAt(),
                e.getAccessTokenExpiresAt()
        );
        builder.token(accessToken);

        if (e.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    e.getRefreshTokenValue(),
                    e.getRefreshTokenIssuedAt(),
                    e.getRefreshTokenExpiresAt()
            );
            builder.token(refreshToken);
        }

        return builder.build();
    }
}

