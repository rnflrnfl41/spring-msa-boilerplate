package com.example.authserver.config;

import com.example.authserver.entity.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Slf4j
@Configuration
public class CustomOidcConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            // 디버그: 어떤 토큰 타입이 들어오는지 확인
            String tokenTypeValue = context.getTokenType().getValue();
            log.debug("🔍 Token Type: {}", tokenTypeValue);
            log.debug("🔍 OidcParameterNames.ID_TOKEN: {}", OidcParameterNames.ID_TOKEN);
            log.debug("🔍 비교 결과: {}", tokenTypeValue.equals(OidcParameterNames.ID_TOKEN));

            // ID Token에만 claims 추가
            if (tokenTypeValue.equals(OidcParameterNames.ID_TOKEN)) {
                log.debug("✅ ID Token 처리 시작");
                Authentication principal = context.getPrincipal();
                CustomUserDetails user = (CustomUserDetails) principal.getPrincipal();

                context.getClaims().claim("sub", user.getId().toString());
                context.getClaims().claim("loginId", user.getLoginId() == null ? "" : user.getLoginId());
                context.getClaims().claim("name", user.getUsername()== null ? "" : user.getUsername());
                context.getClaims().claim("email", user.getEmail() == null ? "" : user.getEmail());
                context.getClaims().claim("phone", user.getPhone() == null ? "" : user.getPhone());
                context.getClaims().claim("role", user.getRole());
                log.debug("✅ ID Token claims 추가 완료");
            } else {
                log.debug("⏭️ ID Token이 아니므로 claims 추가하지 않음: {}", tokenTypeValue);
            }
        };
    }

    /**
     * /userinfo 엔드포인트 커스터마이징
     * principal에서 추가 정보를 가져와서 userinfo 응답에 포함
     */
    @Bean
    public Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper() {
        return (context) -> {
            OAuth2Authorization authorization = context.getAuthorization();

            // OAuth2Authorization에서 Principal attribute 가져오기
            if (authorization != null) {
                Principal principal = authorization.getAttribute(Principal.class.getName());
                
                // Principal이 Authentication인 경우
                if (principal instanceof Authentication auth) {
                    Object authPrincipal = auth.getPrincipal();
                    
                    if (authPrincipal instanceof CustomUserDetails user) {
                        Map<String, Object> claims = new HashMap<>();

                        // 표준 OIDC claims
                        claims.put("sub", user.getId().toString());
                        claims.put("name", user.getUsername() != null ? user.getUsername() : "");
                        claims.put("email", user.getEmail() != null ? user.getEmail() : "");

                        // 추가 커스텀 claims
                        claims.put("loginId", user.getLoginId() != null ? user.getLoginId() : "");
                        claims.put("phone", user.getPhone() != null ? user.getPhone() : "");
                        claims.put("role", user.getRole() != null ? user.getRole().name() : "");
                        claims.put("provider", user.getProvider() != null ? user.getProvider() : "일반 로그인");
                        claims.put("profileImg", user.getProfileImg() != null ? user.getProfileImg() : "");

                        OAuth2Authorization.Token<?> accessToken = authorization.getAccessToken();
                        OAuth2Authorization.Token<?> refreshToken = authorization.getRefreshToken();
                        if (accessToken != null) {
                            Date exp = Date.from(Objects.requireNonNull(accessToken.getToken().getExpiresAt()));
                            claims.put("accessExp", exp.getTime());
                        }

                        if(refreshToken != null) {
                            Date exp = Date.from(Objects.requireNonNull(refreshToken.getToken().getExpiresAt()));
                            claims.put("refreshExp", exp.getTime());
                        }

                        log.debug("✅ /userinfo 응답 생성: {}", claims);
                        return new OidcUserInfo(claims);
                    }
                }
            }

            // 기본 동작 (fallback) - OAuth2Authorization에서 ID Token의 claims 사용
            try {
                if (authorization != null) {
                    OAuth2Authorization.Token<OidcIdToken> idTokenToken = 
                        authorization.getToken(OidcIdToken.class);
                    if (idTokenToken != null) {
                        OidcIdToken idToken = idTokenToken.getToken();
                        if (idToken != null) {
                            log.debug("✅ /userinfo fallback - ID Token claims 사용");
                            return new OidcUserInfo(idToken.getClaims());
                        }
                    }
                }
            } catch (Exception e) {
                log.warn("⚠️ ID Token claims를 가져오는 중 오류 발생: {}", e.getMessage());
            }

            // 최종 fallback - 빈 claims로 반환
            log.warn("⚠️ /userinfo - 모든 방법 실패, 빈 claims 반환");
            return new OidcUserInfo(Map.of());
        };
    }

}
