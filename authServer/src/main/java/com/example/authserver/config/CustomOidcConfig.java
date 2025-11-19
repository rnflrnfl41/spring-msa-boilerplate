package com.example.authserver.config;

import com.example.authserver.entity.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Slf4j
@Configuration
public class CustomOidcConfig {

    /**
     * TODO: 현재 tokenCustomizer로 idToken을 커스텀 하고있는대 /userinfo api를 요청하면 sub,name,email 밖에 내려오지않음
     *  정보를 더 받을수 있도록 커스텀 매핑 필요
     */

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

}
