package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Order(1)
public class AuthorizationServerConfig {

    // ========================================
    // OAuth2 Authorization Server 필터 체인
    // ========================================
    // 이 필터 체인이 실제 OAuth2 Authorization Server의 역할을 담당
    // Spring이 자동으로 다음 엔드포인트들을 제공:
    // - GET /oauth2/authorize (인증 요청)
    // - POST /oauth2/token (토큰 발급) ← 여기서 Spring이 자동으로 JWT 토큰 발급!
    // - POST /oauth2/revoke (토큰 폐기)
    // - GET /.well-known/jwks.json (공개키 조회)
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        //TODO: OIDC 유저 세팅 해서 유저 정보를 받는 로직 만들어야함
        //TODO: oidc 사용해서 openid를 주면 refreshToken할때 주의 뭔가 있어서 에러 날가능성 있음

        // scope로 openid를 받기 위해선 oidc 설정을 따로 해줘야함
        // oidc란 기본 oauth2는 접근 권한을 주지만 사용자 인증은 하지않는대
        // oidc는 ID Token으로 사용자 정보를 가져와서 인증 가능
        //OAuth2: “이 사용자가 API 자원에 접근할 수 있는 권한이 있는가?” → 인가(Authorization) 중심
        //OIDC: “이 사용자가 누구인가?” → 인증(Authentication) 중심
       /* http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());*/

        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/token", "/oauth2/revoke"))
                .formLogin(Customizer.withDefaults());

        return http.build();
    }
}
