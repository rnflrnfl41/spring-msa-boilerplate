package com.example.webbffserver.config;

//import com.example.webbffserver.security.filter.JwtFromCookieFilter;
import com.example.webbffserver.security.point.JwtAuthEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(AppProperties.class)
public class SecurityConfig {

    private final AppProperties appProperties;
    //private final JwtFromCookieFilter jwtFromCookieFilter;
    private final JwtAuthEntryPoint jwtAuthEntryPoint;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(appProperties.getFrontendUrl()));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // 1시간

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/auth/callback", "/api/auth/status",
                                "/api/auth/user/me", "/api/auth/logout", "/login/oauth2/code/**").permitAll()
                )
                // ✅ JWT 기반 인증 (Auth Server의 JWK URI 이용)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwkSetUri(appProperties.getAuthServerJwkSetUrl())
                        )
                        .authenticationEntryPoint(jwtAuthEntryPoint)
                )

                // ✅ 쿠키 → Authorization 헤더 변환 필터 추가
                //.addFilterBefore(jwtFromCookieFilter, BearerTokenAuthenticationFilter.class)
                .build();
    }


}
