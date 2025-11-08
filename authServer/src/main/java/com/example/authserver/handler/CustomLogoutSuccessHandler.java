package com.example.authserver.handler;

import com.example.authserver.service.RedisOAuth2AuthorizationService;
import com.example.authserver.service.TokenBlacklistService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    private final RedisOAuth2AuthorizationService redisOAuth2AuthorizationService;
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtDecoder jwtDecoder;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException {
        try {
            String accessToken = extractCookie(request, "ACCESS_TOKEN");
            String refreshToken = extractCookie(request, "REFRESH_TOKEN");

            if (refreshToken != null) {
                OAuth2Authorization authorization =
                        redisOAuth2AuthorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
                if (authorization != null) {
                    redisOAuth2AuthorizationService.remove(authorization);
                    log.info("✅ Redis Authorization 제거 완료");
                }
            }

            if (accessToken != null) {
                blacklistAccessToken(accessToken);
            }

            log.info("✅ 로그아웃 처리 완료");
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (Exception e) {
            log.error("❌ 로그아웃 실패: {}", e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie c : request.getCookies()) {
            if (name.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    private void blacklistAccessToken(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);
            Instant expiresAt = jwt.getExpiresAt();
            if (expiresAt == null) return;
            Duration ttl = Duration.between(Instant.now(), expiresAt);
            if (!ttl.isNegative() && !ttl.isZero()) {
                tokenBlacklistService.blacklist(accessToken, ttl);
            }
        } catch (JwtException e) {
            log.warn("⚠️ access token 디코딩 실패: {}", e.getMessage());
        }
    }
}
