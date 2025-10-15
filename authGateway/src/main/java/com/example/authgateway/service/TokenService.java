package com.example.authgateway.service;

import com.example.authgateway.dto.TokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    /**
     * OAuth2 Authorization Server에서 토큰 교환
     */
    public TokenResponse exchangeToken(String authorizationCode, String state) {
        try {
            String tokenUrl = "http://localhost:9090/oauth2/token";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth("bff-client", "bff-secret");

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "authorization_code");
            body.add("code", authorizationCode);
            body.add("redirect_uri", "http://localhost:9091/api/auth/callback");
            body.add("client_id", "bff-client");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            
            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(tokenUrl, request, TokenResponse.class);
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                log.info("✅ 토큰 교환 성공: {}", response.getBody().getAccessToken().substring(0, 20) + "...");
                return response.getBody();
            }
        } catch (Exception e) {
            log.error("❌ 토큰 교환 실패: {}", e.getMessage());
        }
        return null;
    }

    /**
     * 세션 ID로 토큰 저장
     */
    public void saveToken(String sessionId, TokenResponse tokenResponse) {
        try {
            // Access Token을 30분간 저장
            redisTemplate.opsForValue().set(
                "access_token:" + sessionId, 
                tokenResponse.getAccessToken(), 
                Duration.ofMinutes(30)
            );
            
            // Refresh Token을 7일간 저장
            if (tokenResponse.getRefreshToken() != null) {
                redisTemplate.opsForValue().set(
                    "refresh_token:" + sessionId, 
                    tokenResponse.getRefreshToken(), 
                    Duration.ofDays(7)
                );
            }
            
            log.info("✅ 토큰 저장 완료: sessionId={}", sessionId);
        } catch (Exception e) {
            log.error("❌ 토큰 저장 실패: {}", e.getMessage());
        }
    }

    /**
     * 세션 ID로 Access Token 조회
     */
    public String getAccessToken(String sessionId) {
        try {
            return (String) redisTemplate.opsForValue().get("access_token:" + sessionId);
        } catch (Exception e) {
            log.error("❌ Access Token 조회 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 세션 ID로 Refresh Token 조회
     */
    public String getRefreshToken(String sessionId) {
        try {
            return (String) redisTemplate.opsForValue().get("refresh_token:" + sessionId);
        } catch (Exception e) {
            log.error("❌ Refresh Token 조회 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 토큰 갱신
     */
    public TokenResponse refreshToken(String refreshToken) {
        try {
            String tokenUrl = "http://localhost:9090/oauth2/token";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth("bff-client", "bff-secret");

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "refresh_token");
            body.add("refresh_token", refreshToken);
            body.add("client_id", "bff-client");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            
            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(tokenUrl, request, TokenResponse.class);
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                log.info("✅ 토큰 갱신 성공");
                return response.getBody();
            }
        } catch (Exception e) {
            log.error("❌ 토큰 갱신 실패: {}", e.getMessage());
        }
        return null;
    }

    /**
     * 세션 삭제
     */
    public void deleteSession(String sessionId) {
        try {
            redisTemplate.delete("access_token:" + sessionId);
            redisTemplate.delete("refresh_token:" + sessionId);
            log.info("✅ 세션 삭제 완료: sessionId={}", sessionId);
        } catch (Exception e) {
            log.error("❌ 세션 삭제 실패: {}", e.getMessage());
        }
    }

    /**
     * 사용자 정보 조회
     */
    public Map<String, Object> getUserInfo(String accessToken) {
        try {
            String userInfoUrl = "http://localhost:9090/userinfo";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userInfoUrl, 
                HttpMethod.GET, 
                request, 
                Map.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                log.info("✅ 사용자 정보 조회 성공");
                return response.getBody();
            }
        } catch (Exception e) {
            log.error("❌ 사용자 정보 조회 실패: {}", e.getMessage());
        }
        return null;
    }

}
