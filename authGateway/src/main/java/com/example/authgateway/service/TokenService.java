package com.example.authgateway.service;

import com.example.authgateway.dto.TokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final PasswordEncoder passwordEncoder;

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
     * 사용자 정보 조회 (JWT 토큰에서 직접 추출)
     */
    public Map<String, Object> getUserInfo(String accessToken) {
        try {
            // 1️⃣ JWT 토큰 파싱
            JWT jwt = JWTParser.parse(accessToken);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            
            // 2️⃣ 토큰 유효성 검증
            if (isTokenExpired(claimsSet)) {
                log.error("❌ JWT 토큰 만료됨");
                return null;
            }
            
            // 3️⃣ 발급자 검증 (Auth Server에서 발급된 토큰인지 확인)
            String issuer = claimsSet.getIssuer();
            if (issuer == null || !issuer.equals("http://localhost:9090")) {
                log.error("❌ 잘못된 토큰 발급자: {}", issuer);
                return null;
            }
            
            // 4️⃣ 사용자 정보 추출
            Map<String, Object> userInfo = new HashMap<>();
            
            // 표준 JWT Claims
            String sub = claimsSet.getSubject();
            String email = claimsSet.getStringClaim("email");
            String name = claimsSet.getStringClaim("name");
            String picture = claimsSet.getStringClaim("picture");
            Boolean emailVerified = claimsSet.getBooleanClaim("email_verified");
            
            // 사용자 정보 설정
            userInfo.put("sub", sub != null ? sub : "unknown");
            userInfo.put("email", email != null ? email : "unknown@example.com");
            userInfo.put("name", name != null ? name : "Unknown User");
            userInfo.put("picture", picture != null ? picture : "https://example.com/default-avatar.jpg");
            userInfo.put("email_verified", emailVerified != null ? emailVerified : false);
            
            // 추가 정보 (발급자, 만료시간 등)
            userInfo.put("issuer", claimsSet.getIssuer());
            userInfo.put("issued_at", claimsSet.getIssueTime());
            userInfo.put("expires_at", claimsSet.getExpirationTime());
            
            log.info("✅ 사용자 정보 조회 성공 (JWT 기반): {} ({})", name, email);
            return userInfo;
            
        } catch (Exception e) {
            log.error("❌ JWT 토큰 파싱 실패: {}", e.getMessage());
            
            // JWT 파싱 실패 시 null 반환 (보안상 fallback 데이터 사용하지 않음)
            return null;
        }
    }
    
    /**
     * JWT 토큰 만료 여부 확인
     */
    private boolean isTokenExpired(JWTClaimsSet claimsSet) {
        try {
            return claimsSet.getExpirationTime().before(new java.util.Date());
        } catch (Exception e) {
            log.error("❌ 토큰 만료 시간 확인 실패: {}", e.getMessage());
            return true; // 확인할 수 없으면 만료된 것으로 처리
        }
    }

}
