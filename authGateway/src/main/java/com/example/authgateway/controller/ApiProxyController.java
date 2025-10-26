package com.example.authgateway.controller;

import com.example.authgateway.dto.TokenResponse;
import com.example.authgateway.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/proxy")
@RequiredArgsConstructor
public class ApiProxyController {

    private final TokenService tokenService;
    private final RestTemplate restTemplate;

    /**
     * API 서버로의 프록시 요청
     * BFF가 API 서버에 요청 + Access Token 포함 → API 서버가 JWT 검증 후 응답
     */
    @GetMapping("/**")
    public ResponseEntity<Object> proxyGet(HttpServletRequest request) {
        return proxyRequest(request, HttpMethod.GET, null);
    }

    @PostMapping("/**")
    public ResponseEntity<Object> proxyPost(HttpServletRequest request, @RequestBody(required = false) Object body) {
        return proxyRequest(request, HttpMethod.POST, body);
    }

    @PutMapping("/**")
    public ResponseEntity<Object> proxyPut(HttpServletRequest request, @RequestBody(required = false) Object body) {
        return proxyRequest(request, HttpMethod.PUT, body);
    }

    @DeleteMapping("/**")
    public ResponseEntity<Object> proxyDelete(HttpServletRequest request) {
        return proxyRequest(request, HttpMethod.DELETE, null);
    }

    private ResponseEntity<Object> proxyRequest(HttpServletRequest request, HttpMethod method, Object body) {
        try {
            // 세션 ID에서 Access Token 조회
            String sessionId = getSessionIdFromCookie(request);
            if (sessionId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "세션 없음"));
            }

            String accessToken = tokenService.getAccessToken(sessionId);
            if (accessToken == null) {
                // Refresh Token으로 토큰 갱신 시도
                String refreshToken = tokenService.getRefreshToken(sessionId);
                if (refreshToken != null) {
                    TokenResponse newTokenResponse = tokenService.refreshToken(refreshToken);
                    if (newTokenResponse != null) {
                        tokenService.saveToken(sessionId, newTokenResponse);
                        accessToken = newTokenResponse.getAccessToken();
                    }
                }
            }

            if (accessToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "토큰 없음"));
            }

            // API 서버 URL 구성
            String apiServerUrl = "http://localhost:8080";
            String requestPath = request.getRequestURI().replace("/api/proxy", "");
            String targetUrl = apiServerUrl + requestPath;

            // 요청 헤더 구성
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            
            // 원본 요청의 헤더들을 복사 (Authorization 제외)
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                if (!"authorization".equalsIgnoreCase(headerName) && 
                    !"cookie".equalsIgnoreCase(headerName)) {
                    headers.set(headerName, request.getHeader(headerName));
                }
            }

            // 쿼리 파라미터 추가
            String queryString = request.getQueryString();
            if (queryString != null) {
                targetUrl += "?" + queryString;
            }

            // 요청 생성
            HttpEntity<Object> httpEntity = new HttpEntity<>(body, headers);

            // API 서버로 요청 전달
            ResponseEntity<Object> response = restTemplate.exchange(
                    targetUrl, 
                    method, 
                    httpEntity, 
                    Object.class
            );

            log.info("✅ API 프록시 성공: {} {}", method, targetUrl);
            return ResponseEntity.status(response.getStatusCode())
                    .headers(response.getHeaders())
                    .body(response.getBody());

        } catch (Exception e) {
            log.error("❌ API 프록시 실패: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "API 프록시 실패: " + e.getMessage()));
        }
    }

    /**
     * 쿠키에서 세션 ID 추출
     */
    private String getSessionIdFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("SESSION_ID".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
