package com.example.authserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Controller
public class LoginController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    /**
     * 사용자 정보 엔드포인트 (OAuth2 Resource Server용)
     * BFF에서 사용자 정보를 조회할 때 사용
     */
    @GetMapping("/userinfo")
    @ResponseBody
    public Map<String, Object> userinfo() {
        Map<String, Object> userInfo = new HashMap<>();
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            
            if (principal instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) principal;
                userInfo.put("sub", oidcUser.getSubject());
                userInfo.put("email", oidcUser.getEmail());
                userInfo.put("name", oidcUser.getFullName());
                userInfo.put("given_name", oidcUser.getGivenName());
                userInfo.put("family_name", oidcUser.getFamilyName());
                userInfo.put("picture", oidcUser.getPicture() != null ? oidcUser.getPicture().toString() : null);
                userInfo.put("email_verified", oidcUser.getEmailVerified());
            } else {
                // 일반 사용자 (폼 로그인)
                userInfo.put("sub", authentication.getName());
                userInfo.put("name", authentication.getName());
                userInfo.put("email", authentication.getName() + "@example.com");
            }
            
            userInfo.put("authenticated", true);
        } else {
            userInfo.put("authenticated", false);
        }
        
        return userInfo;
    }
}
