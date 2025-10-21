package com.example.authserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.HashMap;
import java.util.Map;

@Controller
public class LoginController {

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
                // Google OIDC 사용자
                OidcUser oidcUser = (OidcUser) principal;
                userInfo.put("sub", oidcUser.getSubject());
                userInfo.put("email", oidcUser.getEmail());
                userInfo.put("name", oidcUser.getFullName());
                userInfo.put("given_name", oidcUser.getGivenName());
                userInfo.put("family_name", oidcUser.getFamilyName());
                userInfo.put("picture", oidcUser.getPicture() != null ? oidcUser.getPicture().toString() : null);
                userInfo.put("email_verified", oidcUser.getEmailVerified());
            } else if (principal instanceof OAuth2User) {
                // 카카오 OAuth2 사용자
                OAuth2User oauth2User = (OAuth2User) principal;
                userInfo.put("sub", oauth2User.getAttribute("sub"));
                userInfo.put("email", oauth2User.getAttribute("email"));
                userInfo.put("name", oauth2User.getAttribute("name"));
                userInfo.put("picture", oauth2User.getAttribute("picture"));
                userInfo.put("email_verified", oauth2User.getAttribute("email_verified"));
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
