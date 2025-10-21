package com.example.authserver.service;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        // 카카오 OAuth2 사용자 정보 처리
        if ("kakao".equals(userRequest.getClientRegistration().getRegistrationId())) {
            return processKakaoUser(oauth2User);
        }
        
        return oauth2User;
    }

    //수정 필요함 토큰까진 받는대 여기 부분 문제
    //그리고 카카오에서 받아오는거에 비해 많음 수정 필요함
    @SuppressWarnings("unchecked")
    private OAuth2User processKakaoUser(OAuth2User oauth2User) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");
        
        // 카카오 사용자 정보를 표준 OAuth2 형식으로 변환
        Map<String, Object> standardAttributes = new HashMap<>();
        standardAttributes.put("id", attributes.get("id"));
        standardAttributes.put("sub", attributes.get("id").toString());
        standardAttributes.put("name", profile.get("nickname"));
        standardAttributes.put("email", kakaoAccount.get("email"));
        standardAttributes.put("picture", profile.get("profile_image_url"));
        standardAttributes.put("email_verified", kakaoAccount.get("email_verified"));

        // 원본 카카오 속성도 유지
        standardAttributes.put("kakao_account", kakaoAccount);
        standardAttributes.put("properties", attributes.get("properties"));

        return new CustomOAuth2User(standardAttributes, oauth2User.getAuthorities());
    }
    
    // 커스텀 OAuth2User 구현
    private static class CustomOAuth2User implements OAuth2User {
        private final Map<String, Object> attributes;
        private final java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> authorities;
        
        public CustomOAuth2User(Map<String, Object> attributes, 
                               java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> authorities) {
            this.attributes = attributes;
            this.authorities = authorities;
        }
        
        @Override
        public Map<String, Object> getAttributes() {
            return attributes;
        }
        
        @Override
        public java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> getAuthorities() {
            return authorities;
        }
        
        @Override
        public String getName() {
            return (String) attributes.get("name");
        }
    }
}
