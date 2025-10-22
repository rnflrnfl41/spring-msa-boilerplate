package com.example.authserver.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {

        OAuth2User oauth2User = super.loadUser(userRequest);

        if ("kakao".equals(userRequest.getClientRegistration().getRegistrationId())) {
            return processKakaoUser(oauth2User);
        }

        return oauth2User;
    }

    @SuppressWarnings("unchecked")
    private OAuth2User processKakaoUser(OAuth2User oauth2User) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        // 카카오 정보를 표준화
        Map<String, Object> standardAttributes = new HashMap<>();
        Object idValue = attributes.get("id");
        standardAttributes.put("id", idValue != null ? String.valueOf(idValue) : null);
        standardAttributes.put("sub", idValue != null ? String.valueOf(idValue) : null);

        standardAttributes.put("name", profile.get("nickname"));
        standardAttributes.put("picture", profile.get("profile_image_url"));

        standardAttributes.put("kakao_account", kakaoAccount);

        return new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("OAUTH2_USER")),
                standardAttributes,
                "sub"
        );
    }
}
