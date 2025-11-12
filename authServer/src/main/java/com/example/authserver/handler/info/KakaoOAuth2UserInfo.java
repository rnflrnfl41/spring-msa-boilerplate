package com.example.authserver.handler.info;

import java.util.Map;


@SuppressWarnings("unchecked")
public class KakaoOAuth2UserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attributes;

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getId() {
        Object id = attributes.get("id");
        if (id == null) id = attributes.get("sub");
        return (id != null) ? String.valueOf(id) : null;
    }

    @Override
    public String getEmail() {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        if (account == null) return null;
        return (String) account.get("email");
    }

    @Override
    public String getName() {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        if (account == null) return (String) attributes.get("name");
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");
        if (profile == null) return (String) attributes.get("name");
        return (String) profile.getOrDefault("nickname", attributes.get("name"));
    }

}