package com.example.authserver.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.Serial;
import java.io.Serializable;
import java.util.*;

@Getter
@NoArgsConstructor
public class CustomUserDetails implements UserDetails, OAuth2User, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private UUID id;
    private String loginId;
    private String username;
    private String profileImg;
    private String email;
    private String phone;
    private String password;
    private Role role;
    private String provider;

    private Map<String, Object> attributes = Map.of(); // OAuth2User attributes

    private List<SimpleGrantedAuthority> authorities = new ArrayList<>();

    // DB 기반 생성자
    public CustomUserDetails(UserInfo user) {
        this.id = user.getId();
        this.loginId = user.getLoginId();
        this.profileImg = user.getProfileImg();
        this.username = user.getName();
        this.email = user.getEmail();
        this.phone = user.getPhone();
        this.password = user.getPassword();
        this.role = user.getRole();
        this.provider = user.getProvider();

        this.authorities = List.of(new SimpleGrantedAuthority(role.name()));
    }

    // OAuth2User용 생성자
    public CustomUserDetails(UserInfo user, Map<String, Object> attributes) {
        this(user);
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return loginId != null ? loginId : id.toString();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
