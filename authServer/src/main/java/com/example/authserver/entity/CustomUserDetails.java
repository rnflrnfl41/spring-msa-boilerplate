package com.example.authserver.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Getter
@NoArgsConstructor
public class CustomUserDetails implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private UUID id;
    private String loginId;
    private String username;
    private String email;
    private String phone;
    private String password;
    private Role role;

    // ✅ Jackson 역직렬화용 생성자
    @JsonCreator
    public CustomUserDetails(
            @JsonProperty("id") UUID id,
            @JsonProperty("loginId") String loginId,
            @JsonProperty("username") String username,
            @JsonProperty("email") String email,
            @JsonProperty("phone") String phone,
            @JsonProperty("password") String password,
            @JsonProperty("role") Role role
    ) {
        this.id = id;
        this.loginId = loginId;
        this.username = username;
        this.email = email;
        this.phone = phone;
        this.password = password;
        this.role = role;
    }

    // ✅ 기존 DB 객체로부터 생성자
    public CustomUserDetails(UserInfo user) {
        this.id = user.getId();
        this.loginId = user.getLoginId();
        this.username = user.getName();
        this.email = user.getEmail();
        this.phone = user.getPhone();
        this.password = user.getPassword();
        this.role = user.getRole();
    }

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // ROLE Enum의 name() 사용, ROLE_ prefix 자동 추가
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }
    @Override public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }
    @Override public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }
    @Override public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
