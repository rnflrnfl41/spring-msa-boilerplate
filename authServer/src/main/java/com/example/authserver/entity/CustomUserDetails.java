package com.example.authserver.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Getter
@NoArgsConstructor
public class CustomUserDetails implements UserDetails {

    private UUID id;
    private String loginId;
    private String username;
    private String password;
    private Role role;

    // ✅ Jackson 역직렬화용 생성자
    @JsonCreator
    public CustomUserDetails(
            @JsonProperty("id") UUID id,
            @JsonProperty("loginId") String loginId,
            @JsonProperty("username") String username,
            @JsonProperty("password") String password,
            @JsonProperty("role") Role role
    ) {
        this.id = id;
        this.loginId = loginId;
        this.username = username;
        this.password = password;
        this.role = role;
    }

    // ✅ 기존 DB 객체로부터 생성자
    public CustomUserDetails(UserInfo user) {
        this.id = user.getId();
        this.loginId = user.getLoginId();
        this.username = user.getName();
        this.password = user.getPassword();
        this.role = user.getRole();
    }

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // ROLE Enum의 name() 사용, ROLE_ prefix 자동 추가
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
