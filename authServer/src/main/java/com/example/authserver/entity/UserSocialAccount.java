package com.example.authserver.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;

import java.time.Instant;

@Getter
@Setter
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "user_social_account")
public class UserSocialAccount {
    @Id
    @ColumnDefault("uuid()")
    @Column(name = "id", nullable = false, length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "userId", nullable = false)
    private UserInfo user;

    @Column(name = "provider", length = 100)
    private String provider;

    @Column(name = "provider_id", length = 100)
    private String providerId;

    @Column(name = "email", length = 100)
    private String email;

    @Column(name = "connected_at")
    private Instant connectedAt;

}