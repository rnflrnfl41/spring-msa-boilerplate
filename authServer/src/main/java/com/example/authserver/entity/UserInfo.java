package com.example.authserver.entity;

import lombok.*;

@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfo {

    private String email;
    private String name;
    private String picture;

}
