package com.example.hotsix.dto.auth;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
public class SignUpRequest {
    private Long id;
    private String email;
    private String name;
    private String nickname;
    private String profileUrl;
    private String phone;
    private String address;
    private String role;
    private String lgnMtd;
    private LocalDateTime regDTTM;

}
