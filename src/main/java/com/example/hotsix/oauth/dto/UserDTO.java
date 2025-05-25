package com.example.hotsix.oauth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Builder
public class UserDTO {

    private Long id;
    private String role;
    private String name;
    private String username;
    private String email;

    @Override
    public String toString() {
        return "UserDTO{" +
                "id=" + id +
                ", role='" + role + '\'' +
                ", name='" + name + '\'' +
                ", username='" + username + '\'' +
                '}';
    }
}
