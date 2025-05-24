package com.example.hotsix.dto.auth;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ReissueResponse {
    private String token;
}
