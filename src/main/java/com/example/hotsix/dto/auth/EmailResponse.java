package com.example.hotsix.dto.auth;

import lombok.*;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class EmailResponse {
    private String link;
    private String type;

}
