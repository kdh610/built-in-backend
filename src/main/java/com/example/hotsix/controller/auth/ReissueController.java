
package com.example.hotsix.controller.auth;


import com.example.hotsix.dto.auth.ReissueResponse;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.service.auth.ReissueService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ReissueController {

    private final ReissueService reissueService;

    @PostMapping("/reissue")
    public ReissueResponse reissue(HttpServletRequest request, HttpServletResponse response) {
        log.info("reissue");
        String refresh = getToeknFromCookie(request).orElseThrow(() -> new BuiltInException(Process.INVALID_TOKEN));
        String newAccess = reissueService.reissueAcessToken(refresh);

        response.setHeader("Authorization", "Bearer " + newAccess);
        return ReissueResponse.builder()
                .token(newAccess)
                .build();
    }

    private static Optional<String> getToeknFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")){
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

}