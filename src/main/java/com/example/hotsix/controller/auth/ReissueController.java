
package com.example.hotsix.controller.auth;


import com.example.hotsix.dto.auth.ReissueResponse;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.jwt.TokenType;
import com.example.hotsix.service.auth.ReissueService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ReissueController {

    private final ReissueService reissueService;
    private final JWTUtil jwtUtil;

    @PostMapping("/reissue")
    public ReissueResponse reissue(HttpServletRequest request, HttpServletResponse response) {
        log.info("reissue");
        String refresh = jwtUtil.getTokenFromCookie(request, TokenType.REFRESH).orElseThrow(() -> new BuiltInException(Process.INVALID_TOKEN));
        String newAccess = reissueService.reissueAcessToken(refresh);

        response.setHeader("Authorization", "Bearer " + newAccess);
        return ReissueResponse.builder()
                .token(newAccess)
                .build();
    }


}