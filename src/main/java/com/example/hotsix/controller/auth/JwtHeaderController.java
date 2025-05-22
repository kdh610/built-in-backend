
package com.example.hotsix.controller.auth;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

import static com.example.hotsix.enums.Process.*;

@RestController
@Slf4j
public class JwtHeaderController {

    @GetMapping("/convert")
    public ResponseEntity<?> convertJwtHeader(HttpServletRequest request, HttpServletResponse response, @CookieValue(value = "access", required = false) Cookie accessCookie) throws IOException {
        log.info("/convert 컨트롤러");
        String access = accessCookie.getValue();
        System.out.println("coockie = "+access);

        if (access != null) {
            // 액세스 토큰을 로컬 스토리지에 저장하기 위해 헤더에 포함
            //리프레시 토큰 쿠키 값 0
            Cookie newCookie = new Cookie("access",null);
            newCookie.setMaxAge(0);
            newCookie.setPath("/");
            response.addCookie(newCookie);
            response.setHeader("Authorization", "Bearer " + access);

            return new ResponseEntity<>(NORMAL_RESPONSE.getHttpStatus());
        } else {

            return new ResponseEntity<>(INVALID_TOKEN.getHttpStatus());
        }


    }

    @Value("${client.host}")
    private String clinetHost;


}
