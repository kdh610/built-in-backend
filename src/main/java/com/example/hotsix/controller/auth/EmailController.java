package com.example.hotsix.controller.auth;

import com.example.hotsix.dto.auth.EmailResponse;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.model.Member;
import com.example.hotsix.service.auth.LoginService;
import com.example.hotsix.service.auth.RedisTokenService;
import com.example.hotsix.service.auth.MailLinkService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

@RestController
@Slf4j
@RequiredArgsConstructor
public class EmailController {

    private final MailLinkService mailLinkService;
    private final LoginService loginService;
    private final JWTUtil jwtUtil;
    private final RedisTokenService redisTokenService;

    @Value("${client.host}")
    private String clinetHost;

    /**
     * Email 로그인 or 가입시 링크 email로 전송.
     * @param email
     * @return
     */
    @PostMapping("/email-link")
    public EmailResponse emailLink(@RequestBody String email) {
        String type = mailLinkService.choiceLoginOrRegister(email);
        String link = mailLinkService.createLink(type, email);
        mailLinkService.sendMail(email,type,link);

        return EmailResponse.builder()
                .link(link)
                .type(type)
                .build();
    }


    // 메일로 온 링크로 들어오면 token검증하고 유효하면 로그인 처리
    @GetMapping("/email-login")
    public void emailLogin(@RequestParam("code") String code, @CookieValue(value = "refresh", required = false) Cookie refresh, HttpServletResponse response) throws IOException {
        String email = null;
        try{
            if(jwtUtil.validateToken(code)){
                email = jwtUtil.getEmail(code);
            }
        }catch (BuiltInException e){
            log.info(e.getMessage());
            try {
                if(refresh!=null && redisTokenService.isTokenInRedis(jwtUtil.getId(refresh.getValue()).toString())){
                    // 리프레시 토큰 삭제
                    log.info("Redis refresh토큰 삭제");
                    redisTokenService.deleteRefreshToken(jwtUtil.getId(refresh.getValue()).toString());

                    //리프레시 토큰 쿠키 값 0
                    Cookie cookie = new Cookie("refresh",null);
                    cookie.setMaxAge(0);
                    cookie.setPath("/");

                    log.info("로그아웃 완료");
                    response.addCookie(cookie);
                    response.setStatus(HttpServletResponse.SC_OK);
                }

                response.sendRedirect(clinetHost);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }

        log.info("email {}", email);
        if(email != null) {

        Map<String, Cookie> cookies = loginService.login(email);

        response.addCookie(cookies.get("access"));
        response.addCookie(cookies.get("refresh"));
        response.sendRedirect(clinetHost+"/afterlogin");
        }
    }

    //메일로 온 링크로 들어와서 토큰이 유요하면 프로필 작성 페이지로 리다이렉트
    @GetMapping("/register")
    public void register(@RequestParam("code") String code, HttpServletResponse response){
        try{
            if(jwtUtil.validateToken(code)){
                String email = jwtUtil.getEmail(code);
                redirect(response, "/register?email=" + email.replace("\"", ""));
            }
        }catch (BuiltInException e){
            log.info(e.getMessage());
            redirect(response, "");
        }
    }

    private void redirect(HttpServletResponse response, String address){
        try {
            response.sendRedirect(clinetHost + address);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // 프로필 작성 후 가입 버튼 누를시 가입완료
    @PostMapping(value = "/signup", consumes = "application/json;charset=UTF-8")
    public MemberDto signup(@RequestBody MemberDto member){
        log.info("member {}",member.toString());
        MemberDto memberDto = loginService.signUp(Member.fromDto(member));
        return memberDto;
    }




}
