package com.example.hotsix.service.auth;

import com.example.hotsix.jwt.JWTUtil;
import com.example.hotsix.model.Member;
import com.example.hotsix.repository.member.MemberRepository;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

@Service
@Slf4j
@RequiredArgsConstructor
public class MailLinkService {

    private final MemberRepository memberRepository;
    private final JWTUtil jwtUtil;
    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine templateEngine;

    @Value("${server.origin}")
    private String hostUrl;

    public String createLink(String type, String email){
        String code = jwtUtil.createEmailJwt(email);
        return  hostUrl+"/hot6man/"+ type + "?code="+code;
    }

    public String choiceLoginOrRegister(String email){
        Member exist = memberRepository.findByEmail(email.replace("\"", ""));
        if(exist != null){
            return "email-login";
        }
        return "register";
    }

    public void sendMail(String email, String type, String link){
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        String title = "Built-In 로그인";
        if(type.equals("register")){
            title = "Built-In 회원가입";
        }
        try {
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, false, "UTF-8");
            mimeMessageHelper.setTo(email); // 메일 수신자
            mimeMessageHelper.setSubject(title); // 메일 제목
            mimeMessageHelper.setText(setContext(type,link), true); // 메일 본문 내용, HTML 여부
            javaMailSender.send(mimeMessage);

            log.info("Succeeded to send Email");
        } catch (Exception e) {
            log.info("Failed to send Email");
            throw new RuntimeException(e);
        }
    }

    //thymeleaf를 통한 html 적용
    public String setContext(String type, String link) {
        Context context = new Context();
        context.setVariable("link", link);
        return templateEngine.process(type, context);
    }


}
