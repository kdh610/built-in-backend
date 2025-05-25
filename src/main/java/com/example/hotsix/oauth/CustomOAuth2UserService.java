package com.example.hotsix.oauth;

import com.example.hotsix.dto.auth.SignUpRequest;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.model.Member;
import com.example.hotsix.oauth.dto.*;

import com.example.hotsix.repository.member.MemberRepository;
import com.example.hotsix.service.auth.SignUpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;
    private final SignUpService signUpService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //리소스 서버로 부터 받을 유저정보
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("oAuth2User: {}", oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("registrationId: {}", registrationId);

        OAuth2Response oAuth2Response;
        if(registrationId.equals("naver")){
            log.info("naver 로그인");
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }else if(registrationId.equals("google")){
            log.info("google 로그인");
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }else if(registrationId.equals("github")){
            log.info("github 로그인");
            oAuth2Response = new GithubResponse(oAuth2User.getAttributes());
        }else{
            return null;
        }

        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값
        log.info("oAuth2Response: {}", oAuth2Response);
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        String email = oAuth2Response.getEmail();
        Member findMember = memberRepository.findByEmail(email);

        if(findMember == null){
            log.info("신규 가입 이메일");
            MemberDto memberDto = signUpService.signUp(SignUpRequest.builder()
                        .email(email)
                        .nickname(oAuth2Response.getName())
                        .name(oAuth2Response.getName())
                        .role("ROLE_USER")
                        .lgnMtd(oAuth2Response.getProvider())
                        .build());

            return new CustomOAuth2User(UserDTO.builder()
                        .id( Member.fromDto(memberDto).getId())
                        .username(username)
                        .email(email)
                        .name(oAuth2Response.getName())
                        .role("ROLE_USER")
                        .build());
        }
        else{
            if(isEmailSignUp(findMember)){
                log.info("이메일 가입하기로 등록된 이메일");
                return null;
            }
            else{
                log.info("OAuth 가입하기로 등록된 이메일");
                return new CustomOAuth2User(UserDTO.builder()
                            .id(findMember.getId())
                            .username(username)
                            .email(email)
                            .name(oAuth2Response.getName())
                            .role("ROLE_USER")
                            .build());
            }
        }
    }

    private static boolean isEmailSignUp(Member findMember) {
        return findMember.getLgnMtd().equals("built-in");
    }
}
