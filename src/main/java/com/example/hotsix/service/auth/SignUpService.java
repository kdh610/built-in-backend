package com.example.hotsix.service.auth;

import com.example.hotsix.dto.auth.SignUpRequest;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.model.Member;
import com.example.hotsix.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SignUpService {

    private final MemberRepository memberRepository;

    @Transactional
    public MemberDto signUpByOauth(SignUpRequest signUpRequest) {
        signUpRequest.setRole("ROLE_USER");
        Member signupMember = Member.createSignupMember(signUpRequest);
        Member member = memberRepository.save(signupMember);
        return member.toDto();
    }

    @Transactional
    public MemberDto signUpByEmail(SignUpRequest signUpRequest) {
        signUpRequest.setRole("ROLE_USER");
        signUpRequest.setLgnMtd("built-in");
        Member signupMember = Member.createSignupMember(signUpRequest);
        Member member = memberRepository.save(signupMember);
        return member.toDto();
    }

}
