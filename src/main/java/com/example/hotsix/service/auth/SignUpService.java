package com.example.hotsix.service.auth;

import com.example.hotsix.dto.auth.SignUpRequest;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.model.Member;
import com.example.hotsix.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SignUpService {

    private final MemberRepository memberRepository;

    public MemberDto signUp(SignUpRequest signUpRequest) {
        Member signupMember = Member.createSignupMember(signUpRequest);
        Member member = memberRepository.save(signupMember);
        return member.toDto();
    }

}
