package com.example.hotsix.jwt;

import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.exception.BuiltInException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;


@AutoConfigureMockMvc
public class JwtUtilTest {

    private JWTUtil jwtUtil;

   @BeforeEach
   void setJwtUtil(){
       jwtUtil = new JWTUtil("test-scret-key-20223235-Lim-Dong-Gil-Kang-Min-Seo");
   }


    @Test
    @DisplayName("Jwt생성 테스트")
    void createJwt(){
        MemberDto member = MemberDto.builder()
                .email("test@gmail.com")
                .name("Test")
                .nickname("Test")
                .build();

        String accessToken = jwtUtil.createAccessToken(member, 10000000L);
        String name = jwtUtil.getName(accessToken);
        Assertions.assertEquals(name, "Test");
    }

    @Test
    @DisplayName("Jwt만료 테스트")
    void validateExpiredJwt(){
        MemberDto member = MemberDto.builder()
                .email("test@gmail.com")
                .name("Test")
                .nickname("Test")
                .build();

        String accessToken = jwtUtil.createAccessToken(member, 1000L);
        System.out.println(accessToken);
        try {
            Thread.sleep(1000L);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        Assertions.assertThrows(BuiltInException.class, () -> jwtUtil.validateToken(accessToken));
    }


    @Test
    @DisplayName("잘못된 Jwt 테스트")
    void validateWrongJwt(){
        Assertions.assertThrows(
                BuiltInException.class,() ->
                jwtUtil.validateToken("eyJhbGciOiJIUeI1NvJ9.eyJuYW1lIjoiVGVzdCIsImVtYWlsIjoidGVzdEBnbWFpbC5jb20iLCJjYXRlZ29yeSI6ImFjY2VzcyIsImlhdCI6MTc0NzkxODA0MSwiZXhwIjoxNzQ3OTE4MDQyfQ.DFRY-NNwhej3Mvbgjz2zeiX2GuC4Wzk-3H1L-ggFqC8"));
    }




}
