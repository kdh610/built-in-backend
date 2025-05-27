
package com.example.hotsix.jwt;

import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.service.auth.RedisTokenService;
import com.example.hotsix.service.auth.ReissueService;
import com.example.hotsix.service.storage.StorageService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;

@Import(SecurityConfiguration.class)
@ExtendWith(MockitoExtension.class)
public class ReissueServiceTest {

    @InjectMocks
    private ReissueService reissueService;
    @Mock
    private JWTUtil jwtUtil;
    @Mock
    private RedisTokenService redisTokenService;
    @MockBean
    private StorageService storageService;
    @MockBean
    private JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @BeforeEach
    void setReissueService(){
        ReflectionTestUtils.setField(reissueService, "accessExpiretime", 100000L);
    }


    @Test
    @DisplayName("AccessToken 재발행 테스트")
    void reissueAccessToken() throws Exception {

        Long expectedUserId = 1L;
        String expectedRole = "ROLE_USER";
        String expectedName = "Test User Name";
        String expectedEmail = "test@example.com";
        String refreshToken = "refreshToken";
        String expectedAccessToken = "newAccessToken";

        Mockito.when(jwtUtil.validateToken(refreshToken)).thenReturn(true);
        Mockito.when(jwtUtil.isTokenTypeRefresh(refreshToken)).thenReturn(true);
        Mockito.when(jwtUtil.getId(refreshToken)).thenReturn(expectedUserId);
        Mockito.when(redisTokenService.isTokenInRedis("1")).thenReturn(true);
        Mockito.when(jwtUtil.getRole(refreshToken)).thenReturn(expectedRole);
        Mockito.when(jwtUtil.getEmail(refreshToken)).thenReturn(expectedEmail);
        Mockito.when(jwtUtil.getName(refreshToken)).thenReturn(expectedName);
        Mockito.when(jwtUtil.createAccessToken(any(MemberDto.class), anyLong())).thenReturn(expectedAccessToken);

        String newAccessToken = reissueService.reissueAcessToken(refreshToken);
        Assertions.assertEquals(expectedAccessToken, newAccessToken);
    }

    @Test
    @DisplayName("잘못된 refresh토큰요청 테스트")
    void expiredRefreshToken() throws Exception {
        String refreshToken = "refreshToken";
        Mockito.when(jwtUtil.validateToken(refreshToken)).thenThrow(new BuiltInException(Process.INVALID_TOKEN));

        Assertions.assertThrows(BuiltInException.class, () -> reissueService.reissueAcessToken(refreshToken));
    }

}
