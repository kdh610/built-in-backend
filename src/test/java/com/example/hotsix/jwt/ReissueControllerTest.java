package com.example.hotsix.jwt;

import com.example.hotsix.controller.auth.ReissueController;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.service.auth.RedisTokentService;
import com.example.hotsix.service.storage.StorageService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Import(SecurityConfiguration.class)
@WebMvcTest(controllers = ReissueController.class)
public class ReissueControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private JWTUtil jwtUtil;
    @MockBean
    private RedisTokentService redisTokentService;
    @MockBean
    private StorageService storageService;
    @MockBean
    private JpaMetamodelMappingContext jpaMetamodelMappingContext;


    @Test
    @DisplayName("AccessToken 재발행 테스트")
    void reissueAccessToken() throws Exception {

        Long expectedUserId = 1L;
        String expectedUsername = "testUser";
        String expectedRole = "ROLE_USER";
        String expectedName = "Test User Name";
        String expectedEmail = "test@example.com";
        String refreshToken = "refreshToken";
        String newAccessToken = "newAccessToken";
        Cookie refresh = new Cookie("refresh", refreshToken);

        Mockito.when(jwtUtil.getCategory(refreshToken)).thenReturn("refresh");
        Mockito.when(jwtUtil.getId(refreshToken)).thenReturn(expectedUserId);
        Mockito.when(jwtUtil.getUsername(refreshToken)).thenReturn(expectedUsername);
        Mockito.when(jwtUtil.getRole(refreshToken)).thenReturn(expectedRole);
        Mockito.when(jwtUtil.getName(refreshToken)).thenReturn(expectedName);
        Mockito.when(jwtUtil.getEmail(refreshToken)).thenReturn(expectedEmail);
        Mockito.when(redisTokentService.isTokenInRedis("1")).thenReturn(true);
        Mockito.when(jwtUtil.createAccessToken(any(MemberDto.class), anyLong()))
                .thenReturn(newAccessToken);


        mockMvc.perform(MockMvcRequestBuilders.post("/reissue")
                .contentType(MediaType.APPLICATION_JSON)
                .cookie(refresh)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.process").exists())
                .andExpect(jsonPath("$.process.statusCode").value(200))
                .andExpect(jsonPath("$.process.message").value("정상적인 응답을 반환하였습니다"))
                .andExpect(jsonPath("$.data").exists())
                .andExpect(jsonPath("$.data.token").exists());

    }

    @Test
    @DisplayName("잘못된 refresh토큰요청 테스트")
    void expiredRefreshToken() throws Exception {
        String refreshToken = "refreshToken";
        Cookie refresh = new Cookie("refresh", refreshToken);

        Mockito.when(jwtUtil.validateToken(refreshToken)).thenReturn(false);
        Mockito.when(jwtUtil.getCategory(refreshToken)).thenReturn("refresh");


        mockMvc.perform(MockMvcRequestBuilders.post("/reissue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .cookie(refresh)
                        .with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.process").exists())
                .andExpect(jsonPath("$.process.statusCode").value(401))
                .andExpect(jsonPath("$.process.message").value("유효기간이 만료된 Token입니다."))
                .andExpect(jsonPath("$.data").doesNotExist());

    }

    @Test
    @DisplayName("이미 로그아웃된 refreshToken 테스트")
    void aleadyLogoutRefreshToken() throws Exception {
        Long expectedUserId = 1L;
        String expectedUsername = "testUser";
        String expectedRole = "ROLE_USER";
        String expectedName = "Test User Name";
        String expectedEmail = "test@example.com";
        String refreshToken = "refreshToken";
        String newAccessToken = "newAccessToken";
        Cookie refresh = new Cookie("refresh", refreshToken);

        Mockito.when(jwtUtil.getCategory(refreshToken)).thenReturn("refresh");
        Mockito.when(jwtUtil.getId(refreshToken)).thenReturn(expectedUserId);
        Mockito.when(jwtUtil.getUsername(refreshToken)).thenReturn(expectedUsername);
        Mockito.when(jwtUtil.getRole(refreshToken)).thenReturn(expectedRole);
        Mockito.when(jwtUtil.getName(refreshToken)).thenReturn(expectedName);
        Mockito.when(jwtUtil.getEmail(refreshToken)).thenReturn(expectedEmail);
        Mockito.when(redisTokentService.isTokenInRedis("1")).thenReturn(false);
        Mockito.when(jwtUtil.createAccessToken(any(MemberDto.class), anyLong()))
                .thenReturn(newAccessToken);


        mockMvc.perform(MockMvcRequestBuilders.post("/reissue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .cookie(refresh)
                        .with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.process").exists())
                .andExpect(jsonPath("$.process.statusCode").value(401))
                .andExpect(jsonPath("$.process.message").value("유효기간이 만료된 Token입니다."))
                .andExpect(jsonPath("$.data").doesNotExist());
    }


}
