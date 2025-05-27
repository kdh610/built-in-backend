package com.example.hotsix.jwt;

import com.example.hotsix.controller.auth.ReissueController;
import com.example.hotsix.dto.member.MemberDto;
import com.example.hotsix.enums.Process;
import com.example.hotsix.exception.BuiltInException;
import com.example.hotsix.service.auth.RedisTokenService;
import com.example.hotsix.service.auth.ReissueService;
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
    private ReissueService reissueService;
    @MockBean
    private StorageService storageService;
    @MockBean
    private JpaMetamodelMappingContext jpaMetamodelMappingContext;


    @Test
    @DisplayName("AccessToken 재발행 테스트")
    void reissueAccessToken() throws Exception {
        String refreshToken = "refreshToken";
        String newAccessToken = "newAccessToken";
        Cookie refresh = new Cookie("refresh", refreshToken);

        Mockito.when(reissueService.reissueAcessToken(refreshToken)).thenReturn(newAccessToken);

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
        Mockito.when(reissueService.reissueAcessToken(refreshToken)).thenThrow(new BuiltInException(Process.INVALID_TOKEN));

        mockMvc.perform(MockMvcRequestBuilders.post("/reissue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .cookie(refresh)
                        .with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.process").exists())
                .andExpect(jsonPath("$.process.statusCode").value(401))
                .andExpect(jsonPath("$.process.message").value("잘못된 JWT Token 입니다."))
                .andExpect(jsonPath("$.data").doesNotExist());
    }


}
