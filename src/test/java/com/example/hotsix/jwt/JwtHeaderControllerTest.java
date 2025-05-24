package com.example.hotsix.jwt;

import com.example.hotsix.controller.auth.JwtHeaderController;
import com.example.hotsix.service.storage.StorageService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Import(SecurityConfiguration.class)
@WebMvcTest(controllers = JwtHeaderController.class)
public class JwtHeaderControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private StorageService storageService;
    @MockBean
    private JpaMetamodelMappingContext jpaMetamodelMappingContext;


    @Test
    @DisplayName("AccessToken 헤더로 전환 테스트")
    void convertAccessToken() throws Exception {
        String accessToken = "accessToken";
        Cookie access = new Cookie("access", accessToken);

        mockMvc.perform(MockMvcRequestBuilders.get("/convert")
                .contentType(MediaType.APPLICATION_JSON)
                .cookie(access)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(header().exists("Authorization")) // "Authorization" 헤더의 존재 여부 확인
            .andExpect(header().string("Authorization", "Bearer " + accessToken));

    }




}
