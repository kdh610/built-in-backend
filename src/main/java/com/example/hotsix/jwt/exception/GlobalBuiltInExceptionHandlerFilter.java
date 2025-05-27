package com.example.hotsix.jwt.exception;

import com.example.hotsix.dto.common.APIResponse;
import com.example.hotsix.dto.common.ErrorResponse;
import com.example.hotsix.dto.common.ProcessResponse;
import com.example.hotsix.exception.BuiltInException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class GlobalBuiltInExceptionHandlerFilter extends OncePerRequestFilter {
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response); // 다음 필터 호출
        } catch (BuiltInException ex) {
            log.warn("GlobalBuiltInExceptionHandlerFilter에서 BuiltInException 처리: {}", ex.getMessage());
            handleBuiltInException(response, ex);
        }
    }

    private void handleBuiltInException(HttpServletResponse response, BuiltInException error) throws IOException {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .process(error.getProcess())
                .build();

        APIResponse<Object> apiResponse = APIResponse.builder()
                .process(ProcessResponse.from(errorResponse.getProcess()))
                .build();

        response.setStatus(errorResponse.getProcess().getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // try-with-resources를 사용하거나, ObjectMapper를 필드 멤버로 두고 재사용하는 것이 좋습니다.
        String json = objectMapper.writeValueAsString(apiResponse);
        response.getWriter().write(json);
    }
}
