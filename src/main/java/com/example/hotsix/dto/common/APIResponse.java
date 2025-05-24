package com.example.hotsix.dto.common;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * 모든 API의 반환 타입은 APIResponse 타입이어야 함
 * @param <T> : API 데이터 타입(dto 형태)
 */

@Getter
@Setter
public class APIResponse<T> {
    private ProcessResponse process;
    private T data;

    @Builder
    private APIResponse(ProcessResponse process, T data) {
        this.process = process;
        this.data = data;
    }

    public static <T> APIResponse<T> success(ProcessResponse process, T data){
        return APIResponse.<T>builder()
                .process(process)
                .data(data).build();
    }
}