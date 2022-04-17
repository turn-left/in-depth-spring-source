package com.ethen.usecase.parsing;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDate;

@Getter
@Setter
@ToString
public class BaseUserDto {
    /**
     * 失效日期 默认值 2122/12/31
     */
    @JsonFormat(pattern = "yyyy/MM/dd", timezone = "GMT+8")
    private LocalDate expireDate = LocalDate.of(2122, 12, 31);

    /**
     * 下次登录是否需要修改密码
     */
    private boolean pwdNeedChange = false;
}