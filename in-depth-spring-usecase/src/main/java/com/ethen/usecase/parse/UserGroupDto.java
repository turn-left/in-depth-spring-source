package com.ethen.usecase.parse;

import cn.afterturn.easypoi.excel.annotation.Excel;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.ToString;

import javax.validation.constraints.NotBlank;
import java.math.BigDecimal;

@Data
@CsvEntity(propertySize = 6, name = "UserGroupDto")
@ToString(callSuper = true)
public class UserGroupDto extends BaseUserDto {

    @NotBlank(message = "用户账号为必填")
    @CsvProperty(index = 0, name = "用户账号（必填）")
    @Excel(name = "用户账号（必填）", width = 20)
    private String name;

    @NotBlank(message = "密码为必填")
    @Excel(name = "密码（必填）", width = 20)
    @CsvProperty(index = 1, name = "密码（必填）")
    private String password;

    @Excel(name = "所属组织（选填，为空则默认为“系统默认”）", width = 40)
    @CsvProperty(index = 2, name = "所属组织（选填，为空则默认为“系统默认”）")
    private String orgName;

    @Excel(name = "初始金额（选填，为空则默认为0）", width = 40)
    @CsvProperty(index = 3, name = "初始金额（选填，为空则默认为0）")
    private BigDecimal balance;

    @Excel(name = "姓名（选填）", width = 20)
    @CsvProperty(index = 4, name = "姓名（选填）")
    private String realName;

    @Excel(name = "邮箱（选填）", width = 20)
    @CsvProperty(index = 5, name = "邮箱（选填）")
    private String email;

    private boolean frozen;

    private Long updateAt;

    private String orgId;


    @JsonIgnore
    private Integer gid; // linux gid

    @JsonIgnore
    private Integer uid; // linux uid

    /**
     * 手机号 （仅限国内版，国内必填）
     */
    private String phoneNumber;

}
