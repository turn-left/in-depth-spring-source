package com.ethen.mongo.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.mongodb.core.mapping.MongoId;

import java.time.LocalDate;

@Getter
@Setter
@ToString
@Builder
public class UserVO {
    // 使用@MongoId注解能更清晰的指定_id主键
    @MongoId
    private String id;

    private String name;

    private String sex;

    private Integer salary;

    private Integer age;

    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "GMT+8")
    private LocalDate birthday;

    private String remarks;

    private Status status;


    @Getter
    @Setter
    @ToString
    public static class Status {
        private Integer hight;
        private Integer weight;
    }

}
