package com.ethen.usecase.parse;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * csv entity 用于标注需要操作csv的类
 *
 * @author ethen
 * @since 2022/04/13
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface CsvEntity {
    /**
     * 名称
     */
    String name();

    /**
     * csv列数数量
     */
    int propertySize();

    /**
     * 层级 用于有继承csv属性的情况
     */
    int hierarchy() default 0;
}
