package com.ethen.usecase.parsing.csv;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * csv字段 用于标注需要操作的csv字段
 *
 * @author ethen
 * @since 2022/04/13
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface CsvProperty {
    /**
     * csv字段序号
     */
    int index() default 0;

    /**
     * csv字段名(表头)
     */
    String name();
}