package com.ethen.usecase.parsing.csv;


import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * csv文件读写
 * <p>
 * note 不支持多层次继承
 *
 * @author ethen
 * @since 2022/04/13
 */
@Slf4j
public class CsvUtils {
    /**
     * csv文件本质上是逗号分隔(Comma Separated Values)的文本文件
     */
    public static final String CSV_DELIMITER = ",";

    /**
     * 逐行读取
     *
     * @param inputStream   input
     * @param excludeHeader 是否排除头信息
     * @return line list
     */
    public static List<String> readLineList(InputStream inputStream, boolean excludeHeader) {
        List<String> resultList = new ArrayList<>();
        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
            if (excludeHeader) {
                bufferedReader.readLine();
            }
            String line;
            while (StringUtils.isNoneBlank((line = bufferedReader.readLine()))) {
                resultList.add(line);
            }
        } catch (IOException e) {
            log.error("CsvUtils read error", e);
        }
        return resultList;
    }

    /**
     * 读取数据列表
     *
     * @param inputStream input
     * @param klass       data type info
     * @param <T>         type
     * @return object data list
     */
    public static <T> List<T> readObjectList(InputStream inputStream, Class<T> klass) {
        List<String> lineList = readLineList(inputStream, true);
        if (CollectionUtils.isEmpty(lineList)) {
            return Lists.newArrayList();
        }
        Field[] csvFields = parseCsvFields(klass);
        List<T> resultList = new ArrayList<>();
        try {
            for (String line : lineList) {
                if (StringUtils.isEmpty(line)) {
                    continue;
                }
                String[] rowData = line.trim().split(CSV_DELIMITER);
                T rowObj = klass.newInstance();

                for (int i = 0; i < csvFields.length; i++) {
                    Field csvField = csvFields[i];
                    csvField.setAccessible(true);
                    String columnData = rowData[i];
                    columnData = StringUtils.isBlank(columnData) ? StringUtils.EMPTY : columnData;
                    csvField.set(rowObj, convertValue(csvField.getType(), columnData));
                }
                resultList.add(rowObj);
            }
        } catch (InstantiationException | IllegalAccessException e) {
            log.error("CsvUtils readObject error", e);
        }
        return resultList;
    }

    /**
     * 写Csv文件
     *
     * @param lineList
     * @param outputStream
     */
    public static void writeLineList(List<String> lineList, OutputStream outputStream) {
        if (CollectionUtils.isEmpty(lineList)) {
            log.warn("CsvUtils do write lineList is empty");
            return;
        }
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(outputStream))) {
//                                                (byte) 0xEF, (byte) 0xBB, (byte) 0xBF
            writer.append(new String(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF}));
            for (String line : lineList) {
                writer.append(line).append(System.lineSeparator());
            }
        } catch (IOException e) {
            log.error("writeLineList error", e);
        }
    }

    /**
     * 读取csv文件
     *
     * @param dataList
     * @param klass
     * @param outputStream
     * @param <T>
     */
    public static <T> void writeObjectList(List<T> dataList, Class<T> klass, OutputStream outputStream) {
        Field[] fields = parseCsvFields(klass);
        List<String> lineList = new ArrayList<>();
        // 表头
        lineList.add(parseHeader(fields));
        try {
            for (T obj : dataList) {
                String[] rowData = new String[fields.length];
                for (int i = 0; i < fields.length; i++) {
                    Field field = fields[i];
                    field.setAccessible(true);
                    Object value = field.get(obj);
                    rowData[i] = Objects.isNull(value) ? StringUtils.EMPTY : value.toString();
                }
                lineList.add(String.join(CSV_DELIMITER, rowData));
            }
            writeLineList(lineList, outputStream);
        } catch (IllegalAccessException e) {
            log.error("writeObjectList error ", e);
        }
    }

    /**
     * 提取csv字段并且排序
     *
     * @param klass csv entity
     * @return field array
     */
    private static Field[] parseCsvFields(Class<?> klass) {
        CsvEntity csvEntity = klass.getAnnotation(CsvEntity.class);
        if (csvEntity == null) {
            throw new IllegalStateException(String.format(Locale.ENGLISH, "%s is not csv entity", klass.getSimpleName()));
        }
        Field[] csvFields = new Field[csvEntity.propertySize()];
        for (Field fd : klass.getDeclaredFields()) {
            CsvProperty csvProperty = fd.getAnnotation(CsvProperty.class);
            if (csvProperty == null) {
                continue;
            }
            csvFields[csvProperty.index()] = fd;
        }
        int hierarchy = csvEntity.hierarchy();
        // 读取继承关系
        for (int i = 0; i < hierarchy; i++) {
            Class<?> superclass = klass.getSuperclass();
            if (superclass == null) {
                break;
            }
            Field[] fields = superclass.getDeclaredFields();
            for (Field fd : fields) {
                CsvProperty csvProperty = fd.getAnnotation(CsvProperty.class);
                if (csvProperty == null) {
                    continue;
                }
                csvFields[csvProperty.index()] = fd;
            }
        }
        return csvFields;
    }

    private static String parseHeader(Field[] csvFields) {
        String[] header = new String[csvFields.length];
        for (int i = 0; i < csvFields.length; i++) {
            Field fd = csvFields[i];
            CsvProperty csvProperty = fd.getAnnotation(CsvProperty.class);
            header[i] = csvProperty.name();
        }
        return String.join(CSV_DELIMITER, header);
    }

    // 数据类型转换 csv读取都是String类型
    private static Object convertValue(Class<?> klass, String value) {
        if (klass.isAssignableFrom(BigDecimal.class)) {
            return new BigDecimal(value);
        } else {
            return value;
        }
    }
}
