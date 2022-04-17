package com.ethen.usecase.multipart;

import lombok.Getter;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Locale;

/**
 * 常用文件类型
 *
 * @author ethen
 * @since 2022/04/10
 */
public enum FileType {
    UNKNOWN("UNKOWN", "UNKOWN", "UNKOWN"),
    CSV("csv", "csv", ""), //fixme what is the magic number?
    XLSX("excel", "xlsx", "504B0304"),
    ;

    @Getter
    private final String name;

    @Getter
    private final String suffix;

    @Getter
    private final String magic;

    FileType(String name, String suffix, String magic) {
        this.name = name;
        this.suffix = suffix;
        this.magic = magic;
    }

    public static FileType fromSuffix(String suffix) {
        for (FileType fileType : values()) {
            if (fileType.getSuffix().equalsIgnoreCase(suffix)) {
                return fileType;
            }
        }
        return UNKNOWN;
    }

    /**
     * 判定文件后缀是否在指定的后缀名中
     *
     * @param fileName 文件名
     * @param suffixes 后缀列表
     * @return boolean
     */
    public static boolean checkFileInSuffixes(String fileName, String... suffixes) {
        if (StringUtils.isBlank(fileName) || suffixes == null || suffixes.length == 0) {
            return false;
        }
        String fileSuffix = FilenameUtils.getExtension(fileName).toLowerCase(Locale.ENGLISH);
        return Arrays.stream(suffixes).anyMatch(suff -> suff.toLowerCase(Locale.ENGLISH).equals(fileSuffix));
    }

    public static FileType getFileTypeByName(String fileName) {
        if (StringUtils.isEmpty(fileName)) {
            return UNKNOWN;
        }
        return fromSuffix(FilenameUtils.getExtension(fileName));
    }


}
