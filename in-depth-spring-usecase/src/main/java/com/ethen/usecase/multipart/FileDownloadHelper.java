package com.ethen.usecase.multipart;

import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class FileDownloadHelper {

    public static void setDownloadProperties(HttpServletResponse response, FileType fileType, String fileName) throws UnsupportedEncodingException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("content-Type", ContentTypeConstant.getContentType(fileType.getSuffix()));
        response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(fileName, StandardCharsets.UTF_8.name()));
    }
}
