package com.ethen.usecase.web.service;

import cn.afterturn.easypoi.excel.ExcelExportUtil;
import cn.afterturn.easypoi.excel.entity.ExportParams;
import cn.afterturn.easypoi.excel.entity.enmus.ExcelType;
import com.ethen.usecase.parsing.csv.CsvUtils;
import com.ethen.usecase.parsing.UserGroupDto;
import com.ethen.usecase.multipart.AccountConstant;
import com.ethen.usecase.multipart.FileDownloadHelper;
import com.ethen.usecase.multipart.FileType;
import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.Workbook;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;

@Slf4j
@Service
public class ExcelService {

    /**
     * 下载导入模板
     *
     * @param fileType 类型
     * @param response response
     */
    public void downloadTemplate(String fileType, HttpServletResponse response) {
        try {
            FileType type = FileType.fromSuffix(fileType);
            this.doDownloadTemplateInternal(type, response);
        } catch (IOException e) {
            log.error("doDownloadTemplateInternal error", e);
        }
    }

    private void doDownloadTemplateInternal(FileType type, HttpServletResponse response) throws IOException {
        String fileName = String.format(Locale.ENGLISH, AccountConstant.USER_EXPT_TEMPLATE_NAME, type.getSuffix());
        FileDownloadHelper.setDownloadProperties(response, type, fileName);
        // 导出属性设置
        if (type == FileType.CSV) {
            CsvUtils.writeLineList(Lists.newArrayList(AccountConstant.TEMPLATE_HEADER), response.getOutputStream());
        } else {
            ExportParams exportParams = new ExportParams();
            exportParams.setType(ExcelType.XSSF);
            Workbook workbook = ExcelExportUtil.exportExcel(exportParams, UserGroupDto.class, Lists.newArrayList());
            workbook.write(response.getOutputStream());
        }
    }
}
