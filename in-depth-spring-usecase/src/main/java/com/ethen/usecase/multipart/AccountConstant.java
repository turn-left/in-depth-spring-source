package com.ethen.usecase.multipart;

import java.time.ZoneId;

/**
 * 常量提取
 */
public interface AccountConstant {
    /**
     * 默认时区
     */
    ZoneId DEFAULT_ZONE_CTT = ZoneId.of("Asia/Shanghai");

    /**
     * 默认批次capacity
     */
    int DEFAULT_BATCH_CAP = 100;

    /**
     * 用户数据导入有误
     */
    String USER_IMPORT_ERROR = "error-%s";

    /**
     * 默认组织
     */
    String DEFAULT_ORG = "default";

    String ACCOUNT_ORG_COLLECTION = "accountorganization";

    String TEMPLATE_HEADER = "用户账号（必填）,密码（必填）,所属组织（选填，为空则默认为”系统默认“）,初始金额（选填，为空则默认为0）,姓名（选填）,邮箱（选填）";

    String USER_EXPT_TEMPLATE_NAME = "超算平台用户导入模板.%s";

    String USER_EXPT_FILE_NAME = "超算平台用户列表.xlsx";
}
