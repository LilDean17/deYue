package burp;

/**
 * MD5 去重数据模型
 * 用于记录已检测过的请求 MD5，避免重复检测
 */
class RequestMd5 {
    final String md5Data;

    RequestMd5(String md5Data) {
        this.md5Data = md5Data;
    }
}
