package burp;

/**
 * 日志条目数据模型
 * 存储一次越权检测的完整信息
 * <p>
 * 字段含义：
 * <ul>
 *   <li>id - 序号</li>
 *   <li>method - HTTP 方法</li>
 *   <li>requestResponse / requestResponse_1 / requestResponse_2 - 账号A包 / 账号B包 / 未授权包</li>
 *   <li>url - 请求 URL</li>
 *   <li>lowSim - 账号B响应 vs 账号A响应的相似度（百分比）</li>
 *   <li>unauthorizedSim - 未授权响应 vs 账号A响应的相似度（百分比）</li>
 *   <li>detectionResult - 检测结果："idor" / "unauthorized" / "idor+unauthorized" / 空</li>
 * </ul>
 * </p>
 */
class LogEntry {
    final int id;
    final String method;
    final IHttpRequestResponsePersisted requestResponse;
    final IHttpRequestResponsePersisted requestResponse_1;
    final IHttpRequestResponsePersisted requestResponse_2;
    final String url;
    final String lowSim;
    final String unauthorizedSim;
    final String detectionResult;

    LogEntry(int id, String method,
             IHttpRequestResponsePersisted requestResponse,
             IHttpRequestResponsePersisted requestResponse_1,
             IHttpRequestResponsePersisted requestResponse_2,
             String url, String lowSim, String unauthorizedSim, String detectionResult) {
        this.id = id;
        this.method = method;
        this.requestResponse = requestResponse;
        this.requestResponse_1 = requestResponse_1;
        this.requestResponse_2 = requestResponse_2;
        this.url = url;
        this.lowSim = lowSim;
        this.unauthorizedSim = unauthorizedSim;
        this.detectionResult = detectionResult;
    }
}
