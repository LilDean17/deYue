package burp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;

/**
 * 越权检测引擎
 * <p>
 * 核心检测逻辑：对每个请求发送三种权限级别的请求（高权限/低权限/未授权），
 * 对比响应长度差异来识别潜在的越权漏洞。
 * 包含 MD5 去重、参数替换引擎、差异报告生成等功能。
 * </p>
 */
class VulnDetector {

    private final BurpExtender extender;
    private final GuiRefs refs;
    private final RequestFilter requestFilter;

    VulnDetector(BurpExtender extender, GuiRefs refs, RequestFilter requestFilter) {
        this.extender = extender;
        this.refs = refs;
        this.requestFilter = requestFilter;
    }

    // ==================== 核心检测入口 ====================

    void checkVul(IHttpRequestResponse baseRequestResponse, int toolFlag) {
        if (!isValidRequest(baseRequestResponse, toolFlag)) {
            return;
        }
        String md5 = generateMD5(baseRequestResponse);
        if (isDuplicateRequest(md5)) {
            return;
        }
        // 先登记 MD5（防止并发重复触发），处理失败时再回滚移除
        RequestMd5 md5Entry = new RequestMd5(md5);
        extender.log4_md5.add(md5Entry);
        processRequestAndResponse(baseRequestResponse, md5Entry);
    }

    // ==================== 请求验证 ====================

    private boolean isValidRequest(IHttpRequestResponse baseRequestResponse, int toolFlag) {
        if (toolFlag != 4 && toolFlag != 64) {
            return false;
        }
        String url = extender.helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        String extension = requestFilter.getFileExtension(url);
        // 不检测静态资源（过滤由 RequestFilter 也处理，这里做双重保险）
        String[] staticExts = {
            "jpg", "png", "gif", "css", "js", "pdf", "mp3",
            "mp4", "avi", "map", "svg", "ico", "woff", "woff2", "ttf"
        };
        for (String ext : staticExts) {
            if (ext.equalsIgnoreCase(extension)) {
                return false;
            }
        }
        return true;
    }

    // ==================== MD5 去重 ====================

    String generateMD5(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo analyzeRequest = extender.helpers.analyzeRequest(baseRequestResponse);
        String url = analyzeRequest.getUrl().toString();
        String method = analyzeRequest.getMethod();

        // 提取 URL 路径，忽略查询参数
        String urlPath = url.split("\\?")[0];

        // 构建 MD5 输入：URL 路径 + 方法 + 参数名（忽略参数值）
        StringBuilder md5Input = new StringBuilder(urlPath);
        md5Input.append("+").append(method);

        List<IParameter> parameters = analyzeRequest.getParameters();
        if (!parameters.isEmpty()) {
            List<String> paramNames = new ArrayList<>();
            for (IParameter param : parameters) {
                paramNames.add(param.getName());
            }
            Collections.sort(paramNames);
            for (String paramName : paramNames) {
                md5Input.append("+").append(paramName);
            }
        }

        return MD5(md5Input.toString());
    }

    private boolean isDuplicateRequest(String md5) {
        Iterator<RequestMd5> it = extender.log4_md5.iterator();
        while (it.hasNext()) {
            if (it.next().md5Data.equals(md5)) {
                return true;
            }
        }
        return false;
    }

    // ==================== 核心请求处理 ====================

    private void processRequestAndResponse(IHttpRequestResponse baseRequestResponse, RequestMd5 md5Entry) {
        extender.temp_data = String.valueOf(extender.helpers.analyzeRequest(baseRequestResponse).getUrl());

        // 原始响应判空
        if (baseRequestResponse.getResponse() == null) {
            extender.stdout.println("原始数据包无响应，已跳过记录: " + extender.temp_data);
            extender.log4_md5.remove(md5Entry);
            return;
        }

        IRequestInfo analyIRequestInfo = extender.helpers.analyzeRequest(baseRequestResponse);
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        String request = extender.helpers.bytesToString(baseRequestResponse.getRequest());
        int bodyOffset = analyIRequestInfo.getBodyOffset();
        byte[] body = request.substring(bodyOffset).getBytes();
        List<String> baseHeaders = analyIRequestInfo.getHeaders();

        // 是否有参数（用于 IDOR 检测判定）
        boolean hasParams = !analyIRequestInfo.getParameters().isEmpty();

        // 读取未授权区域文本框实时内容（缓存变量，避免非 EDT 线程读 Swing 组件）
        String[] authHeaderNames = extender.unauthorizedFieldCache;

        // ---- ① 账号A（高权限）请求 ----
        List<String> headers_a = buildHeadersWithCredential(baseHeaders, authHeaderNames, extender.accountA_cred);
        byte[] newRequest_a = extender.helpers.buildHttpMessage(headers_a, body);
        IHttpRequestResponse requestResponse_a = extender.callbacks.makeHttpRequest(iHttpService, newRequest_a);

        if (requestResponse_a == null || requestResponse_a.getResponse() == null) {
            extender.stdout.println("账号A数据包无响应，已跳过记录: " + extender.temp_data);
            extender.log4_md5.remove(md5Entry);
            return;
        }

        // ---- ② 账号B（低权限）请求 ----
        // 凭据为空检查：accountB_cred 为 null 或空时，B 请求实际是 "未授权请求"
        // 这会导致 originalBody == bBody 误判为 IDOR。显示 "未配置" 提醒用户。
        boolean bCredConfigured = extender.accountB_cred != null && !extender.accountB_cred.trim().isEmpty();
        List<String> headers_b = buildHeadersWithCredential(baseHeaders, authHeaderNames, bCredConfigured ? extender.accountB_cred : null);
        byte[] newRequest_b = extender.helpers.buildHttpMessage(headers_b, body);
        IHttpRequestResponse requestResponse_b = extender.callbacks.makeHttpRequest(iHttpService, newRequest_b);

        if (requestResponse_b == null || requestResponse_b.getResponse() == null) {
            extender.stdout.println("账号B数据包无响应，已跳过记录: " + extender.temp_data);
            extender.log4_md5.remove(md5Entry);
            return;
        }
        String bBody = extractResponseBody(requestResponse_b.getResponse());

        // ---- ③ 未授权请求 ----
        List<String> headers_w = buildHeadersWithCredential(baseHeaders, authHeaderNames, null);
        byte[] newRequest_w = extender.helpers.buildHttpMessage(headers_w, body);
        IHttpRequestResponse requestResponse_w = extender.callbacks.makeHttpRequest(iHttpService, newRequest_w);

        if (requestResponse_w == null || requestResponse_w.getResponse() == null) {
            extender.stdout.println("未授权数据包无响应，已跳过记录: " + extender.temp_data);
            extender.log4_md5.remove(md5Entry);
            return;
        }
        // 计算响应相似度
        // 关键修复：低权限相似度应该对比 A 重发 vs B 重发（两个账号的数据是否一致），
        // 而不是 originalBody vs bBody（因为 originalBody 取决于当前登录用户，
        // 如果用户登录的是 B，originalBody 就是 B 的数据，跟 bBody 必然 100% 一样）
        String aBody = extractResponseBody(requestResponse_a.getResponse());
        String wBody = extractResponseBody(requestResponse_w.getResponse());
        double simB = ResponseSimilarity.compareResponses(aBody, bBody);  // A vs B
        double simW = ResponseSimilarity.compareResponses(aBody, wBody);  // A vs 未授权

        // 凭据未配置时显示 "N/A"，避免误判为 IDOR
        String lowSim_data = bCredConfigured
            ? ResponseSimilarity.formatSimilarity(simB)
            : "N/A (未配置B凭据)";
        String unauthorizedSim_data = ResponseSimilarity.formatSimilarity(simW);

        // === 检测结果判定（依据 需求变更文档.md）===
        // 无参: A vs B 比对无意义，仅根据 A vs 未授权判定 unauthorized
        // 有参: A vs B ≥0.98 → idor；A vs 未授权 ≥0.98 → unauthorized；可同时命中
        String detectionResult = computeDetectionResult(hasParams, simB, simW, bCredConfigured);

        // 精简调试日志（保留最关键信息）
        extender.stdout.println("====== 检测结果 ====== URL: " + extender.temp_data);
        extender.stdout.println("  有参=" + hasParams + "  simB=" + String.format("%.4f", simB)
            + "  simW=" + String.format("%.4f", simW));
        extender.stdout.println("  判定=" + (detectionResult.isEmpty() ? "(空)" : detectionResult));
        // 打印请求体前 80 字符（帮助排查 body 含 userId 的场景）
        String bodyStr = new String(body);
        if (!bodyStr.isEmpty()) {
            extender.stdout.println("  请求体前80: " + bodyStr.substring(0, Math.min(80, bodyStr.length())));
        }

        // 构建日志条目（在 EDT 外准备好数据）
        final LogEntry newEntry = new LogEntry(
            extender.conut + 1, analyIRequestInfo.getMethod(),
            extender.callbacks.saveBuffersToTempFiles(requestResponse_a),
            extender.callbacks.saveBuffersToTempFiles(requestResponse_b),
            extender.callbacks.saveBuffersToTempFiles(requestResponse_w),
            String.valueOf(analyIRequestInfo.getUrl()),
            lowSim_data, unauthorizedSim_data, detectionResult
        );

        // 必须在 EDT 上添加数据和刷新表格，消除线程安全问题
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    extender.log.add(newEntry);
                    extender.conut = newEntry.id;
                    extender.fireTableDataChanged();
                    if (extender.logTable != null) {
                        int last = Math.max(0, extender.log.size() - 1);
                        extender.logTable.setRowSelectionInterval(last, last);
                        extender.logTable.repaint();
                    }
                } catch (Exception e) {
                    extender.stdout.println("刷新表格时发生错误: " + e.getMessage());
                    e.printStackTrace(extender.stdout);
                }
            }
        });
    }

    // ==================== Body 提取（供相似度计算）====================

    /**
     * 从 HTTP 响应字节中提取 body 部分
     * <p>
     * 解析失败或 bodyOffset 异常时返回空串，确保相似度计算不会 NPE。
     * </p>
     *
     * @param response 完整 HTTP 响应字节（含状态行 + headers + body）
     * @return body 字符串（UTF-8 解码）
     */
    private String extractResponseBody(byte[] response) {
        if (response == null || response.length == 0) {
            return "";
        }
        try {
            int bodyOffset = extender.helpers.analyzeResponse(response).getBodyOffset();
            if (bodyOffset < 0 || bodyOffset > response.length) {
                return "";
            }
            // IExtensionHelpers.bytesToString 只接受 byte[]，无 3 参数版本，手动切片
            int bodyLen = response.length - bodyOffset;
            byte[] bodyBytes = new byte[bodyLen];
            System.arraycopy(response, bodyOffset, bodyBytes, 0, bodyLen);
            return extender.helpers.bytesToString(bodyBytes);
        } catch (Exception e) {
            return "";
        }
    }

    // ==================== 检测结果判定 ====================

    /**
     * 依据 需求变更文档.md 判定检测结果
     * <pre>
     * 无参:
     *   - A vs B 比对无意义
     *   - A vs 未授权 ≥0.98 → "unauthorized"
     *   - 否则 → ""
     * 有参:
     *   - A vs B ≥0.98 → "idor"
     *   - A vs 未授权 ≥0.98 → "unauthorized"
     *   - 可同时命中 → "idor+unauthorized"
     *   - 否则 → ""
     * </pre>
     *
     * @param hasParams        请求是否含参数
     * @param simB             A 响应 vs B 响应的相似度
     * @param simW             A 响应 vs 未授权响应的相似度
     * @param bCredConfigured  B 凭据是否已配置（未配置时跳过 idor 判定）
     * @return 检测结果字符串，可空
     */
    private String computeDetectionResult(boolean hasParams, double simB, double simW, boolean bCredConfigured) {
        final double THRESHOLD = 0.98;
        java.util.List<String> results = new java.util.ArrayList<>();
        if (hasParams && bCredConfigured && simB >= THRESHOLD) {
            results.add("idor");
        }
        if (simW >= THRESHOLD) {
            results.add("unauthorized");
        }
        return String.join("+", results);
    }

    // ==================== 请求头构建（统一方法） ====================

    /**
     * 构建请求头：移除配置的认证头，插入新凭据
     * <p>
     * credential 支持两种格式：
     * <ul>
     *   <li>完整格式："Cookie: PHPSESSID=xxx" / "Authorization: Bearer xxx"</li>
     *   <li>纯值格式："PHPSESSID=xxx"（自动用 "Cookie" 作为 header 名）</li>
     * </ul>
     *
     * @param headers          原始请求头列表
     * @param authHeaderNames  未授权区域配置的认证头名称数组（一行一个）
     * @param credential       要插入的凭据，为 null 表示不插入（即未授权请求）
     * @return 处理后的请求头列表
     */
    private List<String> buildHeadersWithCredential(List<String> headers, String[] authHeaderNames, String credential) {
        List<String> result = new ArrayList<>(headers);

        // 第一步：移除配置的认证头（大小写不敏感，避免 "Usertoken" vs "usertoken" 不匹配）
        for (int i = 0; i < result.size(); ++i) {
            String head_key = result.get(i).split(":")[0].trim();
            for (String authName : authHeaderNames) {
                String trimmedName = authName.trim();
                if (!trimmedName.isEmpty() && head_key.equalsIgnoreCase(trimmedName)) {
                    result.remove(i);
                    --i;
                    break;
                }
            }
        }

        // 第二步：插入新凭据（credential 为 null 时不插入，即未授权请求）
        if (credential != null && !credential.isEmpty()) {
            String headerName = null;
            String headerValue = null;
            int colonIdx = credential.indexOf(":");
            if (colonIdx > 0) {
                // 完整格式 "HeaderName: value"
                headerName = credential.substring(0, colonIdx).trim();
                headerValue = credential.substring(colonIdx + 1).trim();
            } else {
                // 纯值格式 "value" → 默认用 Cookie 作为 header 名
                headerName = "Cookie";
                headerValue = credential.trim();
            }
            if (headerName != null && !headerName.isEmpty()
                    && headerValue != null && !headerValue.isEmpty()) {
                result.add(result.size() / 2, headerName + ": " + headerValue);
            }
        }

        return result;
    }

    // ==================== 差异报告 ====================

    String generateDiffReport(String original, String modified) {
        // 计算相似度
        double similarity = ResponseSimilarity.compareResponses(original, modified);

        StringBuilder report = new StringBuilder();
        report.append("=== 差异报告 ===\n\n");
        report.append("响应相似度: ").append(String.format("%.2f%%", similarity * 100)).append("\n");
        report.append("相似度阈值: ").append(String.format("%.0f%%", ResponseSimilarity.getSimilarityThreshold() * 100));
        if (similarity >= ResponseSimilarity.getSimilarityThreshold()) {
            report.append("  ⚠ 高相似度，疑似越权/未授权访问\n");
        } else {
            report.append("  - 正常\n");
        }
        report.append("\n");

        String[] originalLines = original.split("\n");
        String[] modifiedLines = modified.split("\n");

        int maxLines = Math.max(originalLines.length, modifiedLines.length);
        for (int i = 0; i < maxLines; i++) {
            String originalLine = i < originalLines.length ? originalLines[i] : "";
            String modifiedLine = i < modifiedLines.length ? modifiedLines[i] : "";

            if (!originalLine.equals(modifiedLine)) {
                report.append("行 ").append(i + 1).append(":\n");
                report.append("原始响应: ").append(originalLine).append("\n");
                report.append("低权限响应: ").append(modifiedLine).append("\n\n");
            }
        }

        report.append("\n=== 长度比较 ===\n");
        report.append("原始响应长度: ").append(original.length()).append("\n");
        report.append("低权限响应长度: ").append(modified.length()).append("\n");
        report.append("差异: ").append(modified.length() - original.length()).append(" 字节\n");

        return report.toString();
    }

    void showDiffReportDialog(final LogEntry logEntry) {
        if (logEntry == null) return;

        try {
            String originalResponse = extender.helpers.bytesToString(logEntry.requestResponse.getResponse());
            String modifiedResponse = extender.helpers.bytesToString(logEntry.requestResponse_1.getResponse());
            String diffReport = generateDiffReport(originalResponse, modifiedResponse);

            JPanel reportPanel = new JPanel(new BorderLayout());
            javax.swing.JTextArea reportArea = new javax.swing.JTextArea(diffReport);
            reportArea.setEditable(false);
            reportArea.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));
            JScrollPane reportScroll = new JScrollPane(reportArea);
            reportPanel.add(reportScroll, BorderLayout.CENTER);

            JOptionPane.showMessageDialog(
                null, reportPanel, "差异报告 - " + logEntry.url,
                JOptionPane.INFORMATION_MESSAGE
            );
        } catch (Exception e) {
            extender.stdout.println("生成差异报告时发生错误: " + e.getMessage());
            e.printStackTrace(extender.stdout);
        }
    }

    // ==================== 数据清理 ====================

    void clearAllData() {
        extender.log.clear();
        extender.log4_md5.clear();
        extender.conut = 0;

        refs.requestViewer.setMessage(new byte[0], true);
        refs.responseViewer.setMessage(new byte[0], false);
        refs.requestViewerLow.setMessage(new byte[0], true);
        refs.responseViewerLow.setMessage(new byte[0], false);
        refs.requestViewerUnauth.setMessage(new byte[0], true);
        refs.responseViewerUnauth.setMessage(new byte[0], false);

        extender.currentlyDisplayedItem = null;
        extender.currentlyDisplayedItem_1 = null;
        extender.currentlyDisplayedItem_2 = null;

        extender.fireTableDataChanged();
    }

    // ==================== MD5 工具方法 ====================

    static String MD5(String key) {
        char[] hexDigits = new char[]{
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };

        try {
            byte[] btInput = key.getBytes();
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            mdInst.update(btInput);
            byte[] md = mdInst.digest();
            int j = md.length;
            char[] str = new char[j * 2];
            int k = 0;

            for (int i = 0; i < j; ++i) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 15];
                str[k++] = hexDigits[byte0 & 0x0F];
            }

            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }
}
