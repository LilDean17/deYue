package burp;

import java.util.*;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;

/**
 * 凭证扫描器
 * <p>
 * 扫描 Burp Proxy 历史，提取域名和不同账号的凭证（Cookie/Token）。
 * 由 BurpExtender 持有实例。
 * </p>
 */
class CredentialScanner {

    private final BurpExtender extender;

    CredentialScanner(BurpExtender extender) {
        this.extender = extender;
    }

    // ==================== 域名扫描 ====================

    /**
     * 扫描 Proxy 历史，提取所有不重复的域名
     */
    String[] scanDomains() {
        IHttpRequestResponse[] proxyHistory = extender.callbacks.getProxyHistory();
        Set<String> domainSet = new LinkedHashSet<>();

        for (IHttpRequestResponse requestResponse : proxyHistory) {
            try {
                IRequestInfo requestInfo = extender.helpers.analyzeRequest(requestResponse);
                if (requestInfo == null) continue;
                java.net.URL url = requestInfo.getUrl();
                if (url == null) continue;
                String host = url.getHost();
                if (host != null && !host.isEmpty()) {
                    domainSet.add(host);
                }
            } catch (Exception e) {
                // 跳过无法解析的请求
            }
        }

        return domainSet.toArray(new String[0]);
    }

    // ==================== 凭证分析 ====================

    /**
     * 分析指定域名的所有请求，找出两个不同的凭证
     */
    CredentialResult analyzeDomain(String targetDomain) {
        CredentialResult result = new CredentialResult();
        IHttpRequestResponse[] proxyHistory = extender.callbacks.getProxyHistory();

        // 收集该域名下所有请求的完整认证头
        List<String[]> allCreds = new ArrayList<>();

        for (IHttpRequestResponse requestResponse : proxyHistory) {
            try {
                String host = extender.helpers.analyzeRequest(requestResponse).getUrl().getHost();
                if (!targetDomain.equals(host)) {
                    continue;
                }
                String[] creds = extractFullHeaders(requestResponse);
                if (creds.length > 0) {
                    allCreds.add(creds);
                }
            } catch (Exception e) {
                // 跳过
            }
        }

        if (allCreds.size() < 2) {
            return result;
        }

        // 统计每种认证头出现的频率
        Map<String, Integer> headerFreq = new LinkedHashMap<>();

        for (String[] creds : allCreds) {
            for (String header : creds) {
                headerFreq.put(header, headerFreq.getOrDefault(header, 0) + 1);
            }
        }

        // 选出频率最高的两个不同认证头
        List<Map.Entry<String, Integer>> sorted = new ArrayList<>(headerFreq.entrySet());
        sorted.sort((a, b) -> b.getValue() - a.getValue());

        if (sorted.size() >= 2) {
            result.accountAFullHeader = sorted.get(0).getKey();
            result.accountBFullHeader = sorted.get(1).getKey();
        } else if (sorted.size() == 1) {
            result.accountAFullHeader = sorted.get(0).getKey();
        }

        return result;
    }

    /**
     * 从请求中提取所有认证头的完整内容（保留 "HeaderName: value" 格式）
     * 认证头名称从未授权区域缓存读取（由 AuthPanel 在 EDT 上同步，避免后台线程读 Swing 组件）
     */
    String[] extractFullHeaders(IHttpRequestResponse requestResponse) {
        java.util.List<String> creds = new java.util.ArrayList<>();
        try {
            // 从缓存读取未授权认证字段名（线程安全）
            String[] authHeaderNames = extender.unauthorizedFieldCache;
            List<String> headers = extender.helpers.analyzeRequest(requestResponse).getHeaders();
            for (String header : headers) {
                header = header.trim();
                if (header.startsWith("POST ") || header.startsWith("GET ") ||
                    header.startsWith("PUT ") || header.startsWith("DELETE ") ||
                    header.startsWith("HEAD ") || header.startsWith("OPTIONS ")) {
                    continue;
                }
                // 按未授权区域配置的认证头名称匹配（不区分大小写）
                for (String authName : authHeaderNames) {
                    String trimmedName = authName.trim();
                    if (!trimmedName.isEmpty() && header.toLowerCase().startsWith(trimmedName.toLowerCase() + ":")) {
                        creds.add(header);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            // 跳过
        }
        return creds.toArray(new String[0]);
    }

    // ==================== 结果类 ====================

    static class CredentialResult {
        String accountAFullHeader = "";   // 完整认证头，如 "Cookie: xxx"
        String accountBFullHeader = "";   // 完整认证头，如 "Authorization: Bearer xxx"

        boolean hasResult() {
            return !accountAFullHeader.isEmpty() || !accountBFullHeader.isEmpty();
        }
    }
}
