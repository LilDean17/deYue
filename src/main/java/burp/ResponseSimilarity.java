package burp;

/**
 * 响应相似度工具类（纯 Java 实现，无外部依赖）
 * <p>
 * 算法层只做字符串相似度，不解析响应格式。
 * HTML 响应通过 stripHtml() 预处理后再对比，JSON 响应直接对比。
 * </p>
 * <p>
 * Levenshtein 编辑距离：使用滚动数组优化，空间 O(min(n,m))，
 * 时间 O(n*m)。相比直接计算完整矩阵大幅降低内存占用。
 * </p>
 */
class ResponseSimilarity {

    // 大响应体优化阈值：>50KB 只比头 10KB + 尾 5KB
    private static final int MAX_SIZE = 50 * 1024;
    private static final int HEAD_SIZE = 10 * 1024;
    private static final int TAIL_SIZE = 5 * 1024;

    // 相似度阈值（>= 此值标记为潜在漏洞）
    private static final double SIMILARITY_THRESHOLD = 0.95;

    /**
     * 计算两个字符串的 Levenshtein 编辑距离（纯 Java 实现）
     * <p>
     * 使用滚动数组优化：只保留上一行和当前行，节省空间。
     </p>
     *
     * @param s1 字符串1
     * @param s2 字符串2
     * @return 编辑距离（将 s1 改为 s2 所需的最少单字符编辑操作数）
     */
    static int levenshteinDistance(String s1, String s2) {
        if (s1 == null || s2 == null) {
            return Integer.MAX_VALUE;
        }
        if (s1.equals(s2)) {
            return 0;
        }
        int m = s1.length();
        int n = s2.length();
        if (m == 0) return n;
        if (n == 0) return m;

        // 始终让较短的字符串作为列（n），减少内存占用
        if (m < n) {
            String tmp = s1; s1 = s2; s2 = tmp;
            int t = m; m = n; n = t;
        }

        int[] prev = new int[n + 1];
        int[] curr = new int[n + 1];

        // 初始化第一行
        for (int j = 0; j <= n; j++) {
            prev[j] = j;
        }

        for (int i = 1; i <= m; i++) {
            curr[0] = i;
            char ci = s1.charAt(i - 1);
            for (int j = 1; j <= n; j++) {
                int cost = (ci == s2.charAt(j - 1)) ? 0 : 1;
                curr[j] = Math.min(
                    Math.min(curr[j - 1] + 1,      // 插入
                             prev[j] + 1),          // 删除
                    prev[j - 1] + cost              // 替换
                );
            }
            // 滚动：curr → prev
            int[] tmp = prev; prev = curr; curr = tmp;
        }

        return prev[n];
    }

    /**
     * 计算两个字符串的 Levenshtein 相似度
     *
     * @param s1 字符串1
     * @param s2 字符串2
     * @return 相似度值 (0.0-1.0)，完全相同返回 1.0
     */
    static double levenshtein(String s1, String s2) {
        if (s1 == null || s2 == null) return 0.0;
        if (s1.equals(s2)) return 1.0;
        int maxLen = Math.max(s1.length(), s2.length());
        if (maxLen == 0) return 1.0;
        int distance = levenshteinDistance(s1, s2);
        return 1.0 - (double) distance / maxLen;
    }

    /**
     * 智能响应相似度（大响应体优化）
     * <p>
     * 对于超大响应体（>50KB），只比较头部 10KB + 尾部 5KB，取平均值。
     * 避免大响应（如 HTML 页面、JSON 长列表）计算 Levenshtein 过慢。
     * </p>
     *
     * @param r1 响应1
     * @param r2 响应2
     * @return 相似度 (0.0-1.0)
     */
    static double responseSimilarity(String r1, String r2) {
        if (r1 == null || r2 == null) return 0.0;
        if (r1.equals(r2)) return 1.0;
        if (r1.isEmpty() && r2.isEmpty()) return 1.0;
        if (r1.isEmpty() || r2.isEmpty()) return 0.0;

        if (r1.length() > MAX_SIZE || r2.length() > MAX_SIZE) {
            String r1Head = r1.substring(0, Math.min(HEAD_SIZE, r1.length()));
            String r1Tail = r1.length() > HEAD_SIZE
                ? r1.substring(Math.max(0, r1.length() - TAIL_SIZE)) : "";
            String r2Head = r2.substring(0, Math.min(HEAD_SIZE, r2.length()));
            String r2Tail = r2.length() > HEAD_SIZE
                ? r2.substring(Math.max(0, r2.length() - TAIL_SIZE)) : "";
            return (levenshtein(r1Head, r2Head) + levenshtein(r1Tail, r2Tail)) / 2.0;
        }

        return levenshtein(r1, r2);
    }

    /**
     * 自动判断响应格式并计算相似度
     */
    static double compareResponses(String r1, String r2) {
        if (r1 == null || r2 == null) return 0.0;
        if (r1.isEmpty() && r2.isEmpty()) return 1.0;
        if (r1.isEmpty() || r2.isEmpty()) return 0.0;

        if (isHtmlResponse(r1) || isHtmlResponse(r2)) {
            return responseSimilarity(stripHtml(r1), stripHtml(r2));
        }
        return responseSimilarity(r1, r2);
    }

    /**
     * 检测是否为 HTML 响应
     */
    private static boolean isHtmlResponse(String body) {
        if (body == null) return false;
        String trimmed = body.trim();
        return trimmed.startsWith("<") && !trimmed.startsWith("<?xml");
    }

    /**
     * 剥离 HTML 标签，保留文本内容
     */
    static String stripHtml(String html) {
        if (html == null || html.isEmpty()) return "";
        String s = html;
        s = s.replaceAll("(?is)<script[^>]*>.*?</script>", " ");
        s = s.replaceAll("(?is)<style[^>]*>.*?</style>", " ");
        s = s.replaceAll("<[^>]+>", " ");
        s = s.replace("&nbsp;", " ").replace("&lt;", "<")
             .replace("&gt;", ">").replace("&amp;", "&")
             .replace("&quot;", "\"").replace("&apos;", "'");
        s = s.replaceAll("\\s+", " ").trim();
        return s;
    }

    /**
     * 格式化相似度为表格显示字符串
     * <ul>
     *   <li>相似度 1.0 → "100.0%  ✔"（潜在漏洞）</li>
     *   <li>相似度 0.96 → "96.0%  ✔"（接近阈值）</li>
     *   <li>相似度 0.5 → "50.0%"</li>
     * </ul>
     */
    static String formatSimilarity(double similarity) {
        String percent = String.format("%.1f%%", similarity * 100);
        if (similarity >= SIMILARITY_THRESHOLD) {
            return percent + "  ✔";
        }
        return percent;
    }

    /**
     * 获取相似度阈值
     */
    static double getSimilarityThreshold() {
        return SIMILARITY_THRESHOLD;
    }
}
