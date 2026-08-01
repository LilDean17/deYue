package burp;

import java.util.Arrays;

/**
 * 请求过滤器 — 仅保留静态资源过滤
 */
class RequestFilter {

    private final BurpExtender extender;

    private static final String[] STATIC_FILE_EXTENSIONS = {
        "jpg", "png", "gif", "css", "js", "pdf", "mp3",
        "mp4", "avi", "map", "svg", "ico", "woff", "woff2", "ttf"
    };

    RequestFilter(BurpExtender extender) {
        this.extender = extender;
    }

    boolean shouldFilter(IHttpRequestResponse messageInfo) {
        return shouldFilterStaticResource(messageInfo);
    }

    private boolean shouldFilterStaticResource(IHttpRequestResponse messageInfo) {
        try {
            String url = extender.helpers.analyzeRequest(messageInfo).getUrl().toString();
            String extension = getFileExtension(url);
            return Arrays.asList(STATIC_FILE_EXTENSIONS).contains(extension);
        } catch (Exception e) {
            return false;
        }
    }

    String getFileExtension(String url) {
        if (url == null) return "";
        int lastDotPos = url.lastIndexOf('.');
        int lastSlashPos = url.lastIndexOf('/');
        if (lastDotPos > lastSlashPos && lastDotPos < url.length() - 1) {
            String ext = url.substring(lastDotPos + 1);
            int paramIndex = ext.indexOf('?');
            if (paramIndex > 0) {
                ext = ext.substring(0, paramIndex);
            }
            return ext.toLowerCase();
        }
        return "";
    }
}
