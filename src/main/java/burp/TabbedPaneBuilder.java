package burp;

import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;

/**
 * 中间标签页构建器
 * <p>
 * 创建三个数据包查看器标签页：原始数据包、低权限数据包、未授权数据包。
 * 消息查看器引用注册到 GuiRefs，供其他模块（如 VulnDetector）使用。
 * </p>
 */
class TabbedPaneBuilder {

    private final BurpExtender extender;
    private final GuiRefs refs;

    TabbedPaneBuilder(BurpExtender extender, GuiRefs refs) {
        this.extender = extender;
        this.refs = refs;
    }

    JTabbedPane build() {
        JTabbedPane tabs = new JTabbedPane();

        // 创建消息查看器
        refs.requestViewer = extender.callbacks.createMessageEditor(extender, false);
        refs.responseViewer = extender.callbacks.createMessageEditor(extender, false);
        refs.requestViewerLow = extender.callbacks.createMessageEditor(extender, false);
        refs.responseViewerLow = extender.callbacks.createMessageEditor(extender, false);
        refs.requestViewerUnauth = extender.callbacks.createMessageEditor(extender, false);
        refs.responseViewerUnauth = extender.callbacks.createMessageEditor(extender, false);

        // 原始数据包标签页
        JSplitPane y_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        y_jp.setDividerLocation(500);
        y_jp.setLeftComponent(refs.requestViewer.getComponent());
        y_jp.setRightComponent(refs.responseViewer.getComponent());

        // 低权限数据包标签页
        JSplitPane d_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        d_jp.setDividerLocation(500);
        d_jp.setLeftComponent(refs.requestViewerLow.getComponent());
        d_jp.setRightComponent(refs.responseViewerLow.getComponent());

        // 未授权数据包标签页
        JSplitPane w_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        w_jp.setDividerLocation(500);
        w_jp.setLeftComponent(refs.requestViewerUnauth.getComponent());
        w_jp.setRightComponent(refs.responseViewerUnauth.getComponent());

        tabs.addTab("账号A数据包", y_jp);
        tabs.addTab("账号B数据包", d_jp);
        tabs.addTab("未授权数据包", w_jp);

        return tabs;
    }
}
