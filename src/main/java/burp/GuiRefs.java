package burp;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/**
 * 所有 UI 组件引用的统一持有者
 */
class GuiRefs {

    // === 控制面板组件 ===
    JCheckBox chkbox1;          // 启动插件
    JButton btnClear;           // 清空列表按钮

    // === 凭证管理组件 ===
    JTextField domainInputField;     // 目标域名输入框
    JButton btnDropdown;             // 下拉选择域名按钮
    JButton btnReload;               // 重新加载 Proxy 域名
    JTextArea accountACredField;     // 账号A凭证
    JTextArea accountBCredField;     // 账号B凭证

    // === 未授权认证字段 ===
    JTextArea unauthorizedArea;    // 未授权认证字段

    // === 消息查看器 ===
    IMessageEditor requestViewer;
    IMessageEditor responseViewer;
    IMessageEditor requestViewerLow;
    IMessageEditor responseViewerLow;
    IMessageEditor requestViewerUnauth;
    IMessageEditor responseViewerUnauth;
}
