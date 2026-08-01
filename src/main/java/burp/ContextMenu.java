package burp;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/**
 * 右键菜单工厂
 * <p>
 * 实现 IContextMenuFactory 接口，提供三个右键菜单项：
 * 发送到deYue检测、提取认证信息、快速配置。
 * 由 BurpExtender 持有实例。
 * </summary>
 */
class ContextMenu {

    private final BurpExtender extender;
    private final GuiRefs refs;
    private final ConfigManager configManager;

    ContextMenu(BurpExtender extender, GuiRefs refs, ConfigManager configManager) {
        this.extender = extender;
        this.refs = refs;
        this.configManager = configManager;
    }

    List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        // 发送到deYue检测
        JMenuItem sendToXiaYue = new JMenuItem("发送到deYue检测");
        sendToXiaYue.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    if (extender.switchs == 1) {
                        for (IHttpRequestResponse message : messages) {
                            new Thread(new Runnable() {
                                public void run() {
                                    try {
                                        extender.vulnDetector.checkVul(message, 4);
                                    } catch (Exception ex) {
                                        extender.stdout.println("处理请求时发生错误: " + ex.getMessage());
                                        ex.printStackTrace(extender.stdout);
                                    }
                                }
                            }).start();
                        }
                    } else {
                        JOptionPane.showMessageDialog(
                            null, "请先启动插件！", "deYue提示",
                            JOptionPane.WARNING_MESSAGE
                        );
                    }
                }
            }
        });

        // 提取认证信息
        JMenuItem extractAuth = new JMenuItem("提取认证信息");
        extractAuth.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    extractAuthInfo(messages[0]);
                }
            }
        });

        // 快速配置
        JMenuItem quickConfig = new JMenuItem("快速配置");
        quickConfig.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showQuickConfigDialog();
            }
        });

        menuItems.add(sendToXiaYue);
        menuItems.add(extractAuth);
        menuItems.add(quickConfig);
        return menuItems;
    }

    // ==================== 提取认证信息 ====================

    private void extractAuthInfo(IHttpRequestResponse message) {
        IRequestInfo requestInfo = extender.helpers.analyzeRequest(message);
        List<String> headers = requestInfo.getHeaders();

        // 提取第一个认证头作为完整字符串
        String fullHeader = "";
        for (String header : headers) {
            header = header.trim();
            if (header.startsWith("POST ") || header.startsWith("GET ") ||
                header.startsWith("PUT ") || header.startsWith("DELETE ") ||
                header.startsWith("HEAD ") || header.startsWith("OPTIONS ")) {
                continue;
            }
            String lower = header.toLowerCase();
            if (lower.startsWith("cookie:") || lower.startsWith("authorization:") ||
                lower.startsWith("token:") || lower.startsWith("usertoken:")) {
                fullHeader = header;
                break;
            }
        }

        if (!fullHeader.isEmpty()) {
            final String finalHeader = fullHeader;
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    if (refs.accountACredField != null) {
                        refs.accountACredField.setText(finalHeader);
                    }
                    extender.accountA_cred = finalHeader;
                }
            });
            JOptionPane.showMessageDialog(
                null, "已成功提取认证信息到账号A: " + fullHeader, "deYue提示",
                JOptionPane.INFORMATION_MESSAGE
            );
        } else {
            showManualInputDialog();
        }
    }

    private void showManualInputDialog() {
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BorderLayout());

        JTextArea inputArea = new JTextArea(5, 30);
        inputArea.setText("Cookie: session=xxx\nAuthorization: Bearer xxx");
        JScrollPane scrollPane = new JScrollPane(inputArea);

        JLabel label = new JLabel("请输入认证信息（完整头，如 Cookie: xxx）：");
        inputPanel.add(label, BorderLayout.NORTH);
        inputPanel.add(scrollPane, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(
            null, inputPanel, "无法提取认证信息",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
        );

        if (result == JOptionPane.OK_OPTION) {
            String manualInput = inputArea.getText().trim();
            if (!manualInput.isEmpty()) {
                final String finalManualInput = manualInput;
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        if (refs.accountACredField != null) {
                            refs.accountACredField.setText(finalManualInput);
                        }
                        extender.accountA_cred = finalManualInput;
                    }
                });
                JOptionPane.showMessageDialog(
                    null, "已成功添加认证信息到账号A", "deYue提示",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        }
    }

    // ==================== 快速配置 ====================

    private void showQuickConfigDialog() {
        JPanel configPanel = new JPanel();
        configPanel.setLayout(new GridLayout(4, 2, 5, 5));

        configPanel.add(new JLabel("账号A凭证:"));
        JTextField accountACredField = new JTextField(
            refs.accountACredField != null ? refs.accountACredField.getText() : "");
        configPanel.add(accountACredField);

        configPanel.add(new JLabel("账号B凭证:"));
        JTextField accountBCredField = new JTextField(
            refs.accountBCredField != null ? refs.accountBCredField.getText() : "");
        configPanel.add(accountBCredField);

        configPanel.add(new JLabel("未授权认证字段:"));
        JTextArea unauthArea = new JTextArea(3, 25);
        unauthArea.setText(extender.unauthorizedTextArea.getText());
        JScrollPane unauthScroll = new JScrollPane(unauthArea);
        configPanel.add(unauthScroll);

        int result = JOptionPane.showConfirmDialog(
            null, configPanel, "快速配置",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
        );

        if (result == JOptionPane.OK_OPTION) {
            if (refs.accountACredField != null) {
                refs.accountACredField.setText(accountACredField.getText());
            }
            if (refs.accountBCredField != null) {
                refs.accountBCredField.setText(accountBCredField.getText());
            }

            extender.accountA_cred = accountACredField.getText();
            extender.accountB_cred = accountBCredField.getText();

            extender.unauthorizedTextArea.setText(unauthArea.getText());

            configManager.save();

            JOptionPane.showMessageDialog(
                null, "配置已更新并保存", "deYue提示",
                JOptionPane.INFORMATION_MESSAGE
            );
        }
    }
}
