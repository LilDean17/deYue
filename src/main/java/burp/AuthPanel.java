package burp;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/**
 * 右侧凭证管理面板
 */
class AuthPanel {

    private final BurpExtender extender;
    private final GuiRefs refs;
    private final CredentialScanner credentialScanner;
    private boolean scanning = false;

    private String[] cachedDomains = new String[0];
    private JPopupMenu currentPopup = null;
    private boolean suppressDocUpdate = false;
    private Timer popupTimer;

    AuthPanel(BurpExtender extender, GuiRefs refs, CredentialScanner credentialScanner) {
        this.extender = extender;
        this.refs = refs;
        this.credentialScanner = credentialScanner;
    }

    JPanel build() {
        JPanel jps_2 = new JPanel();
        jps_2.setLayout(new BorderLayout(5, 5));

        JPanel topPanel = buildDomainPanel();

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        centerSplit.setTopComponent(buildCredentialPanel());
        centerSplit.setBottomComponent(buildUnauthorizedPanel());
        centerSplit.setResizeWeight(0.5);
        centerSplit.setDividerLocation(0.5);

        jps_2.add(topPanel, BorderLayout.NORTH);
        jps_2.add(centerSplit, BorderLayout.CENTER);

        return jps_2;
    }

    // ==================== 域名选择区 ====================

    private JPanel buildDomainPanel() {
        JPanel panel = new JPanel(new BorderLayout(3, 3));

        refs.domainInputField = new JTextField();
        refs.domainInputField.setPreferredSize(new Dimension(170, 25));
        refs.domainInputField.setToolTipText("输入域名自动匹配，按回车搜索，或点击下拉按钮");

        refs.btnDropdown = new JButton("▼");
        refs.btnDropdown.setPreferredSize(new Dimension(30, 25));
        refs.btnDropdown.setToolTipText("点击查看所有已扫描域名");

        refs.btnClear = new JButton("清空列表");

        JPanel centerRow = new JPanel(new BorderLayout(3, 0));
        centerRow.add(new JLabel("目标域名:"), BorderLayout.WEST);
        centerRow.add(refs.domainInputField, BorderLayout.CENTER);
        centerRow.add(refs.btnDropdown, BorderLayout.EAST);

        JPanel btnRow = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 3, 0));
        btnRow.add(refs.btnClear);

        refs.btnReload = new JButton("重新加载");
        btnRow.add(refs.btnReload);
        panel.add(centerRow, BorderLayout.CENTER);
        panel.add(btnRow, BorderLayout.EAST);

        // 延迟弹窗定时器
        popupTimer = new Timer(300, new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                popupTimer.stop();
                onDomainTextChanged();
            }
        });
        popupTimer.setRepeats(false);

        // 实时过滤
        refs.domainInputField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { onDomainTextChanged(); }
            public void removeUpdate(DocumentEvent e) { onDomainTextChanged(); }
            public void changedUpdate(DocumentEvent e) { onDomainTextChanged(); }
        });

        // 输入框按回车 → 搜索域名
        refs.domainInputField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                hidePopup();
                searchDomain();
            }
        });

        // 下拉按钮：弹出所有已扫描域名
        refs.btnDropdown.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                showAllDomainsPopup();
            }
        });

        // 重新加载：清缓存 + 重新扫描 Proxy + 清输入框
        refs.btnReload.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                reloadDomains();
            }
        });

        // 清空列表
        refs.btnClear.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                extender.clearAllData();
                refs.accountACredField.setText("");
                refs.accountBCredField.setText("");
                refs.domainInputField.setText("");
                hidePopup();
            }
        });

        return panel;
    }

    // ==================== 重新加载 Proxy 域名 ====================

    private void reloadDomains() {
        cachedDomains = new String[0];
        refs.domainInputField.setText("");
        hidePopup();

        cachedDomains = credentialScanner.scanDomains();
        if (cachedDomains.length > 0) {
            showPopup(cachedDomains);
        }
    }

    // ==================== 实时过滤回显 ====================

    private void onDomainTextChanged() {
        if (suppressDocUpdate) return;

        String text = refs.domainInputField.getText().trim();
        if (text.isEmpty()) {
            hidePopup();
            return;
        }

        if (cachedDomains.length == 0) {
            cachedDomains = credentialScanner.scanDomains();
        }

        java.util.List<String> matches = new ArrayList<>();
        String lowerText = text.toLowerCase();
        for (String d : cachedDomains) {
            if (d.toLowerCase().contains(lowerText)) {
                matches.add(d);
            }
        }

        if (matches.isEmpty()) {
            hidePopup();
        } else {
            showPopup(matches.toArray(new String[0]));
        }
    }

    private void showAllDomainsPopup() {
        if (cachedDomains.length == 0) {
            cachedDomains = credentialScanner.scanDomains();
        }
        if (cachedDomains.length == 0) return;
        showPopup(cachedDomains);
    }

    private void showPopup(String[] domains) {
        hidePopup();

        final DefaultListModel<String> listModel = new DefaultListModel<>();
        for (String d : domains) {
            listModel.addElement(d);
        }
        final JList<String> list = new JList<>(listModel);
        list.setVisibleRowCount(Math.min(domains.length, 8));
        list.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        list.setFocusable(false);

        list.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                int index = list.locationToIndex(e.getPoint());
                if (index >= 0 && index < listModel.getSize()) {
                    String selected = listModel.getElementAt(index);
                    selectDomainFromPopup(selected);
                }
            }
        });

        list.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    String selected = list.getSelectedValue();
                    if (selected != null) {
                        selectDomainFromPopup(selected);
                    }
                    e.consume();
                }
            }
        });

        final JPopupMenu popup = new JPopupMenu();
        popup.setLightWeightPopupEnabled(true);
        popup.setFocusable(false);
        popup.add(new JScrollPane(list));
        currentPopup = popup;

        java.awt.Rectangle bounds = refs.domainInputField.getBounds();
        popup.show(refs.domainInputField, 0, bounds.height);

        refs.domainInputField.requestFocusInWindow();
    }

    private void hidePopup() {
        if (currentPopup != null) {
            currentPopup.setVisible(false);
            currentPopup = null;
        }
    }

    private void selectDomainFromPopup(String domain) {
        hidePopup();
        suppressDocUpdate = true;
        refs.domainInputField.setText(domain);
        suppressDocUpdate = false;
        extender.selectedDomain = domain;
        analyzeAndFillCredentials(domain);
    }

    // ==================== 搜索域名 ====================

    private void searchDomain() {
        if (scanning) return;
        String domain = refs.domainInputField.getText().trim();
        if (domain.isEmpty()) return;

        scanning = true;
        try {
            extender.selectedDomain = domain;
            analyzeAndFillCredentials(domain);
        } finally {
            scanning = false;
        }
    }

    // ==================== 账号凭证区 ====================

    private JPanel buildCredentialPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 5, 5));

        JPanel panelA = new JPanel(new BorderLayout(3, 3));
        panelA.add(new JLabel("账号A (高权限):"), BorderLayout.NORTH);
        JTextArea areaA = new JTextArea(3, 20);
        areaA.setLineWrap(true);
        areaA.setWrapStyleWord(true);
        areaA.setEditable(true);
        refs.accountACredField = areaA;
        JScrollPane scrollA = new JScrollPane(areaA);
        panelA.add(scrollA, BorderLayout.CENTER);

        JPanel panelB = new JPanel(new BorderLayout(3, 3));
        panelB.add(new JLabel("账号B (低权限):"), BorderLayout.NORTH);
        JTextArea areaB = new JTextArea(3, 20);
        areaB.setLineWrap(true);
        areaB.setWrapStyleWord(true);
        areaB.setEditable(true);
        refs.accountBCredField = areaB;
        JScrollPane scrollB = new JScrollPane(areaB);
        panelB.add(scrollB, BorderLayout.CENTER);

        panel.add(panelA);
        panel.add(panelB);
        return panel;
    }

    // ==================== 未授权认证区 ====================

    private JPanel buildUnauthorizedPanel() {
        JPanel bottomPanel = new JPanel(new BorderLayout(3, 3));
        JLabel jps_2_jls_2 = new JLabel("未授权：将移除下列头认证信息,区分大小写");
        extender.unauthorizedTextArea = new JTextArea("Cookie\nAuthorization\nToken\nUsertoken", 3, 30);
        extender.unauthorizedTextArea.setLineWrap(true);
        extender.unauthorizedTextArea.setWrapStyleWord(true);
        // 初始化缓存（当前在 EDT）
        extender.unauthorizedFieldCache = extender.unauthorizedTextArea.getText().split("\n");
        // 监听文本变化，实时同步缓存（避免后台线程直接读 Swing 组件）
        extender.unauthorizedTextArea.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refreshUnauthorizedCache(); }
            public void removeUpdate(DocumentEvent e) { refreshUnauthorizedCache(); }
            public void changedUpdate(DocumentEvent e) { refreshUnauthorizedCache(); }
        });
        JScrollPane jsp_1 = new JScrollPane(extender.unauthorizedTextArea);
        bottomPanel.add(jps_2_jls_2, BorderLayout.NORTH);
        bottomPanel.add(jsp_1, BorderLayout.CENTER);
        return bottomPanel;
    }

    /** 在 EDT 上同步未授权字段缓存到 extender，供后台检测线程使用 */
    private void refreshUnauthorizedCache() {
        if (extender.unauthorizedTextArea == null) return;
        extender.unauthorizedFieldCache = extender.unauthorizedTextArea.getText().split("\n");
    }

    // ==================== 扫描和分析逻辑 ====================

    private void analyzeAndFillCredentials(String domain) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                CredentialScanner.CredentialResult result = credentialScanner.analyzeDomain(domain);

                if (result.hasResult()) {
                    refs.accountACredField.setText(result.accountAFullHeader);
                    refs.accountBCredField.setText(result.accountBFullHeader);

                    extender.accountA_cred = result.accountAFullHeader;
                    extender.accountB_cred = result.accountBFullHeader;
                }
            }
        });
    }
}
