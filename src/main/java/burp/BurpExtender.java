package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

/**
 * deYue — Burp Suite 越权检测插件入口
 * <p>
 * 作为协调器持有全局状态，委托各模块处理具体职责：
 * <ul>
 *   <li>{@link ControlPanel} — 左侧控制面板</li>
 *   <li>{@link AuthPanel} — 右侧凭证管理面板</li>
 *   <li>{@link TabbedPaneBuilder} — 中间数据包查看标签页</li>
 *   <li>{@link VulnDetector} — 核心越权检测引擎</li>
 *   <li>{@link RequestFilter} — 请求过滤器</li>
 *   <li>{@link ConfigManager} — 配置持久化管理</li>
 *   <li>{@link ContextMenu} — 右键菜单工厂</li>
 *   <li>{@link CredentialScanner} — 扫描 Proxy 历史提取凭证</li>
 * </ul>
 * </p>
 */
public class BurpExtender extends AbstractTableModel
    implements IBurpExtender, ITab, IHttpListener, IScannerCheck, IMessageEditorController, IContextMenuFactory {

    // ==================== Burp 回调 ====================
    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;
    public PrintWriter stdout;

    // ==================== 模块实例 ====================
    private GuiRefs refs = new GuiRefs();
    private ControlPanel controlPanel;
    private AuthPanel authPanel;
    private TabbedPaneBuilder tabbedPaneBuilder;
    VulnDetector vulnDetector;
    RequestFilter requestFilter;
    private ConfigManager configManager;
    private ContextMenu contextMenu;
    private CredentialScanner credentialScanner;

    // ==================== 全局状态 ====================
    JSplitPane splitPane;
    JTabbedPane tabs;
    JTable logTable;

    // 认证配置文本区域
    JTextArea unauthorizedTextArea;

    // 当前显示项（IMessageEditorController 实现需要）
    IHttpRequestResponse currentlyDisplayedItem;
    IHttpRequestResponse currentlyDisplayedItem_1;
    IHttpRequestResponse currentlyDisplayedItem_2;

    // 控制开关
    int switchs = 0;

    // 计数器
    int conut = 0;

    // 临时数据（URL/调试用）
    String temp_data;

    String data_2 = "Cookie\nAuthorization\nToken\nUsertoken";

    // 凭证管理
    String selectedDomain = "";
    String accountA_cred = "";   // 完整认证头，如 "Cookie: xxx" 或 "Authorization: Bearer xxx"
    String accountB_cred = "";   // 完整认证头

    // 未授权认证字段缓存（由 AuthPanel 在 EDT 上更新，避免后台线程读 Swing 组件）
    volatile String[] unauthorizedFieldCache = data_2.split("\n");

    // 数据存储
    final List<LogEntry> log = new ArrayList<>();
    final List<RequestMd5> log4_md5 = new ArrayList<>();

    // 版本信息
    String xy_version = "1.0";

    // 排序状态
    private int lastSortedColumn = -1;
    private boolean lastSortAscending = true;

    // ==================== IBurpExtender ====================

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello deYue!");
        this.stdout.println("你好 欢迎使用 deYue!");
        this.stdout.println("version:" + this.xy_version);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("deYue V" + this.xy_version);

        // 初始化各模块
        configManager = new ConfigManager(this, refs, stdout);
        requestFilter = new RequestFilter(this);
        vulnDetector = new VulnDetector(this, refs, requestFilter);
        controlPanel = new ControlPanel(this, refs, configManager);
        credentialScanner = new CredentialScanner(this);
        authPanel = new AuthPanel(this, refs, credentialScanner);
        tabbedPaneBuilder = new TabbedPaneBuilder(this, refs);
        contextMenu = new ContextMenu(this, refs, configManager);

        // 注册右键菜单和 HTTP 监听
        callbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                initializeUI();
            }
        });
    }

    // ==================== UI 初始化 ====================

    private void initializeUI() {
        // 创建主分割面板
        this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 创建表格
        this.logTable = new JTable(this);
        this.logTable.getColumnModel().getColumn(0).setPreferredWidth(10);
        this.logTable.getColumnModel().getColumn(1).setPreferredWidth(50);
        this.logTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        this.logTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        this.logTable.getColumnModel().getColumn(4).setPreferredWidth(130);
        this.logTable.getColumnModel().getColumn(5).setPreferredWidth(130);

        // 表头排序
        this.logTable.getTableHeader().addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                int column = logTable.columnAtPoint(e.getPoint());
                if (column >= 0) {
                    sortByColumn(column, true);
                }
            }
        });

        // 表头排序指示器
        this.logTable.getTableHeader().setReorderingAllowed(false);
        this.logTable.getTableHeader().setDefaultRenderer(new javax.swing.table.DefaultTableCellRenderer() {
            @Override
            public java.awt.Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == lastSortedColumn) {
                    String arrow = lastSortAscending ? " ▲" : " ▼";
                    setText(value + arrow);
                    setForeground(Color.BLUE);
                } else {
                    setText(value + " ▼");
                    setForeground(Color.BLACK);
                }
                return this;
            }
        });

        // 滚动面板
        JScrollPane scrollPane = new JScrollPane(this.logTable);
        JPanel jp = new JPanel();
        jp.setLayout(new GridLayout(1, 1));
        jp.add(scrollPane);

        // 构建各面板
        JPanel controlPanelUI = controlPanel.build();
        JPanel authPanelUI = authPanel.build();
        this.tabs = tabbedPaneBuilder.build();

        // 组装界面
        splitPanes_2.setLeftComponent(controlPanelUI);
        splitPanes_2.setRightComponent(authPanelUI);
        splitPanes.setLeftComponent(jp);
        splitPanes.setRightComponent(this.tabs);
        this.splitPane.setLeftComponent(splitPanes);
        this.splitPane.setRightComponent(splitPanes_2);
        this.splitPane.setResizeWeight(0.8);
        this.splitPane.setDividerLocation(0.8);

        // 自定义 UI 组件
        callbacks.customizeUiComponent(this.splitPane);
        callbacks.customizeUiComponent(this.logTable);
        callbacks.customizeUiComponent(scrollPane);
        callbacks.customizeUiComponent(controlPanelUI);
        callbacks.customizeUiComponent(jp);
        callbacks.customizeUiComponent(this.tabs);

        // 注册监听器
        callbacks.addSuiteTab(this);
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);

        // 表格行选择监听
        this.logTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) return;
                int selectedRow = logTable.getSelectedRow();
                if (selectedRow < 0 || selectedRow >= log.size()) return;
                LogEntry logEntry = log.get(selectedRow);
                try {
                    refs.requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
                    refs.responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
                    refs.requestViewerLow.setMessage(logEntry.requestResponse_1.getRequest(), true);
                    refs.responseViewerLow.setMessage(logEntry.requestResponse_1.getResponse(), false);
                    refs.requestViewerUnauth.setMessage(logEntry.requestResponse_2.getRequest(), true);
                    refs.responseViewerUnauth.setMessage(logEntry.requestResponse_2.getResponse(), false);
                    currentlyDisplayedItem = logEntry.requestResponse;
                    currentlyDisplayedItem_1 = logEntry.requestResponse_1;
                    currentlyDisplayedItem_2 = logEntry.requestResponse_2;
                } catch (Exception ex) {
                    stdout.println("展示选中行数据时发生错误: " + ex.getMessage());
                }
            }
        });

        // 加载持久化配置
        configManager.loadAfterUI();
    }

    // ==================== 认证区域工具方法 ====================

    String getAuthTextAreaText(int index) {
        if (index == 0 && refs.accountACredField != null) {
            return refs.accountACredField.getText();
        } else if (index == 1 && refs.accountBCredField != null) {
            return refs.accountBCredField.getText();
        }
        return "";
    }

    void setAuthTextAreaEditable(int index, boolean editable) {
        if (index == 0 && refs.accountACredField != null) {
            refs.accountACredField.setEditable(editable);
        } else if (index == 1 && refs.accountBCredField != null) {
            refs.accountBCredField.setEditable(editable);
        }
    }

    // ==================== 清空数据 ====================

    void clearAllData() {
        vulnDetector.clearAllData();
    }

    // ==================== IHttpListener ====================

    public void processHttpMessage(final int toolFlag, boolean messageIsRequest, final IHttpRequestResponse messageInfo) {
        if (this.switchs != 1 || toolFlag != 4 || messageIsRequest) {
            return;
        }

        // 过滤器检查
        if (requestFilter.shouldFilter(messageInfo)) {
            return;
        }

        // 检查域名过滤：只检测选中的域名
        if (!selectedDomain.isEmpty()) {
            try {
                String host = helpers.analyzeRequest(messageInfo).getUrl().getHost();
                if (!selectedDomain.equals(host)) {
                    return;
                }
            } catch (Exception e) {
                return;
            }
        }

        synchronized (this.log) {
            try {
                vulnDetector.checkVul(messageInfo, toolFlag);
            } catch (Exception e) {
                e.printStackTrace();
                this.stdout.println(e);
            }
        }
    }

    // ==================== IScannerCheck（空实现） ====================

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return existingIssue.getIssueName().equals(newIssue.getIssueName()) ? -1 : 0;
    }

    // ==================== IMessageEditorController ====================

    public byte[] getRequest() {
        return this.currentlyDisplayedItem != null ? this.currentlyDisplayedItem.getRequest() : new byte[0];
    }

    public byte[] getResponse() {
        return this.currentlyDisplayedItem != null ? this.currentlyDisplayedItem.getResponse() : new byte[0];
    }

    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem != null ? this.currentlyDisplayedItem.getHttpService() : null;
    }

    // ==================== ITab ====================

    public String getTabCaption() {
        return "deYue";
    }

    public Component getUiComponent() {
        return this.splitPane;
    }

    // ==================== IContextMenuFactory ====================

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return contextMenu.createMenuItems(invocation);
    }

    // ==================== AbstractTableModel ====================

    public int getRowCount() {
        return this.log.size();
    }

    public int getColumnCount() {
        return 6;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
        case 0:  return "#";
        case 1:  return "类型";
        case 2:  return "URL";
        case 3:  return "账号B相似度";
        case 4:  return "未授权相似度";
        case 5:  return "检测结果";
        default: return "";
        }
    }

    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = this.log.get(rowIndex);
        switch (columnIndex) {
        case 0:  return Integer.valueOf(logEntry.id);
        case 1:  return logEntry.method;
        case 2:  return logEntry.url;
        case 3:  return logEntry.lowSim;
        case 4:  return logEntry.unauthorizedSim;
        case 5:  return logEntry.detectionResult;
        default: return "";
        }
    }

    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    // ==================== 排序 ====================

    private void sortByColumn(int columnIndex, boolean ascending) {
        if (log.isEmpty()) return;

        if (lastSortedColumn == columnIndex) {
            ascending = !lastSortAscending;
        }
        lastSortedColumn = columnIndex;
        lastSortAscending = ascending;

        final int col = columnIndex;
        final boolean asc = ascending;

        Collections.sort(log, new Comparator<LogEntry>() {
            @Override
            public int compare(LogEntry o1, LogEntry o2) {
                int result = 0;
                switch (col) {
                case 0: result = Integer.compare(o1.id, o2.id); break;
                case 1: result = o1.method.compareTo(o2.method); break;
                case 2: result = o1.url.compareTo(o2.url); break;
                case 3: result = o1.lowSim.compareTo(o2.lowSim); break;
                case 4: result = o1.unauthorizedSim.compareTo(o2.unauthorizedSim); break;
                case 5: result = o1.detectionResult.compareTo(o2.detectionResult); break;
                default: result = 0;
                }
                return asc ? result : -result;
            }
        });

        fireTableDataChanged();
    }
}
