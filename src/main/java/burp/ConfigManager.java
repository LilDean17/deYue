package burp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.Properties;
import javax.swing.SwingUtilities;

/**
 * 配置管理器
 */
class ConfigManager {

    private final BurpExtender extender;
    private final GuiRefs refs;
    private final PrintWriter stdout;

    private static final String CONFIG_FILE = "deYue_config.properties";

    ConfigManager(BurpExtender extender, GuiRefs refs, PrintWriter stdout) {
        this.extender = extender;
        this.refs = refs;
        this.stdout = stdout;
    }

    void save() {
        try {
            Properties props = new Properties();
            props.setProperty("switchs", String.valueOf(extender.switchs));
            props.setProperty("data_2", extender.data_2);
            props.setProperty("accountA_cred", extender.accountA_cred);
            props.setProperty("accountB_cred", extender.accountB_cred);
            props.setProperty("selectedDomain", extender.selectedDomain);

            String configPath = extender.callbacks.getExtensionFilename();
            if (configPath != null) {
                File configFile = new File(new File(configPath).getParent(), CONFIG_FILE);
                FileOutputStream out = new FileOutputStream(configFile);
                props.store(out, "deYue Configuration");
                out.close();
            }
        } catch (Exception e) {
            stdout.println("保存配置时发生错误: " + e.getMessage());
        }
    }

    void load() {
        try {
            String configPath = extender.callbacks.getExtensionFilename();
            if (configPath != null) {
                File configFile = new File(new File(configPath).getParent(), CONFIG_FILE);
                if (configFile.exists()) {
                    Properties props = new Properties();
                    FileInputStream in = new FileInputStream(configFile);
                    props.load(in);
                    in.close();

                    // 插件加载时强制不自动启动，避免配置残留导致误判流量
                    extender.switchs = 0;
                    String loadedData2 = props.getProperty("data_2", null);
                    if (loadedData2 != null && !loadedData2.isEmpty()) {
                        extender.data_2 = loadedData2;
                    }
                    // 配置文件为空或不存在时，保留字段默认值 "Cookie\nAuthorization\nToken\nUsertoken"
                    extender.accountA_cred = props.getProperty("accountA_cred", "");
                    extender.accountB_cred = props.getProperty("accountB_cred", "");
                    extender.selectedDomain = props.getProperty("selectedDomain", "");
                }
            }
        } catch (Exception e) {
            stdout.println("恢复配置时发生错误: " + e.getMessage());
        }
    }

    void loadAfterUI() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                load();
                updateUIFromConfig();
            }
        });
    }

    void updateUIFromConfig() {
        try {
            if (refs.chkbox1 != null) {
                refs.chkbox1.setSelected(extender.switchs == 1);
            }
            if (refs.accountACredField != null) {
                refs.accountACredField.setText(extender.accountA_cred);
            }
            if (refs.accountBCredField != null) {
                refs.accountBCredField.setText(extender.accountB_cred);
            }
            if (extender.unauthorizedTextArea != null) {
                extender.unauthorizedTextArea.setText(extender.data_2);
            }

            // 凭据字段始终可编辑（修复：之前根据 switchs 状态设为不可编辑，导致选完凭据后无法修改）
            if (refs.accountACredField != null) refs.accountACredField.setEditable(true);
            if (refs.accountBCredField != null) refs.accountBCredField.setEditable(true);
        } catch (Exception e) {
            stdout.println("更新UI状态时发生错误: " + e.getMessage());
        }
    }
}
