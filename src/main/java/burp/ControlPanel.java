package burp;

import java.awt.GridLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * 左侧控制面板
 */
class ControlPanel {

    private final BurpExtender extender;
    private final GuiRefs refs;
    private final ConfigManager configManager;

    ControlPanel(BurpExtender extender, GuiRefs refs, ConfigManager configManager) {
        this.extender = extender;
        this.refs = refs;
        this.configManager = configManager;
    }

    JPanel build() {
        JPanel jps = new JPanel();
        jps.setLayout(new GridLayout(3, 1, 3, 3));

        JLabel jls = new JLabel("插件名：deYue");
        JLabel jls_2 = new JLabel("版本：deYue V" + extender.xy_version);
        refs.chkbox1 = new JCheckBox("启动插件");

        refs.chkbox1.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (refs.chkbox1.isSelected()) {
                    extender.switchs = 1;
                    extender.setAuthTextAreaEditable(0, false);
                    extender.setAuthTextAreaEditable(1, false);
                } else {
                    extender.switchs = 0;
                    extender.setAuthTextAreaEditable(0, true);
                    extender.setAuthTextAreaEditable(1, true);
                }
                configManager.save();
            }
        });

        jps.add(jls);
        jps.add(jls_2);
        jps.add(refs.chkbox1);

        return jps;
    }
}
