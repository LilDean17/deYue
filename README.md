# deYue

**deYue** — Burp Suite 越权检测插件，帮助你快速识别接口中的 IDOR 和未授权访问漏洞。

---

## 核心特性

- **自动扫描 Proxy 历史提取多账号凭证**：输入域名后自动从 Proxy 历史中提取使用频率最高的两个不同账号的完整认证头（Cookie / Token / Authorization），无需手动复制粘贴。
- **基于响应相似度区分越权类型**：对同一请求发送高权限（A）、低权限（B）、未授权（W）三组请求，通过 Levenshtein 相似度算法对比响应内容：
  - **A vs B 相似度高** → 判定为 **IDOR**（水平越权）
  - **A vs 未授权 相似度高** → 判定为 **Unauthorized**（未授权访问）
  - 可同时命中两者
- **域名实时过滤补全**：输入域名时实时匹配已扫描域名，下拉列表一键选择。
- **一键重新加载**：刷新 Proxy 历史，更新域名列表。
- **无 B 账号凭据时跳过 IDOR 判定**：未配置低权限账号时 IDOR 列显示 N/A，仅保留未授权访问判定，避免无意义的比对结果干扰判断。
- **大响应优化**：响应体超过 50KB 时只比较头 10KB + 尾 5KB，Levenshtein 使用滚动数组降低内存占用。
- **HTML 智能预处理**：自动识别 HTML 响应并剥除标签后比较，排除页面结构差异干扰。
- **MD5 参数名去重**：基于"URL 路径 + 方法 + 参数名"去重，同一接口不同参数值不会重复检测。
- **EDT 线程安全**：Swing 组件更新全部在 EDT 执行，后台线程通过 volatile 缓存读取数据。

## 安装使用

1. 下载 [`deYue-1.0.jar`](https://github.com/LilDean17/deYue/releases)
2. Burp Suite → Extensions → Add → 选择 `deYue-1.0.jar`
3. 首次启动后插件会自动生成 `deYue_config.properties` 配置文件

## 使用流程

1. 确保 Burp Proxy 已捕获目标站点的请求流量
2. 在右侧"目标域名"输入框输入域名，从下拉列表选择
3. 插件自动扫描 Proxy 历史并填充账号 A（高权限）和账号 B（低权限）的凭证
4. 在左侧勾选"启动插件"
5. 在 Proxy 历史中右键请求 → "发送到 deYue 检测"
6. 检测结果自动显示在表格中，包含越权类型和相似度

## 检测逻辑

| 场景 | 判定条件 | 结果 |
|---|---|---|
| 无参请求 | A vs 未授权相似度 ≥ 98% | `unauthorized` |
| 有参请求 | A vs B 相似度 ≥ 98% | `idor` |
| 有参请求 | A vs 未授权相似度 ≥ 98% | `unauthorized` |
| 有参请求 | 两者同时命中 | `idor+unauthorized` |

## 配置文件

首次启动后插件会自动生成 `deYue_config.properties`，保存以下配置：

- 插件开关状态
- 未授权认证字段列表（默认：Cookie、Authorization、Token、Usertoken）
- 账号 A / B 的认证凭据
- 选中的目标域名

手动修改配置文件后重启插件即可生效。

## 技术栈

- Java 8+
- Burp Extender API 2.3
- 纯 Java 实现，无外部依赖

## 关于原版

deYue 基于 [xiaYue_Pro](https://github.com/your-repo) 二开，主要改进：

- 自动扫描 Proxy 历史提取凭证，无需手动输入
- 基于响应相似度区分 IDOR / 未授权，而非简单长度对比
- 域名实时过滤 + 一键重新加载
- 大响应性能优化 + HTML 智能预处理
- B 账号未配置防误报
- EDT 线程安全修复

## License

MIT
