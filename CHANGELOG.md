# Changelog

所有重要的变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且该项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [3.3.0] - 2025-11-26

### 架构重构与功能增强

本次发布是一次全面的架构重构版本，重点优化代码结构、增强安全性、完善测试覆盖，并新增多项实用功能。

#### 🏗️ 架构重构

**代码结构重组**
- 按功能职责重组包结构，提升代码可维护性：
  - `core/` - 核心扩展类（DetSql、MyHttpHandler、MyExtensionUnloadingHandler）
  - `config/` - 配置管理（ConfigManager、ConfigValidator、DetSqlConfig、DetSqlYamlConfig、DefaultConfig）
  - `injection/` - 注入策略（InjectionStrategyManager 及各类注入策略实现）
  - `model/` - 数据模型（PocLogEntry、PocTableModel、SourceLogEntry、SourceTableModel）
  - `ui/` - UI 组件（DetSqlUI、ConfigPanel、CodeToolPanel、StatisticsPanel、MyFilterRequest 等）
  - `util/` - 工具类（MyCompare、Statistics、StringUtils、RegexUtils、SafeString、LogSanitizer 等）
  - `logging/` - 日志系统（DetSqlLogger、LogHelper、LogLevel）
- 移除根目录下的 28 个混杂文件，职责划分更清晰
- 删除过时文件：`ThreadSafeAttackMap.java`、旧版 `DefaultConfig.java` 等

**注入策略模式重构**
- 新增 `InjectionStrategy` 接口和 `AbstractInjectionStrategy` 抽象类
- 实现多种注入策略：
  - `StringInjection` - 字符串型注入检测
  - `NumericInjection` - 数字型注入检测
  - `BooleanInjection` - 布尔型注入检测
  - `ErrorBasedInjection` - 错误型注入检测
  - `OrderByInjection` - ORDER BY 注入检测
  - `CustomInjection` - 自定义注入检测
- 新增 `InjectionStrategyManager` 统一管理注入策略
- 消除 `MyHttpHandler` 中 5000+ 行重复代码

#### ✨ 新增功能

**配置管理增强**
- `ConfigManager.java` - 统一配置管理器，支持 YAML 配置文件
- `ConfigValidator.java` - 配置验证器，确保配置合法性
- `DetSqlYamlConfig.java` - YAML 配置模型
- 支持路径黑名单、域名过滤、参数黑名单等高级配置

**UI 功能增强**
- `DetSqlUI.java` - 全新主界面，支持多 Tab 布局
- `ConfigPanel.java` - 配置面板，提供可视化配置管理
- `CodeToolPanel.java` - 代码工具面板
- `StatisticsPanel.java` - 统计面板，实时展示检测统计
- `UIBindingHelper.java` - UI 双向绑定机制
- `BindingContext.java` - 绑定上下文管理
- `LanguageManager.java` - 语言管理器，支持国际化切换
- `LanguageChangeListener.java` - 语言变更监听器

**工具类增强**
- `StringUtils.java` - 字符串工具类
- `RegexUtils.java` - 安全的正则表达式工具，提供超时保护
- `SafeString.java` - 安全的字符串操作，防止索引越界
- `LogSanitizer.java` - 日志脱敏工具，保护敏感信息
- `StructuralSignature.java` - 结构化签名工具
- `LRUCache.java` - LRU 缓存实现

**国际化支持**
- 资源文件迁移：`Messages_*.properties` → `i18n/messages_*.properties`
- 增强 `Messages.java`，支持动态语言切换
- 完善中英文翻译

#### 🔒 安全加固

**修复关键安全漏洞**
- 修复配置文件路径遍历漏洞（P0）
- 修复内部可变集合直接暴露问题（P0）
- 修复 ReDoS（正则表达式拒绝服务）漏洞（P1）
- 修复索引越界问题（P1）
- 修复 parseDelimitedString 方法的安全过滤绕过问题
- 修复域名过滤 endsWith() 导致的子域名绕过漏洞
- 修复 reJson() 和 reUrlJson() 的数组越界问题

**安全工具类**
- `RegexUtils` 提供 200ms 超时保护机制
- `SafeString` 防止索引越界
- `LogSanitizer` 自动脱敏敏感参数（password、token、session 等）

#### 🐛 Bug 修复

**P0 级别修复**
- 修复 Table2 无法查看完整响应的问题（使用 WeakReference 平衡内存与功能）
- 修复路径黑名单不生效问题（调整过滤顺序）
- 修复配置保存失效问题（统一保存逻辑）
- 改进配置保存用户体验（优化成功/错误提示）

**其他修复**
- 修复参数索引对齐问题
- 修复并发安全问题（使用 putIfAbsent、ConcurrentHashMap.newKeySet）
- 修复内存泄漏问题（实现 LRU 缓存和资源清理）
- 修复 JSON/XML 偏移量计算错误
- 修复空指针异常风险
- 修复资源泄漏问题
- 消除所有编译警告

#### ⚡ 性能优化

- 移除并发扫描单线程瓶颈，预期性能提升 50-90%
- UI 绑定机制性能优化（消除不必要的监听器创建）
- 优化 MyHttpHandler.processRequestInternal 方法，降低嵌套深度至 3 层
- 预编译静态正则表达式，性能提升 50 倍
- 实现参数黑名单全过滤检查优化
- 简化相似度计算边界检查逻辑

#### 🧪 测试覆盖率大幅提升

**新增 40+ 测试类**
- 配置管理测试：`DetSqlConfigTest`、`DetSqlConfigValidationTest`、`ConfigValidatorTest`、`ConfigManagerSecurityTest`、`ConfigSaveBugDiagnosticTest` 等
- 核心功能测试：`DetSqlInitializationTest`、`MyHttpHandlerIntegrationTest`、`MyHttpHandlerConcurrencySmokeTest` 等
- 过滤器测试：`DomainFilterTest`、`PathBlacklistTest`、`SuffixAndParamsFilterTest`、`MyFilterRequestTest`、`ManualRequestFilterTest` 等
- 工具类测试：`RegexUtilsTest`、`SafeStringTest`、`StringUtilsTest`、`LogSanitizerTest`、`StructuralSignatureTest` 等
- 性能测试：`MyCompareBoundaryTest`、`MyCompareComprehensiveTest`、`UIBindingPerformanceTest` 等
- 并发与内存测试：`ConcurrencyTest`、`MemoryLeakTest`、`PocLogEntryMemoryTest`、`AttackMapCacheTest`、`DualQueueArchitectureTest` 等
- UI 测试：`UIBindingHelperTest`、`CodeToolPanelUITest`、`LanguageManagerTest` 等
- 基准测试：`LevenshteinBenchmark`、`ReDoSBenchmark`、`PerformanceReportGenerator`、`PerformanceTestUtils` 等
- 其他测试：`CollectParamNamesTest`、`ParseDelimitedStringIntegrationTest`、`ProxyHistorySendBlacklistTest`、`UserReportedDomainsTest`、`FileLeak_copyToTempFile_Test`、`SourceTableModelCapacityTest`、`BlacklistConfigurationDiagnosticTest` 等

**测试结果**
- 所有测试通过，构建成功
- 验证了系统的线程安全性、内存管理、性能优化效果

#### 🔧 CI/CD

- 新增 `benchmarks.yml` - 性能基准测试工作流
- 更新 `ci.yml` 和 `codeql.yml` 工作流配置
- 优化 workflow 触发条件，添加 paths 过滤

#### 📚 文档

- 新增 `docs/I18N_CODE_REVIEW_CHECKLIST.md` - 国际化代码审查清单
- 新增 `docs/I18N_DEVELOPMENT_GUIDE.md` - 国际化开发指南
- 新增 `docs/TABLE_MAPPING_BUG_ANALYSIS.md` - Table 映射 Bug 分析
- 完善 `CHANGELOG.md`，详细记录所有变更
- 更新 `README.md`

#### 📊 统计数据

- 118 个文件变更
- 新增代码：20,684 行
- 删除代码：4,635 行
- 净增加：16,049 行
- 代码质量大幅提升，架构更清晰

---

## [3.2.0] - 2025-11-05

### JSON参数支持增强

#### Added
- **JSON字符串参数检测**：支持对参数值中嵌套的JSON字符串进行SQL注入检测
- **深度参数解析**：能够识别和处理多层嵌套的JSON结构中的参数

#### Changed
- 重构 `MyHttpHandler.java` 的参数处理逻辑（775行变更）
- 优化 `ParameterModifier` 接口，增强对复杂数据类型的支持
- 改进 `ParameterModifiers` 类，提供更灵活的参数修改策略

---

## [3.1.0] - 2025-10-29

### 配置页面修复

#### Fixed
- **配置页面显示问题**：修复因国际化导致配置页面无法显示的问题 (#46)
  - 根本原因：CardLayout使用英文key注册组件，但tab标题会被国际化翻译
  - 解决方案：使用固定索引映射数组CARD_KEYS，通过tab索引获取对应key

---

## [3.0.0] - 2025-10-19

### 字符类型检测优化

#### Changed
- **字符类型判断逻辑调整**：优化SQL注入检测中的字符类型识别算法
- 改进 `MyCompare.java` 中的相似度比较逻辑
- 优化 `MyHttpHandler.java` 的检测流程
- 更新 `PocTableModel.java` 的数据展示逻辑

#### Added
- **GitHub Actions支持**：添加CI/CD工作流配置
- **代码质量提升**：修复CodeQL检测到的代码质量问题

---

## [2.9.0] - 2025-10-13

### 架构重构与代码质量提升

#### Added
- **新增 ParameterModifier 接口和实现类**：重构参数修改逻辑，提取统一的参数修改器架构
- **新增工具类**：
  - `DefaultConfig.java`：统一管理默认配置常量
  - `DetSqlConfig.java`：配置管理类，统一配置加载和保存
  - `ResponseExtractor.java`：响应数据提取工具
  - `Messages.java`：国际化消息支持
  - `ThreadSafeAttackMap.java`：线程安全的攻击映射封装
  - `Statistics.java`：统一的统计功能和漏洞聚合
- **日志系统**：
  - `DetSqlLogger.java`：集成日志系统
  - `LogHelper.java`：日志辅助工具
  - `LogLevel.java`：日志级别枚举（OFF/DEBUG/INFO/WARN/ERROR）
  - 支持编译时控制日志级别：`-Ddetsql.log.level`
  - 启动信息始终输出，无论日志级别如何
- **国际化支持**：
  - `messages_zh_CN.properties`：中文资源文件
  - `messages_en.properties`：英文资源文件
  - `detsql.properties`：配置文件
- **测试覆盖**：新增 11 个单元测试类
  - `DefaultConfigJsonErrPocsTest`：JSON 错误 POC 默认配置测试
  - `DetSqlDeriveJsonErrPocsTest`：JSON 错误 POC 派生测试
  - `MyCompareLengthDiffThresholdTest`：长度差阈值测试
  - `MyHttpHandlerBuildResultStringTest`：结果字符串构建测试
  - `MyHttpHandlerByteToHexTest`：字节转十六进制测试
  - `MyHttpHandlerConcurrencySmokeTest`：并发冒烟测试
  - `MyHttpHandlerErrSqlCheckTest`：错误 SQL 检查测试
  - `MyHttpHandlerIsNumericTest`：数值检测测试
  - `ParameterIndexAlignmentTest`：参数索引对齐测试
  - `QuickVerificationTest`：快速验证测试
  - `StatisticsVulnerabilityCountTest`：统计功能测试

#### Changed
- **核心重构**：
  - 统一注入检测方法：`testStringInjection`、`testNumericInjection`、`testBooleanInjection`、`testOrderInjection`、`testDiyInjection`
  - 消除 `MyHttpHandler` 中 5000+ 行重复代码，大幅提升可维护性
  - 删除 63 个无意义的 for 循环和大量魔法数字
  - 提取 UI 布局魔法数字为命名常量
  - 提取统一的文本转换监听器消除重复代码
  - 使用 Stream API 优化 `PocTableModel` 重复检查逻辑
- **漏洞统计优化**：
  - 漏洞计数使用唯一键（METHOD + host:port + path + paramName）替代 per-payload 计数
  - 默认端口标准化（http=80, https=443）
  - 聚合逻辑集中到 `Statistics.recordFromEntries(url, method, entries)`
  - `MyHttpHandler` 委托给统计层，避免业务逻辑泄漏
- **UI 优化**：
  - 调整 Dashboard SourceTab 列顺序，统一列名与 Burp Proxy 一致
  - ID 起始编号从 1 开始
  - 统一 Tested/Vulns 显示在同一行，优化布局
  - Vulns 计数器从 `Statistics.getVulnerabilitiesFound()` 读取，避免 payload 膨胀
  - Tested 计数器从 `Statistics.getRequestsProcessed()` 读取，避免 Repeater 中重复计数
- **配置管理**：
  - 实现 `DetSqlConfig` 统一配置加载和保存
  - 提取 `DefaultConfig` 统一管理默认配置常量
  - 消除配置加载重复代码
  - 使用 UTF-8 编码，正确引用 `DefaultConfig`
- **构建配置**：
  - 项目版本：2.7 → 2.9.0
  - groupId: DetSql → com.detsql
  - artifactId: DetSql → det-sql
  - 优化 `pom.xml` 遵循 Maven 最佳实践
  - 添加 `dependencyManagement` 统一依赖版本
  - 添加 `maven-enforcer-plugin` 确保构建一致性
  - 配置 `maven-surefire-plugin` 3.5.2 支持 JUnit 5

#### Fixed
- **参数索引对齐**：修复参数索引对齐问题，确保 Name 与实际注入字段一致
- **并发安全**：
  - 统一使用 `putIfAbsent` 初始化 `attackMap`，避免覆盖已存在列表
  - 将 `countId++` 和 `attackMap` 初始化移入锁内，消除竞态窗口
  - 使用 `ConcurrentHashMap.newKeySet` 替换 `HashSet` 提升并发安全性
  - 并发冒烟测试验证 ID 唯一性与 map 初始化
- **内存泄漏**：实现进度统计功能并清理过期数据
- **JSON/XML 处理**：修复 JSON/XML 偏移量计算错误
- **空指针异常**：
  - 修复 `timingData` 和 `body` 方法的空指针异常风险
  - 添加 null-guard 避免 NPE 并保持内存清理语义
- **资源泄漏**：修复资源泄漏并消除硬编码后缀重复
- **命名错误**：修复变量命名拼写错误（Chexk → Check）
- **编译警告**：解决编译警告和构建配置问题

#### Performance
- **正则表达式优化**：预编译静态正则表达式，性能提升 50 倍
- **参数过滤优化**：实现参数黑名单全过滤检查优化
- **代码可读性**：优化 Optional 使用以提升代码可读性
- **相似度计算**：
  - 简化 `MyCompare.calculateSimilarity()` 边界检查逻辑
  - 长度差阈值短路返回 0.0，避免大差异响应被误判为相似

#### Documentation
- 添加 `CHANGELOG.md` 记录版本变更
- 更新 `README.md` 添加编译配置说明

#### Statistics
- 37 个文件修改
- 新增代码：5640 行
- 删除代码：4914 行
- 净增加：726 行（代码质量大幅提升）

---

## [2.7.0] - 2025-10-09

### 性能优化与安全加固

#### Performance
- **UI 性能优化**（10-25倍提升）：
  - 修复 UI 卡顿问题，使用 `SwingUtilities.invokeLater()` 确保 EDT 线程安全
  - 优化 `TableModel` 更新机制，避免不必要的 UI 刷新
  - 100个数据包：从卡顿500ms优化到<50ms（10倍提升）
  - 1000个数据包：从假死5s+优化到~200ms（25倍提升）

#### Security
- **依赖安全更新**：
  - gson: 2.2.4 → 2.11.0（修复 CVE-2022-25647 DoS 漏洞）
  - commons-text: 1.9 → 1.13.0（修复 CVE-2022-42889 RCE 漏洞）
  - commons-lang3: 3.12.0 → 3.18.0（性能优化）
  - montoya-api: LATEST → 2025.8（使用具体版本号）
  - 漏洞数量：2 → 0

#### Fixed
- **编码问题修复**：
  - 修复 HTTP 请求响应中文乱码问题
  - 使用 Montoya API 的智能编码检测机制
  - 支持 GBK、GB2312 等多种编码格式
  - 修复 141 处错误的字符串编码转换
- **扩展加载修复**：
  - 添加 `maven-shade-plugin` 构建 fat jar
  - 正确打包所有依赖库（gson、commons-lang3、commons-text）
  - 修复 'Extension class is not a recognized type' 错误
  - JAR 大小：92KB → 1.4MB（包含所有依赖）

#### Changed
- 项目版本：2.6 → 2.7
- 消除 LATEST 版本号的构建不稳定性
- 所有依赖使用具体版本号

---

## [2.6.0] - Earlier Release
- 基础功能实现

## [2.5.0] - Earlier Release
- 基础功能实现

## [2.4.0] - Earlier Release
- 基础功能实现

## [2.3.0] - Earlier Release
- 基础功能实现

## [2.2.0] - Earlier Release
- 基础功能实现

## [2.1.0] - Earlier Release
- 基础功能实现

## [2.0.0] - Earlier Release
- 基础功能实现

## [1.9.0] - Earlier Release
- 基础功能实现

## [1.8.0] - Earlier Release
- 基础功能实现

## [1.7.0] - Earlier Release
- 基础功能实现

## [1.6.0] - Earlier Release
- 基础功能实现