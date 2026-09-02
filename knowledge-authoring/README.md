# 三领域安全运营知识

该目录维护车联网平台、物联网平台和工业互联网平台的安全运营知识。每条知识同时包含人工可读经验和 `executableRule`，由 SecurityOps 的同一规则解释器在 `MatchKnowledge`、`EvaluatePolicy` 和测试中实际执行。运行知识构建只接收完成人工复核的 `approved` 记录。

`sources.json` 登记公开知识库、厂商文档和仓库内边界用例集。公开标准只用于攻击语义与观察点映射，不能单独产生结论；具体阈值必须在 `thresholdBasis` 中列出来源、保守边界和部署后校准规则。

`test-fixtures/` 覆盖确认、授权或良性排除、证据不足、复合或重复活动四类输入，共 396 条。测试会用生产规则解释器逐条执行，并验证移除知识、移除排除条件或越过阈值边界时结果确实变化。这些用例不进入运行知识包，也不作为生产准确率或历史事件数量。

```powershell
cd knowledge-authoring
npm run check
npm test
npm run build:runtime
```

复核结果记录在 `reviews.json`。`review:annotate` 只刷新复核批注和检查项，不生成或改写知识，不填写批准人，也不改变 `draft` 状态。只有同时填写 `reviewStatus=approved`、`reviewedBy`、`reviewMarker` 和 `reviewedAt` 的记录才可发布；修改知识后应重新复核可执行条件、阈值来源、误报/漏报、绕过点和不可用字段，再运行全部校验。`npm run build:runtime` 在批准数量不是 99 时会直接失败。

知识记录是唯一编写源，不提供批量模板生成器，避免用通用模板覆盖逐条复核内容。新增或修改记录时直接编辑对应 JSON，并保持以下安全语义：

- `requiredFacts` 缺失：`insufficient`，请求补充证据；
- `excludeWhen` 命中：`excluded`，保留人工工单；
- `confirmWhen` 完整命中：`confirmed`，升级并人工复核；
- 事实完整但未命中：`not_matched`，进入人工分类；
- 单一 Wazuh 等级、来源地址或事件类型提示不能单独定性。

```powershell
npm run review:annotate
npm run check
npm test
npm run build:runtime
```
