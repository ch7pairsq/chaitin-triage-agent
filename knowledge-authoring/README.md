# 三领域安全运营知识

该目录维护车联网平台、物联网平台和工业互联网平台的安全运营知识。知识来源说明统一为“内部安全运营经验整理”。每条知识必须完成人工复核后才能从 `draft` 改为 `approved`，运行知识构建只接收 `approved` 记录。

`test-fixtures/` 只用于验证知识在证据充分、授权或良性、证据不足、复合或重复活动四类输入下的行为，不进入运行知识包，也不作为历史事件数量。

```powershell
cd knowledge-authoring
npm run generate
npm run check
npm test
```

复核结果记录在 `reviews.json`。`review:annotate` 为每条知识写入结构、分类映射、Wazuh 可观察性、证据门、反例和失效边界检查项，并给出针对该攻击类型和领域范围的复核批注；它不会填写批准人，也不会改变 `draft` 状态。只有同时填写 `reviewStatus=approved`、`reviewedBy`、`reviewMarker` 和 `reviewedAt` 的记录才可发布；修改复核登记后重新执行 `npm run generate` 与 `npm run check`。`npm run build:runtime` 在批准数量不是 99 时会直接失败。

```powershell
npm run generate
npm run review:annotate
npm run check
```
