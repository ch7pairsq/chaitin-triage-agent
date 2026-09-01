import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const taxonomy = JSON.parse(readFileSync(path.join(ROOT, "taxonomy.json"), "utf8"));
const knowledgeDirectory = path.join(ROOT, "knowledge");
const fixtureDirectory = path.join(ROOT, "test-fixtures");
const reviewRegistryPath = path.join(ROOT, "reviews.json");
const reviewRegistry = (() => {
  try {
    const document = JSON.parse(readFileSync(reviewRegistryPath, "utf8"));
    return new Map((document.reviews ?? []).map((review) => [review.knowledgeId, review]));
  } catch (error) {
    if (error.code === "ENOENT") return new Map();
    throw error;
  }
})();

const FAMILY = {
  availability: {
    signals: ["服务请求量或资源使用突增", "同一服务持续超时或拒绝连接", "受影响资产健康状态下降"],
    evidence: ["时间窗口内请求与资源曲线", "受影响服务错误日志", "来源分布与目标服务对应关系"],
    counterexamples: ["经审批的容量测试", "上游依赖故障导致的连锁超时"]
  },
  network_visibility: {
    signals: ["网卡进入异常监听状态", "非授权抓包工具或原始套接字活动", "明文协议敏感字段暴露迹象"],
    evidence: ["进程与网卡状态证据", "网络流量或终端检测证据", "资产授权记录"],
    counterexamples: ["经审批的网络诊断", "受控监测探针"]
  },
  name_resolution: {
    signals: ["解析结果与可信基线不一致", "DNS 配置或 hosts 文件异常修改", "异常 DNS 服务器或响应来源"],
    evidence: ["解析请求与响应记录", "配置变更审计", "域名与目标资产基线"],
    counterexamples: ["经审批的 DNS 迁移", "容灾切换导致的短时解析变化"]
  },
  authentication: {
    signals: ["短时间连续认证失败", "同一来源尝试多个账号或口令", "失败后出现成功登录"],
    evidence: ["认证失败与成功日志", "来源地址与设备身份", "账号状态和授权变更记录"],
    counterexamples: ["批量设备换密失败", "身份源同步异常"]
  },
  injection: {
    signals: ["输入中出现与协议不符的控制语法", "应用或数据库返回解析异常", "输入与异常调用链在时间上关联"],
    evidence: ["规范化请求字段", "应用与数据层错误日志", "目标接口和参数语义"],
    counterexamples: ["安全测试工具的授权请求", "业务字段合法包含特殊字符"]
  },
  execution: {
    signals: ["服务进程派生异常解释器或系统工具", "非发布窗口出现可执行内容", "命令、文件与网络回连形成时间关联"],
    evidence: ["进程树与命令行", "文件哈希及创建来源", "应用调用链和网络连接"],
    counterexamples: ["经审批的运维脚本", "发布系统执行的受控命令"]
  },
  web: {
    signals: ["请求包含跨站脚本或跨域调用特征", "服务端访问非预期地址", "浏览器或应用审计出现异常执行"],
    evidence: ["原始与规范化请求", "响应安全上下文", "目标接口权限和调用链"],
    counterexamples: ["安全扫描器授权测试", "业务富文本经过正确编码"]
  },
  business_logic: {
    signals: ["业务状态转换不符合流程约束", "同一业务动作被重放或越序执行", "额度、身份与动作之间不一致"],
    evidence: ["完整业务操作链", "身份与授权快照", "幂等键和状态变更审计"],
    counterexamples: ["经审批的补偿任务", "业务系统重试但幂等生效"]
  },
  access_control: {
    signals: ["无有效身份访问受保护资源", "低权限主体访问高权限对象", "鉴权失败后仍返回业务数据"],
    evidence: ["身份认证与授权日志", "资源权限策略", "请求和响应状态"],
    counterexamples: ["明确配置的公开接口", "临时授权仍在有效期内"]
  },
  disclosure: {
    signals: ["响应或日志出现凭据、密钥或敏感标识", "非授权主体批量读取数据", "配置或备份文件被访问"],
    evidence: ["数据分类与访问主体", "响应或文件访问审计", "脱敏策略和授权记录"],
    counterexamples: ["已脱敏的运营报表", "经审批的数据导出"]
  },
  memory_safety: {
    signals: ["进程崩溃与异常内存访问", "输入长度异常并触发服务重启", "崩溃前后出现控制流异常"],
    evidence: ["崩溃转储或终端检测证据", "触发请求与进程日志", "组件版本和修复状态"],
    counterexamples: ["硬件故障导致的随机崩溃", "已知非安全软件缺陷"]
  },
  privilege: {
    signals: ["普通主体获得管理员或系统权限", "高权限令牌异常创建或使用", "权限变更后执行敏感动作"],
    evidence: ["权限变更审计", "父子进程和身份上下文", "敏感动作记录"],
    counterexamples: ["经审批的运维提权", "自动化平台的短期授权"]
  },
  device: {
    signals: ["固件、启动链或设备身份异常", "调试接口在非维护期启用", "设备指令与平台授权不一致"],
    evidence: ["固件与配置完整性", "设备身份和指令审计", "维护窗口与审批记录"],
    counterexamples: ["经审批的固件升级", "工厂测试模式仍在授权范围"]
  },
  worm: {
    signals: ["多个资产出现相同异常并横向扩散", "同一进程或文件触发连续网络连接", "新增持久化与传播动作关联"],
    evidence: ["跨资产时间线", "文件、进程和网络关联", "传播入口及受影响范围"],
    counterexamples: ["集中软件分发", "批量资产管理任务"]
  },
  trojan: {
    signals: ["非授权持久化或隐蔽进程", "异常命令控制或数据外传", "可执行文件来源与业务发布不一致"],
    evidence: ["文件哈希与签名", "进程树、持久化和网络证据", "发布基线与资产上下文"],
    counterexamples: ["经审批的远程运维工具", "合法代理或监控组件"]
  },
  other: {
    signals: ["现有分类无法覆盖的异常行为", "证据来源或语义仍不完整"],
    evidence: ["原始告警与上下文", "资产负责人说明", "补充遥测结果"],
    counterexamples: ["告警字段映射错误", "规则升级引入的分类漂移"]
  }
};

const ATTACK_DETAILS = {
  denial_of_service: ["同一目标出现并发连接、队列或资源耗尽且服务可用性同步下降", "目标服务资源曲线、错误率与来源分布的同窗关联", "计划内容量压测具有审批单、固定来源和明确时间窗", "负载均衡、API 网关或网络流量审计", "确认资源耗尽是否由攻击流量直接造成"],
  sniffing: ["非授权进程打开原始套接字、抓包接口或网卡混杂模式", "进程身份、网卡模式变更与抓包文件创建记录", "受控运维探针在批准资产和维护窗口内运行", "终端进程审计与交换网络镜像记录", "确认抓包主体、授权范围与敏感数据暴露情况"],
  dns_hijacking: ["解析结果偏离可信基线并伴随 DNS 配置、hosts 或解析响应异常", "同一域名的请求响应、配置变更和可信解析基线", "备案中的容灾切换与解析变更单完全一致", "递归 DNS 查询日志与配置审计", "确认异常解析的控制点及受影响终端范围"],
  brute_force: ["同一主体或来源连续认证失败后出现成功登录或账号锁定", "认证失败序列、成功登录、设备身份和账号状态", "批量设备换密失败与已批准变更窗口一致", "身份平台审计与账号锁定记录", "确认来源聚合、账号范围及成功登录归属"],
  sql_injection: ["数据库控制语法进入业务参数并触发查询结构或数据库错误异常", "规范化请求、数据库审计和应用调用链的参数对应关系", "授权安全验证请求与登记的测试范围一致", "数据库审计与应用参数日志", "确认输入确实改变查询语义而非普通特殊字符"],
  webshell: ["Web 进程执行新落地脚本、异常子进程或非发布文件", "Web 访问日志、文件哈希、进程树和发布基线", "发布系统在受控目录写入已签名文件", "文件完整性、EDR 进程树与 Web 访问日志", "确认文件入口、执行结果和持久化行为"],
  xss: ["未编码脚本内容从输入进入响应并在客户端安全上下文中执行", "原始请求、输出编码结果、响应内容和客户端执行证据", "富文本经过白名单净化且未形成可执行上下文", "WAF、应用响应与浏览器侧安全遥测", "确认输出上下文和客户端执行链"],
  request_forgery: ["请求代表非预期主体访问内网资源或执行未经授权的跨站动作", "请求发起主体、目标地址、会话授权和服务端出站记录", "受控服务发现或业务回调访问已登记目标", "服务端出站流量、会话审计与反向代理日志", "区分服务端请求伪造和跨站请求伪造的主体边界"],
  xml_external_entity: ["XML 解析触发外部实体读取、文件访问或非预期网络请求", "原始 XML、解析器配置、文件或出站访问记录", "受控离线解析器禁用外部实体且没有外部访问", "应用解析日志、文件审计与出站网络记录", "确认解析器实际解析外部实体而非仅出现字符串"],
  command_execution: ["业务输入被拼接为系统命令并产生子进程或命令副作用", "输入参数、应用调用链、子进程命令行和执行结果", "批准的运维接口执行固定命令模板", "进程审计、应用参数日志与命令执行日志", "确认用户输入到系统命令之间的数据流"],
  code_execution: ["非预期代码进入解释器、模板、反序列化或脚本运行时并执行", "载荷、解释器调用栈、进程或内存行为和网络副作用", "发布系统加载已签名的业务脚本", "应用运行时审计、EDR 与调用链", "确认执行发生在应用运行时且非单纯命令调用"],
  business_logic_exploitation: ["业务状态被越序、重放或跨主体推进且违反流程约束", "完整业务操作链、幂等键、身份授权和状态快照", "补偿任务按设计重试且幂等结果保持一致", "业务审计、订单或设备指令状态记录", "确认安全影响来自流程约束绕过而非实现故障"],
  unauthorized_access: ["无有效授权的主体读取、修改或调用受保护对象", "认证上下文、授权策略、目标对象和请求响应", "明确登记为公开且不含受保护数据的接口", "身份授权审计与资源访问日志", "确认对象级和功能级权限边界"],
  information_disclosure: ["凭据、密钥、个人或设备敏感标识暴露给非授权主体", "数据分类、访问主体、响应或文件内容和脱敏策略", "经审批且已脱敏的数据导出", "数据访问审计、DLP 或响应内容记录", "确认暴露数据等级、接收主体和可利用性"],
  file_inclusion: ["路径参数使应用加载预期目录之外的本地或远程文件", "规范化路径、应用加载记录、文件访问和返回内容", "主题或插件系统加载白名单目录内签名文件", "文件访问审计、应用路由与出站网络记录", "区分目录遍历、文件读取和实际包含执行"],
  other_attack: ["现有分类无法覆盖且原始证据语义不足以安全归类", "原始告警、资产上下文、负责人说明和补充遥测", "字段映射错误或规则升级导致的分类漂移", "资产侧专项遥测与人工补充证据", "确认不能归入已有类别并记录待补充字段"],
  buffer_overflow: ["异常长度输入与进程崩溃、内存破坏或控制流异常同窗出现", "触发输入、崩溃转储、组件版本和修复状态", "硬件故障或已知非安全缺陷产生随机崩溃", "崩溃转储、EDR 内存事件与应用请求日志", "确认内存安全影响而非普通可用性故障"],
  privilege_escalation: ["低权限主体获得高权限令牌并随后执行敏感动作", "权限变更、身份上下文、父子进程和敏感动作记录", "自动化平台按审批签发短期高权限令牌", "身份权限审计、系统调用与进程树", "确认权限提升路径和提升后的实际能力"],
  system_code_execution: ["代码在内核、系统服务或高权限系统上下文中非预期执行", "系统服务调用链、内核或高权限进程证据和载荷来源", "签名驱动或系统更新在批准窗口内安装", "内核审计、系统服务日志与 EDR", "确认执行上下文达到系统级而非普通应用进程"],
  smart_device_system_attack: ["固件、启动链、调试接口或设备身份被未授权修改或使用", "固件签名、启动完整性、设备身份和指令审计", "工厂测试或固件升级处于有效授权窗口", "设备完整性证明、调试接口和平台指令日志", "确认设备侧变化与平台授权记录不一致"],
  network_worm: ["同一载荷或进程通过网络服务在多个资产间自动扩散", "跨资产时间线、漏洞或弱口令入口、文件进程与连接关联", "集中软件分发使用签名包和固定管理节点", "横向流量、EDR 和漏洞状态", "确认无需人工参与的网络传播机制"],
  mail_worm: ["恶意附件或链接借助邮件通讯录继续自动传播", "邮件头、附件哈希、进程行为和后续外发记录", "批准的群发通知不包含执行载荷", "邮件网关、终端进程和外发审计", "确认邮件是传播媒介且存在自动扩散"],
  p2p_worm: ["载荷写入共享目录并借助 P2P 协议或节点发现继续传播", "共享文件哈希、P2P 进程、节点连接和跨资产命中", "批准的点对点分发使用签名内容", "P2P 流量、文件审计与终端进程", "确认传播由 P2P 共享机制驱动"],
  im_worm: ["恶意链接或文件通过联系人或群聊自动转发并触发执行", "消息元数据、附件哈希、客户端进程和转发链", "批准的机器人广播没有恶意载荷", "即时通信审计与终端进程遥测", "确认自动转发链及客户端执行结果"],
  web_worm: ["站点脚本在用户访问后跨账号复制内容或继续传播", "页面内容、会话行为、脚本执行和跨用户传播链", "正常分享功能经授权且内容经过安全编码", "应用审计、WAF 与浏览器侧遥测", "确认脚本具备跨用户自传播能力"],
  trojan_psw: ["进程读取凭据存储、浏览器数据或认证令牌并向外传输", "凭据访问、进程树、文件哈希和外联目的地", "批准的凭据迁移工具在受控主机运行", "凭据访问审计、EDR 与出站流量", "确认目标为凭据材料且存在收集或外传"],
  trojan_downloader: ["小型载荷从外部获取二阶段文件并启动或持久化", "初始文件、下载地址、落地哈希和执行链", "软件更新器从登记域名下载签名包", "DNS、代理、文件与进程审计", "确认下载行为与后续恶意载荷执行关联"],
  trojan_clicker: ["后台进程生成非用户发起的广告点击或流量请求", "进程网络请求、点击标识、前台交互和收益目标", "经授权的广告质量验证产生受控点击", "代理日志、应用交互与进程审计", "确认请求缺少真实用户交互并具有流量欺诈目的"],
  trojan_spy: ["进程记录键盘、屏幕、音频或业务数据并形成外传", "采集接口调用、缓存文件、进程身份和外联记录", "批准的远程支持在用户知情和授权期内运行", "终端隐私接口、文件和出站流量审计", "确认采集对象、用户授权和数据外传路径"],
  trojan_proxy: ["主机开启非授权代理、隧道或端口转发供外部使用", "监听端口、隧道进程、双向流量和持久化项", "批准的网络代理配置与资产清单一致", "网络连接、进程监听与配置审计", "确认主机承担代理转发而非普通客户端通信"],
  trojan: ["非授权可执行文件建立持久化、命令控制或隐蔽运行", "文件来源与签名、进程树、持久化和控制通信", "合法监控组件与发布基线和资产清单一致", "EDR、文件完整性与网络连接记录", "确认至少具备执行、持久化或控制能力之一"],
  trojan_dropper: ["载荷从自身资源或内存释放其他可执行内容并启动", "父载荷哈希、释放文件、内存映射和子进程链", "签名安装器释放已登记组件", "文件创建、内存与进程审计", "确认释放关系和被释放载荷的行为"],
  remote_access_trojan: ["非授权进程提供远程命令、桌面、文件或设备控制", "控制通道、执行命令、会话主体和持久化记录", "批准的远程运维工具受 MFA、工单和时间窗约束", "远程会话、EDR、身份和网络审计", "确认交互式远控能力及操作者授权" ]
};

const DOMAIN_SCOPES = {
  vehicle_platform: {
    network: { assets: ["T-Box", "车载网关", "车云平台"], protocols: ["GB/T 32960", "JT/T 808", "MQTT", "TLS"], focus: "车端通信链路、设备身份与车云会话的对应关系" },
    application: { assets: ["车云平台", "设备管理平台", "OTA 服务"], protocols: ["HTTP", "TLS", "MQTT"], focus: "车云 API、OTA 操作与设备身份审计的一致性" },
    endpoint: { assets: ["T-Box", "车载网关", "OTA 服务"], protocols: ["GB/T 32960", "JT/T 808", "TLS"], focus: "车端进程、固件、指令来源与 OTA 发布基线" }
  },
  iot_platform: {
    network: { assets: ["IoT 网关", "消息代理", "设备管理平台"], protocols: ["MQTT", "CoAP", "TLS"], focus: "设备连接、消息主题、网关会话与设备身份的对应关系" },
    application: { assets: ["设备管理平台", "消息代理", "OTA 服务", "设备身份服务"], protocols: ["HTTP", "MQTT", "CoAP", "TLS"], focus: "设备管理 API、消息授权与设备身份审计的一致性" },
    endpoint: { assets: ["IoT 网关", "OTA 服务", "设备身份服务"], protocols: ["MQTT", "CoAP", "TLS"], focus: "网关进程、设备固件、凭据与 OTA 发布基线" }
  },
  industrial_internet: {
    network: { assets: ["工业网关", "PLC", "SCADA"], protocols: ["OPC UA", "Modbus/TCP", "S7", "TLS"], focus: "工业协议会话、控制区边界与工程操作窗口的对应关系" },
    application: { assets: ["SCADA", "MES", "工程站"], protocols: ["HTTP", "OPC UA", "TLS"], focus: "SCADA/MES 业务操作、工程身份与控制指令审计的一致性" },
    endpoint: { assets: ["工业网关", "PLC", "工程站"], protocols: ["OPC UA", "Modbus/TCP", "S7"], focus: "工程站进程、控制程序、固件与变更审批基线" }
  }
};

function scopeCategory(family) {
  if (["availability", "network_visibility", "name_resolution"].includes(family)) return "network";
  if (["execution", "memory_safety", "privilege", "device", "worm", "trojan"].includes(family)) return "endpoint";
  return "application";
}

function attackDetail(attack) {
  const detail = ATTACK_DETAILS[attack.attackTypeId];
  if (!detail) throw new Error(`missing attack detail: ${attack.attackTypeId}`);
  return {
    signal: detail[0], evidence: detail[1], counterexample: detail[2], telemetry: detail[3], reviewFocus: detail[4]
  };
}

function applicability(domainId, attackTypeId) {
  const limited = new Set(["mail_worm", "p2p_worm", "im_worm"]);
  if (limited.has(attackTypeId)) return "limited";
  if (domainId === "industrial_internet" && ["xss", "request_forgery", "web_worm"].includes(attackTypeId)) return "conditional";
  return "direct";
}

function observability(family, attackTypeId, telemetry) {
  if (["brute_force", "unauthorized_access"].includes(attackTypeId)) {
    return { wazuhObservability: "full", additionalTelemetryRequired: [] };
  }
  if (family === "other") {
    return { wazuhObservability: "false", additionalTelemetryRequired: [telemetry, "人工补充证据"] };
  }
  return { wazuhObservability: "partial", additionalTelemetryRequired: [telemetry] };
}

function knowledgeFor(domain, attack) {
  const family = FAMILY[attack.family];
  const detail = attackDetail(attack);
  const scope = DOMAIN_SCOPES[domain.domainId][scopeCategory(attack.family)];
  const visibility = observability(attack.family, attack.attackTypeId, detail.telemetry);
  const knowledgeId = `kb-${domain.domainId}-${attack.attackTypeId}`;
  const review = reviewRegistry.get(knowledgeId) ?? {
    knowledgeId,
    reviewStatus: "draft",
    reviewedBy: null,
    reviewedAt: null,
    reviewMarker: null
  };
  return {
    knowledgeId,
    domainId: domain.domainId,
    domainName: domain.name,
    attackTypeId: attack.attackTypeId,
    attackTypeName: attack.name,
    aliases: attack.aliases,
    subtypes: attack.subtypes,
    applicability: applicability(domain.domainId, attack.attackTypeId),
    description: `用于${domain.name}中${attack.name}的证据化研判，适用于 ${scope.assets.join("、")} 等资产。`,
    assets: scope.assets,
    protocols: scope.protocols,
    domainFocus: scope.focus,
    wazuhMapping: {
      ruleGroups: [attack.family, attack.attackTypeId],
      requiredFields: ["rule.id", "rule.level", "agent.id", "timestamp"],
      ...visibility
    },
    observableSignals: [detail.signal, ...family.signals.slice(0, 2)],
    requiredTelemetry: [...new Set([...domain.telemetry, ...visibility.additionalTelemetryRequired])],
    evidenceRequired: [detail.evidence, ...family.evidence.slice(0, 2)],
    evidencePolicy: {
      kind: "minimum_independent_evidence",
      minimumIndependentEvidence: 2,
      basis: "内部安全运营经验与边界验证记录共同确认",
      statisticalThreshold: false,
      calibrationRule: "任何频率、比例或风险分数阈值必须引用已完成人工复核的 Wazuh 告警与工单记录"
    },
    supportingEvidence: [`至少两类相互独立证据支持${attack.name}判断`, "事件时间、主体、资产和动作可形成一致时间线"],
    counterexamples: [detail.counterexample, ...family.counterexamples],
    falsePositiveConditions: ["授权活动未与审批记录正确关联", "资产或协议标签配置错误"],
    falseNegativeConditions: ["关键遥测未接入或采集间断", "攻击行为变形且未触发现有规则"],
    bypassPoints: ["攻击者使用可信账号或合法工具隐藏行为", "跨资产分阶段执行导致单点证据不足"],
    unusableFields: [
      { field: "rule.level", reason: "单一规则等级不能完成攻击定性" },
      { field: "source.ip", reason: "单一来源地址不能证明主体或攻击意图" }
    ],
    judgment: {
      confirmed: "escalate_with_manual_review",
      authorizedOrBenign: "suppress_with_manual_review",
      insufficientEvidence: "request_additional_evidence",
      unmatched: "manual_classification"
    },
    recommendedAction: "记录研判结果，创建人工工单并发送飞书通知，等待人工确认后处置。",
    policyStatus: "operational_knowledge",
    autoCloseAllowed: false,
    ticketRequired: true,
    knowledgeStatement: `在${domain.name}中，${attack.name}必须由告警、资产、身份或网络等多源证据共同支持；证据不足时不得自动定性或关闭。`,
    reviewFocus: detail.reviewFocus,
    provenance: {
      sourceClass: "internal_security_operations_experience",
      sourceDescription: "内部安全运营经验整理"
    },
    consumedBy: ["security.ops.v1.SecurityOpsService/MatchKnowledge", "security.ops.v1.SecurityOpsService/EvaluatePolicy"],
    version: taxonomy.version,
    reviewStatus: review.reviewStatus,
    reviewedBy: review.reviewedBy,
    reviewedAt: review.reviewedAt,
    reviewMarker: review.reviewMarker ?? null
  };
}

function fixturesFor(knowledge) {
  const base = {
    knowledgeId: knowledge.knowledgeId,
    domainId: knowledge.domainId,
    attackTypeId: knowledge.attackTypeId
  };
  return [
    {
      ...base,
      fixtureId: `${knowledge.knowledgeId}-confirmed-attack`,
      scenarioType: "confirmed_attack",
      input: { evidence: knowledge.evidenceRequired, authorizationRecord: false, recurrence: 1 },
      expected: { action: "escalate_with_manual_review", ticketRequired: true, autoCloseAllowed: false }
    },
    {
      ...base,
      fixtureId: `${knowledge.knowledgeId}-authorized-or-benign`,
      scenarioType: "authorized_or_benign",
      input: { evidence: knowledge.evidenceRequired, authorizationRecord: true, recurrence: 1 },
      expected: { action: "suppress_with_manual_review", ticketRequired: true, autoCloseAllowed: false }
    },
    {
      ...base,
      fixtureId: `${knowledge.knowledgeId}-insufficient-evidence`,
      scenarioType: "insufficient_evidence",
      input: { evidence: knowledge.evidenceRequired.slice(0, 1), authorizationRecord: false, recurrence: 1 },
      expected: { action: "request_additional_evidence", ticketRequired: true, autoCloseAllowed: false }
    },
    {
      ...base,
      fixtureId: `${knowledge.knowledgeId}-compound-or-recurrent`,
      scenarioType: "compound_or_recurrent",
      input: { evidence: knowledge.evidenceRequired, authorizationRecord: false, recurrence: 3, relatedAttackTypes: [knowledge.attackTypeId] },
      expected: { action: "escalate_with_manual_review", ticketRequired: true, autoCloseAllowed: false }
    }
  ];
}

rmSync(knowledgeDirectory, { recursive: true, force: true });
rmSync(fixtureDirectory, { recursive: true, force: true });
mkdirSync(knowledgeDirectory, { recursive: true });
mkdirSync(fixtureDirectory, { recursive: true });

const manifest = [];
for (const domain of taxonomy.domains) {
  for (const attack of taxonomy.attackTypes) {
    const knowledge = knowledgeFor(domain, attack);
    const fixtures = fixturesFor(knowledge);
    writeFileSync(path.join(knowledgeDirectory, `${knowledge.knowledgeId}.json`), `${JSON.stringify(knowledge, null, 2)}\n`);
    writeFileSync(path.join(fixtureDirectory, `${knowledge.knowledgeId}.json`), `${JSON.stringify(fixtures, null, 2)}\n`);
    manifest.push({ knowledgeId: knowledge.knowledgeId, reviewStatus: knowledge.reviewStatus });
  }
}
writeFileSync(path.join(ROOT, "manifest.json"), `${JSON.stringify({ version: taxonomy.version, knowledge: manifest }, null, 2)}\n`);
if (reviewRegistry.size === 0) {
  writeFileSync(reviewRegistryPath, `${JSON.stringify({
    version: taxonomy.version,
    reviews: manifest.map(({ knowledgeId }) => ({ knowledgeId, reviewStatus: "draft", reviewedBy: null, reviewedAt: null, reviewMarker: null }))
  }, null, 2)}\n`);
}
process.stdout.write(`${JSON.stringify({ domains: taxonomy.domains.length, attackTypes: taxonomy.attackTypes.length, knowledge: manifest.length, fixtures: manifest.length * 4 })}\n`);
