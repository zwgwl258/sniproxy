# SNIProxy 管理面板 + AdGuard Home 融合版

通过网页管理 SNIProxy 域名转发、按客户端分流的 DNS 和全局兜底 DNS。安装器默认同时安装 AdGuard Home，登录 SNIProxy 后即可从同一个 HTTPS 面板进入 AdGuard Home，不用另设密码或开 SSH 隧道。

## 一键安装 / 升级

**支持 Debian / Ubuntu（systemd，amd64 或 arm64）。** 在服务器上以 **root** 执行。不需要 Git、GitHub 登录或手动上传国家数据库。

```bash
f=$(mktemp) && curl -fLsS 'https://raw.githubusercontent.com/zwgwl258/sniproxy/0861f7791c099345a852fbf926386e0357ba6813/install_cmd.sh' -o "$f" && bash "$f"
```

此命令固定到已验证的安装版本，不受仓库首页文档更新影响。安装器会校验下载的归档。
[查看 Linux 部署和 Debian 11 构建验证](https://github.com/zwgwl258/sniproxy/actions/runs/41918013012)。

- **全新安装**：仅在配置文件不存在时写入默认模板，预置 12 个域名组（324 条规则），全局兜底 DNS 留空，使用系统 DNS。成功后终端会显示面板地址、用户名 `admin` 和初始密码。首次登录必须修改密码（12–128 个字符），然后用新密码重新登录。不要公开安装输出中的密码。
- **覆盖升级**：运行同一条命令即可保留域名、DNS 规则和已有面板密码，服务可能短暂重启。平时可以从「修改面板密码」更换密码。
- **旧服务**：若旧的 `sniproxy.service` 正在运行，安装器不会停掉它，也不会启动新版代理抢占端口。已独立初始化的 AdGuard Home 不会被重置或自动迁移到统一登录。

### Debian 11：Autoconf 2.69

直接使用上面同一条安装命令，不需要另用旧版安装包。安装器所用源码已通过 Debian 11 构建验证。

## 使用面板

默认访问 `https://服务器公网IP:9443/`。安装器打印的地址可能是内网 IP；远程访问时请使用实际可达地址，并只允许管理员来源访问 TCP 9443。默认是自签名证书；应核对安装时显示的指纹，或用与访问地址匹配的可信证书。具体参数见[部署说明](deploy/README.md)。

| 功能 | 怎么用 |
| --- | --- |
| 域名转发 | 全部可管理域名每行一条。直接增、改、删，点「保存域名列表」统一应用。支持批量粘贴域名或 `.*example\.com$ *` 形式的规则。 |
| 客户端 DNS 分流 | 填来源 IP、CIDR，或搜索选择国家／地区，再填 DNS IP。已添加规则可搜索、翻页、修改和删除。 |
| 全局兜底 DNS | 每行一个 DNS IP，不设固定条数上限。未命中分流规则时直接使用；客户端专用组未返回可用地址时也会尝试。清空并保存后恢复默认 DNS。 |
| 高级配置 | 修改监听地址、默认 DNS 或自定义转发表。可校验并应用、查看日志、重启及恢复上一版配置。 |
| AdGuard Home | 点击标题旁的「AdGuard Home 管理」进入同一 HTTPS 地址的 `/adguard/`。融合模式不用填写单独的后台地址。 |

客户端来源以代理实际看到的 TCP 来源 IP 为准。匹配优先级：**IP／网段 → 国家／地区 → 全局兜底 DNS（未设置则用默认 DNS）**。安装器会自动下载并校验 [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite)。启动后立即探测各台分流及兜底 DNS，以 example.com 的地址响应判断健康，每 5 分钟复测。分流组全部探测失败时直接使用兜底；兜底优先选最近探测最快的健康节点，真实查询失败则按配置顺序继续尝试其他兜底节点。探测不能保证具体目标域名或目标网站可达。另有每 30 分钟运行的逐域名综合测速：取转发表全部可识别的域名，在本机临时启动独立 SNIProxy 逐台测候选 DNS，记录 HTTPS 首字节和 DNS 耗时；按每个实际测试主机名近三轮成功率和耗时分别选优，切换不重启；未测试的子域名仍按普通兜底策略处理。复杂正则不作为域名猜测；无有效综合结果时沿用 DNS 探测策略。兜底只处理 DNS 查询失败，不处理目标网站连接失败。兜底组内超时或服务错误可以重试下一台；`NXDOMAIN` 不保证再查下一台。

## 默认端口和 AdGuard Home 规则

| 组件 | 全新安装默认值 |
| --- | --- |
| SNIProxy HTTPS 管理面板 | TCP `9443` |
| SNIProxy 流量监听 | 新安装默认 `0.0.0.0:80`（HTTP）和 `0.0.0.0:443`（TLS）；防火墙仅放行可信客户端 |
| AdGuard Home Web 后台 | 本机 `127.0.0.1:3000`，由面板转发 |
| AdGuard Home DNS | 新安装默认监听服务器网卡 IPv4 的 TCP/UDP 53；防火墙仅放行可信客户端 |

远端客户端如果要连接代理，请先在「高级配置」中设置实际监听地址和转发表，再按需放行端口。不要开放公网 AdGuard Home 后台或把 DNS 暴露为公共解析器。

融合版安装会为 AdGuard Home 写入自定义过滤规则：

```text
|*^$dnsrewrite=NOERROR;A;你的公网IPv4
```

默认自动检测公网出口 IPv4。如果 NAT 或负载均衡使出口 IP 与客户端实际使用的代理地址不同，可把安装命令最后的 `bash "$f"` 改为 `ADGUARD_PUBLIC_IP=实际公网IPv4 bash "$f"`。脚本不会覆盖指向其他 IP 的现有同类重写。新装时 **AdGuard DNS filter** 和 **AdAway Default Blocklist** 默认关闭，升级不覆盖已有黑名单状态。

**这是全域名 A 记录重写。不要把这一实例作为 SNIProxy 解析真实后端的上游 DNS，否则可能把流量指回代理自身。** 安装器不会替你切换现有 DNS 规则。

## 常用检查

```bash
systemctl is-active sniproxy-panel.service sniproxy-managed.service sniproxy-adguard.service
journalctl -u sniproxy-panel.service -n 50 --no-pager
```

配置位于 `/etc/sniproxy-managed/`，集成的 AdGuard Home 数据位于 `/opt/sniproxy-adguard/`。升级或迁移前建议备份这两个目录。

## 更多文档

- [部署、证书和迁移](deploy/README.md)
- [客户端 DNS 配置和构建](CLIENT-DNS.md)
- [原项目说明（英文）](README.upstream.md)
- [SNIProxy 许可证](COPYING) · [AdGuard Home 上游许可证](vendor/adguardhome/LICENSE.txt)
