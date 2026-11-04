# 一键部署和网页管理

支持使用 systemd 的 Debian / Ubuntu。安装器会编译并安装同一套 SNIProxy 源码，
同时安装 HTTPS 管理服务；面板是独立进程，不会随代理重启而断开。

在服务器上运行（此仓库是私有的，先为服务器配置可读的 GitHub SSH 密钥；
这里只用 SSH 拉 Git 代码，**浏览器访问面板不需要 SSH 隧道**）：

```bash
git clone git@github.com:zwgwl258/sniproxy.git sniproxy-managed && sudo PANEL_HOST=你的公网IP bash sniproxy-managed/deploy/install.sh
```

把命令里的 `你的公网IP` 换成实际公网 IP 或域名，用于生成证书。打开 **https://服务器IP:9443/**，用户名 `admin`。
密码可用 `sudo cat /etc/sniproxy-managed/panel-password` 获取。
建议用防火墙限制 9443 只允许管理员 IP，不要开放给所有人。
默认是自签名证书；先通过可信渠道核对安装时打印的 SHA-256 指纹，再将证书加入信任。
生产环境可用受信证书与匹配的域名：

```bash
sudo PANEL_CERT=/path/to/fullchain.pem PANEL_KEY=/path/to/privkey.pem bash sniproxy-managed/deploy/install.sh
```

证书更新后重新执行这条命令以复制新证书。可通过 `PANEL_BIND` 和 `PANEL_PORT`
指定面板 IPv4 地址和端口。面板管理员可变更代理监听和日志路径，只给受信任的服务器管理员。

面板可编辑完整配置（含默认 DNS、按来源 IP 分流的 DNS、域名规则、监听端口），
点击「校验、保存并应用」会先运行配置解析器再重启代理。
检测到启动失败时会尝试恢复原配置和服务状态；面板也支持恢复上一版、重启和查看日志。
语法校验不保证上游 DNS 或目标站点可达。

全新部署的代理仅监听本机 8080/8443；在面板里按需改为 80/443，
并确保访问来源受防火墙限制。迁移时可用以下方式复制已有配置，
不会改动原文件，也不会覆盖面板已经保存的配置：

```bash
sudo SNIPROXY_CONFIG=/etc/sniproxy.conf bash sniproxy-managed/deploy/install.sh
```

如果旧的 `sniproxy.service` 正在运行，安装器不会停它。准备切换时，先确认原监听端口
已释放（旧服务请在维护窗口停止），然后在面板应用配置并启用新服务开机启动：

```bash
sudo systemctl enable sniproxy-managed.service
```

更新：在克隆目录执行 `git pull --ff-only`，再运行安装脚本。
重复执行保留面板密码和已保存配置，可能短暂重启代理与面板。
回切到旧服务时，先停止并禁用 `sniproxy-managed.service`，再启动原服务。
