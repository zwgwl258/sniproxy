# 一键部署和网页管理

支持使用 systemd 的 Debian / Ubuntu。安装器会编译并安装同一套 SNIProxy 源码，
同时安装 HTTPS 管理服务；面板是独立进程，不会随代理重启而断开。

在服务器的 Bash 中运行（无需 Git 或 GitHub 登录）：

~~~bash
bash <(curl -fLsS https://raw.githubusercontent.com/zwgwl258/sniproxy/main/install_cmd.sh)
~~~

脚本会下载固定版本、校验 SHA-256，再安装代理和面板。若要给证书指定公网 IP 或域名，
可在命令前加 PANEL_HOST（非必填；需要保留此变量时以 root 执行）。安装后，打开 **https://服务器IP:9443/**，用户名 `admin`。
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

全新部署默认监听所有 IPv4 网卡的 TCP 80/443，请先确认端口空闲，
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

## 按客户端来源国家／地区指定 DNS

一键安装会自动下载并校验 [DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)；
不需要账号、密钥或手动上传。已有数据库会保留。首次安装需要能访问 download.db-ip.com。

安装后在面板「客户端 DNS 分流」填 JP、US、HK 等两字母代码，再填 DNS 并应用。
按代理看到的 TCP 来源 IP 查询本地库，不根据域名或浏览器语言判断。
IP／CIDR 优先于国家；未识别或没有规则的来源用默认 DNS。
数据库由管理员更新，替换后在面板重启代理即可生效。不要用测试数据库部署生产服务。

## AdGuard Home 集成

一键安装默认包含 AdGuard Home（Debian/Ubuntu amd64、arm64）。
上游 v0.107.80 源码与许可证保存在 `vendor/adguardhome/`；安装器使用同版本官方二进制并校验 SHA-256，无需在服务器安装 Go 或 Node.js。
新安装会自动初始化，不显示安装向导。登录 SNIProxy 后，点击「AdGuard Home 管理」即可打开同一 HTTPS 入口下的后台，无需另设密码或使用 SSH 隧道。
集成服务的 Web 后台仅监听 127.0.0.1:3000；新安装的 DNS 默认监听出站路由选中的本机 IPv4 的 TCP/UDP 53，可用 ADGUARD_BIND_IP 指定其他本机 IPv4。防火墙应仅允许可信客户端访问。升级保留已有 AdGuard Home 配置，不替换已有 DNS 规则。
只将面板开放给可信管理员，并限制服务器本地登录权限：本地进程能访问回环后台。
已完成独立初始化的 AdGuard Home 保留配置与认证，不会被迁移或重置。
设置 INSTALL_ADGUARD_HOME=0 可跳过安装。
