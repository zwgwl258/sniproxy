# 按客户端来源 IP 分流 DNS

这个版本保留原版 HTTP Host / TLS SNI 转发，只改变后端域名由哪台 DNS 解析。同一个进程可监听原来的 80/443。

```conf
resolver {
    nameserver 1.1.1.1
    mode ipv4_only
}

resolver {
    client 192.0.2.10
    nameserver 9.9.9.9
    mode ipv4_only
}

resolver {
    client 198.51.100.0/24
    nameserver 8.8.8.8
    mode ipv4_only
}

table {
    ^(.*\.)?netflix\.ca$ *
}
```

把示例客户端地址替换为代理实际看到的 TCP 来源地址，并保留现有的 listener 配置。
支持 IPv4、IPv6、单 IP 和 CIDR；重叠网段取最长前缀，同等长度取最后声明的规则。
没有匹配时使用不带 client 的 resolver。每个 client 块至少写一个 nameserver。
地址族模式和搜索域由各块单独配置；建议明确写出 mode。
DNS 失败不跨组回退。目标为字面 IP 的转发不进行 DNS 查询。
所有需要解析的后端域名都适用，不限于示例的 Netflix 规则。
同一个 NAT 公网出口的客户端不能仅靠 TCP 来源 IP 区分。
修改 DNS 配置后重启服务；SIGHUP 不重载 resolver（与上游行为一致）。

## Ubuntu / Debian 构建

```sh
sudo apt-get install build-essential autoconf automake libev-dev libpcre2-dev libudns-dev
autoreconf -fi
./configure --enable-dns
make -j"$(nproc)"
sudo python3 tests/client_dns_integration.py ./src/sniproxy
```

集成测试仅绑定本机回环地址，使用两个临时 DNS 和 HTTP 后端，
验证同域名的并发请求按来源分流，且未匹配客户端使用默认 DNS。
部署前先备份原二进制和配置；要回滚时恢复两者并重启服务。
只允许受信任客户端访问代理，避免把通配转发暴露到公网。
