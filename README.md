# newip_dns
## 1 概述
new_dns是为支持NewIP协议开发的简易版本DNS系统，主要目的是为了让chrominum可以工作在NewIP协议架构之上，除了要对dns_server做DNS服务器的支持之外，还要调研chrominum内核的工作方式。

## 2 Chrominum DNS 工作方式
在Chrominum Projects的项目介绍网站中，关于Network Stack的描述中记录了其地址解析的基本过程。

[Network_Stack网站链接](https://www.chromium.org/developers/design-documents/network-stack)

文中提到Chrominum中的HostResolverImpl使用 getaddrinfo() 来实现host地址解析，那么接下来的分析工作为两部分，一是了解Chrominum通过 getaddrinfo() 后的后续工作，二是要调研如何让 getaddrinfo() 适配NewIP的地址协议。