# Traefik EdgeOne IP

一个 Traefik middleware 插件：通过腾讯云 EdgeOne API **实时校验**请求来源 IP 是否为 EdgeOne 节点；校验通过后，才会信任并提取真实客户端 IP（优先 `Eo-Connecting-Ip`，其次 `X-Real-IP` / `X-Forwarded-For`），并写回标准头部供后端/其他中间件使用。

本项目的核心校验逻辑参考了 `caddy-edgeone-ip`：使用 [查询 IP 归属信息](https://cloud.tencent.com/document/api/1552/102227) API 对单个 IP 做验证，并通过 LRU+TTL 缓存结果。

## 安装

### Traefik 静态配置

```yaml
experimental:
  plugins:
    traefik-edgeone-ip:
      moduleName: github.com/chunzhennn/traefik-edgeone-ip
      version: v0.1.0
```

## 使用

### Traefik 动态配置（middleware）

```yaml
http:
  middlewares:
    edgeone-real-ip:
      plugin:
        traefik-edgeone-ip:
          secretID: "${EONE_SECRET_ID}"
          secretKey: "${EONE_SECRET_KEY}"
          apiEndpoint: "teo.tencentcloudapi.com"
          timeout: "5s"
          cacheTTL: "1h"
          cacheSize: 1000
          logLevel: "info"
```

## 行为说明

- **可信判断**：对 `req.RemoteAddr` 的来源 IP 调用 EdgeOne API 校验；结果会被 LRU 缓存（默认 1000 条、TTL 1h）。
- **提取真实 IP（仅在可信时）**：
  - 优先 `Eo-Connecting-Ip`
  - 否则使用 `X-Real-IP`（会跳过私网/本地地址）
  - 否则从 `X-Forwarded-For` 里取第一个非私网/本地地址
- **写回头部**：
  - 总是设置 `X-Real-IP`
  - 总是设置 `X-Is-Trusted: yes|no`
  - 可信时：把解析出的真实 IP 放到 `X-Forwarded-For` 最前面（去重）
  - 不可信时：`X-Forwarded-For` 会被设置为来源 IP（fail-closed，避免伪造头部）

## License

MIT


