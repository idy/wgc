(() => {
  "use strict";
  if (!window.IdySite) return;

  // English lives in the HTML so the whole page is useful without JavaScript.
  const en = {
    pageTitle: "WGC — WireGuard connections for Go",
    description: "WGC is a Go library for authenticated, encrypted messages using WireGuard sessions over your own transport. No TUN device or route setup.",
    socialDescription: "Public-key peers. Automatic handshakes. A transport you control.",
    installCopied: "Install command copied.",
    codeCopied: "Code copied.",
    copyFailed: "Select the command or code to copy it manually.",
    copySource: "Text to copy",
    releaseLoading: "Checking GitHub for the latest release…",
    releaseStable: "Latest stable release",
    releasePreview: "Latest preview release",
    releaseFailed: "Release information is unavailable. Browse GitHub Releases for the latest version."
  };
  for (const [attribute, read] of [
    ["data-i18n", (node) => node.textContent],
    ["data-i18n-html", (node) => node.innerHTML],
    ["data-i18n-aria-label", (node) => node.getAttribute("aria-label")]
  ]) {
    document.querySelectorAll(`[${attribute}]`).forEach((node) => {
      en[node.getAttribute(attribute)] = read(node);
    });
  }

  IdySite.init({ en, zh: {
    pageTitle: "WGC — 面向 Go 的 WireGuard 连接库",
    description: "WGC 是一个 Go 库，通过你自己的传输层使用 WireGuard 会话，交换经过身份验证的加密消息。无需 TUN 设备或路由配置。",
    socialDescription: "公钥标识对端，自动管理握手，传输方式由你掌控。",
    getStarted: "开始使用",
    goReference: "Go API 文档",
    heroTitle: "WireGuard，<br>专注连接层。",
    intro: "在以公钥标识的对端之间交换经过身份验证的加密消息。这个 Go 库负责管理会话，传输方式由你选择。",
    build: "使用 WGC 开发",
    documentation: "阅读文档",
    heroNote: "MIT 许可。Go 1.25+。无需 TUN 设备或路由配置。",
    apiLabel: "WGC 连接 API",
    onePeer: "一个对端，一个公钥。",
    handshakeComment: "// 让连接负责握手。",
    authorizedPeer: "由你授权的对端",
    managedSession: "自动管理的会话",
    controlledTransport: "由你掌控的传输层",
    overviewTitle: "会话已就绪。<br>网络由你决定。",
    overviewIntro: "让连接逻辑紧贴你的应用。WGC 提供协议机制，无需安装 VPN 接口。",
    peersTitle: "以公钥标识对端",
    peersBody: "在 <code>PeerConfigLookup</code> 中授权公钥。通过 <code>WriteTo</code> 发送消息，通过 <code>ReadFrom</code> 获取消息及已验证身份的发送方。",
    sessionsTitle: "自动维护会话",
    sessionsBody: "连接负责 WireGuard 握手、密钥更新、重放保护、可选的预共享密钥，以及经过身份验证的端点漫游。",
    socketsTitle: "你的套接字，你的资源限制",
    socketsBody: "使用 UDP 适配器，或实现简洁的 <code>Transport</code> 接口。设置对端和队列上限、共享写队列，并收集流量计数。",
    startTitle: "从一个连接开始。",
    startIntro: "添加模块，选择你信任的密钥，并提供传输层。",
    moduleNote: "模块路径为 <code>github.com/idy/wgc</code>，Go 包名为 <code>wireguard</code>。",
    runExample: "运行本地回显示例",
    copy: "复制",
    copyCode: "复制代码",
    copyInstall: "复制安装命令",
    codeHeading: "授权对端，然后发送消息",
    connectionLabel: "WGC 连接示例",
    codeConfigComment: "// 处理 err，然后配置本地私钥，\n// 并通过 PeerConfigLookup 授权已知公钥。",
    codeCloseComment: "// 处理 err，使用结束后关闭 conn。\n// 写操作会排队；请使用确认和重试机制。",
    codeNote: "这是 API 示意代码；请处理错误并提供自己的配置。<a href=\"https://github.com/idy/wgc/tree/main/examples/echo\">完整示例</a>会创建两个本地对端并交换消息。",
    installCopied: "已复制安装命令。",
    codeCopied: "已复制代码。",
    copyFailed: "请选择命令或代码，手动复制。",
    copySource: "待复制的文本",
    releaseTitle: "使用最新的 WGC。",
    releaseIntro: "将 WGC 作为 Go 模块安装。查看版本说明、阅读 API 文档，或下载源代码归档。",
    releaseFallback: "在 GitHub Releases 中查看当前版本。",
    releaseLoading: "正在从 GitHub 获取最新版本…",
    releaseStable: "最新稳定版",
    releasePreview: "最新预览版",
    releaseFailed: "暂时无法获取版本信息。请前往 GitHub Releases 查看最新版本。",
    sourceArchive: "源代码归档",
    apiReference: "API 文档",
    sourceNote: "WGC 是一个开发库。源代码归档不是预编译二进制文件。",
    scopeTitle: "传入消息，传出消息。",
    scopeBody: "WGC 面向消息。写操作异步排队，握手期间可能丢弃消息。如果需要可靠交付，请使用确认和重试机制。连接 API 通过公钥寻址对端，因此不同于 Go 标准库的 <code>net.Conn</code>。",
    vpnBody: "构建带路由的 VPN 时，你需要自行提供 TUN 设备、IP 配置和路由。标准 WireGuard 对端期望接收 IP 数据包；交换任意消息的应用可以在两端都使用 WGC。",
    transportReference: "了解 Transport 接口",
    trademark: "本项目独立开发。WireGuard 是 Jason A. Donenfeld 的注册商标。"
  } });

  const t = (key) => IdySite.t(key);
  const status = document.getElementById("copy-status");
  let copyMessage = "";
  let release;
  let releaseState = "loading";

  function renderMetadata() {
    document.title = t("pageTitle");
    document.querySelector('meta[name="description"]').content = t("description");
    document.querySelector('meta[property="og:title"]').content = t("pageTitle");
    document.querySelector('meta[property="og:description"]').content = t("socialDescription");
    document.querySelector('meta[name="theme-color"]').content = document.documentElement.dataset.theme === "dark" ? "#111e2b" : "#f2f7fb";
  }

  function renderRelease() {
    const message = releaseState === "loaded"
      ? (release.prerelease ? "releasePreview" : "releaseStable")
      : (releaseState === "failed" ? "releaseFailed" : "releaseLoading");
    document.getElementById("release-status").textContent = t(message);
  }

  function renderLanguage() {
    renderMetadata();
    renderRelease();
    status.textContent = copyMessage ? t(copyMessage) : "";
  }
  document.addEventListener("idy:languagechange", renderLanguage);
  new MutationObserver(renderMetadata).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  renderLanguage();

  function fallbackCopy(text) {
    const previousFocus = document.activeElement;
    const input = document.createElement("textarea");
    input.value = text;
    input.setAttribute("readonly", "");
    input.setAttribute("aria-label", t("copySource"));
    input.style.cssText = "position:fixed;left:-9999px;top:0;";
    document.body.appendChild(input);
    try {
      input.select();
      return document.execCommand("copy");
    } finally {
      input.remove();
      previousFocus?.focus({ preventScroll: true });
    }
  }

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.hidden = false;
    button.addEventListener("click", async () => {
      const source = document.getElementById(button.dataset.copy);
      if (!source) return;
      let copied = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(source.textContent);
          copied = true;
        }
      } catch { /* Try the local selection fallback. */ }
      if (!copied) {
        try { copied = fallbackCopy(source.textContent); } catch { /* Report manual copy below. */ }
      }
      copyMessage = copied
        ? (button.dataset.copy === "install-command" ? "installCopied" : "codeCopied")
        : "copyFailed";
      status.textContent = t(copyMessage);
    });
  });

  IdySite.loadRelease("idy/wgc").then((latest) => {
    release = latest;
    releaseState = "loaded";
    const version = document.getElementById("release-version");
    version.textContent = release.tag_name;
    version.hidden = false;
    document.getElementById("release-link").href = release.html_url;
    if (release.zipball_url) {
      const archive = document.getElementById("source-archive");
      archive.href = release.zipball_url;
      archive.hidden = false;
    }
    renderRelease();
  }).catch(() => {
    releaseState = "failed";
    renderRelease();
  });
})();
