class BrowserFingerprint {
  constructor() {
    this.data = {};
  }

  async collectAll() {
    const collectors = [
      this.navigator(),
      this.screen(),
      this.windowMetrics(),
      this.timezone(),
      this.webgl(),
      this.canvas(),
      this.audio(),
      this.fonts(),
      this.mediaDevices(),
      this.webrtc(),
      this.storage(),
      this.battery(),
      this.network(),
      this.permissions(),
      this.speechVoices(),
      this.hardware(),
      this.features(),
      this.css(),
      this.math(),
      this.plugins(),
      this.performance(),
      this.intl(),
      this.quirks(),
    ];
    await Promise.allSettled(collectors);
    this.data.hash = await this.computeHash();
    return this.data;
  }

  async navigator() {
    const n = window.navigator;
    this.data.navigator = {
      userAgent: n.userAgent,
      appVersion: n.appVersion,
      platform: n.platform,
      product: n.product,
      productSub: n.productSub,
      vendor: n.vendor,
      vendorSub: n.vendorSub,
      language: n.language,
      languages: [...(n.languages || [])],
      cookieEnabled: n.cookieEnabled,
      doNotTrack: n.doNotTrack,
      globalPrivacyControl: n.globalPrivacyControl,
      hardwareConcurrency: n.hardwareConcurrency,
      deviceMemory: n.deviceMemory,
      maxTouchPoints: n.maxTouchPoints,
      pdfViewerEnabled: n.pdfViewerEnabled,
      webdriver: n.webdriver,
      oscpu: n.oscpu,
      buildID: n.buildID,
      connection: n.connection
        ? {
            effectiveType: n.connection.effectiveType,
            downlink: n.connection.downlink,
            rtt: n.connection.rtt,
            saveData: n.connection.saveData,
            type: n.connection.type,
          }
        : null,
    };

    if (n.userAgentData) {
      try {
        this.data.navigator.uaClientHints = await n.userAgentData.getHighEntropyValues([
          "architecture",
          "bitness",
          "brands",
          "fullVersionList",
          "mobile",
          "model",
          "platform",
          "platformVersion",
          "uaFullVersion",
          "wow64",
        ]);
      } catch {
        this.data.navigator.uaClientHints = {
          brands: n.userAgentData.brands,
          mobile: n.userAgentData.mobile,
          platform: n.userAgentData.platform,
        };
      }
    }
  }

  async screen() {
    const s = window.screen;
    this.data.screen = {
      width: s.width,
      height: s.height,
      availWidth: s.availWidth,
      availHeight: s.availHeight,
      colorDepth: s.colorDepth,
      pixelDepth: s.pixelDepth,
      orientation: s.orientation ? { type: s.orientation.type, angle: s.orientation.angle } : null,
      isExtended: s.isExtended,
    };
  }

  async windowMetrics() {
    this.data.window = {
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      outerWidth: window.outerWidth,
      outerHeight: window.outerHeight,
      devicePixelRatio: window.devicePixelRatio,
      screenX: window.screenX,
      screenY: window.screenY,
      scrollX: window.scrollX,
      scrollY: window.scrollY,
    };
  }

  async timezone() {
    this.data.timezone = {
      iana: Intl.DateTimeFormat().resolvedOptions().timeZone,
      offset: new Date().getTimezoneOffset(),
      string: new Date().toTimeString().split("(")[1]?.replace(")", "") || null,
      dst: this._hasDST(),
    };
  }

  _hasDST() {
    const jan = new Date(2024, 0, 1).getTimezoneOffset();
    const jul = new Date(2024, 6, 1).getTimezoneOffset();
    return jan !== jul;
  }

  async webgl() {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl2") || canvas.getContext("webgl");
    if (!gl) {
      this.data.webgl = null;
      return;
    }

    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const anisotropyExt = gl.getExtension("EXT_texture_filter_anisotropic");
    const extensions = gl.getSupportedExtensions();

    this.data.webgl = {
      version: gl.getParameter(gl.VERSION),
      shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      unmaskedVendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : null,
      unmaskedRenderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null,
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxRenderBufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
      maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
      maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
      maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
      maxVertexUniforms: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
      maxFragmentUniforms: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
      maxVertexTextures: gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS),
      maxTextureUnits: gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS),
      maxAnisotropy: anisotropyExt ? gl.getParameter(anisotropyExt.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : null,
      aliasedLineWidthRange: gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE),
      aliasedPointSizeRange: gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE),
      antialias: gl.getContextAttributes()?.antialias,
      extensions,
      extensionCount: extensions?.length || 0,
    };
  }

  async canvas() {
    const canvas = document.createElement("canvas");
    canvas.width = 300;
    canvas.height = 150;
    const ctx = canvas.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(100, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("z.je fingerprint", 2, 15);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("z.je fingerprint", 4, 17);
    ctx.beginPath();
    ctx.arc(50, 100, 30, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(255,0,200,0.5)";
    ctx.fill();
    ctx.strokeStyle = "#00ff00";
    ctx.lineWidth = 2;
    ctx.stroke();
    const gradient = ctx.createLinearGradient(0, 0, 300, 0);
    gradient.addColorStop(0, "red");
    gradient.addColorStop(0.5, "green");
    gradient.addColorStop(1, "blue");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 130, 300, 20);
    const dataUrl = canvas.toDataURL();
    this.data.canvas = {
      dataUrlSnippet: dataUrl.slice(0, 100) + "...",
      hash: await this._sha256(dataUrl),
    };
  }

  async audio() {
    try {
      const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      const ctx = new Ctx(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.setValueAtTime(10000, ctx.currentTime);
      const compressor = ctx.createDynamicsCompressor();
      compressor.threshold.setValueAtTime(-50, ctx.currentTime);
      compressor.knee.setValueAtTime(40, ctx.currentTime);
      compressor.ratio.setValueAtTime(12, ctx.currentTime);
      compressor.attack.setValueAtTime(0, ctx.currentTime);
      compressor.release.setValueAtTime(0.25, ctx.currentTime);
      osc.connect(compressor);
      compressor.connect(ctx.destination);
      osc.start(0);
      const buffer = await ctx.startRendering();
      const samples = buffer.getChannelData(0).slice(4500, 5000);
      let sum = 0;
      for (let i = 0; i < samples.length; i += 1) sum += Math.abs(samples[i]);
      this.data.audio = {
        hash: await this._sha256(samples.toString()),
        sum,
        sampleRate: ctx.sampleRate,
      };
    } catch {
      this.data.audio = null;
    }
  }

  async fonts() {
    const testFonts = [
      "Arial", "Arial Black", "Calibri", "Cambria", "Comic Sans MS", "Consolas",
      "Courier New", "Georgia", "Helvetica", "Helvetica Neue", "Impact", "Lucida Console",
      "Menlo", "Monaco", "Palatino", "Segoe UI", "Tahoma", "Times New Roman",
      "Trebuchet MS", "Verdana", "Roboto", "Ubuntu", "Fira Sans", "Noto Sans",
      "SF Pro", "Inter", "Malgun Gothic", "SimSun", "Yu Gothic", "Meiryo",
      "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", "Papyrus",
      "Garamond", "Copperplate", "Futura", "Optima", "Didot",
    ];
    const baseFonts = ["monospace", "sans-serif", "serif"];
    const span = document.createElement("span");
    span.style.position = "absolute";
    span.style.left = "-9999px";
    span.style.fontSize = "72px";
    span.textContent = "mmmmmmmmmmlli10OQ";
    document.body.appendChild(span);
    const baseWidths = {};
    for (const base of baseFonts) {
      span.style.fontFamily = base;
      baseWidths[base] = { w: span.offsetWidth, h: span.offsetHeight };
    }
    const detected = [];
    for (const font of testFonts) {
      let found = false;
      for (const base of baseFonts) {
        span.style.fontFamily = `'${font}', ${base}`;
        if (span.offsetWidth !== baseWidths[base].w || span.offsetHeight !== baseWidths[base].h) {
          found = true;
          break;
        }
      }
      if (found) detected.push(font);
    }
    document.body.removeChild(span);
    this.data.fonts = { detected, count: detected.length };
  }

  async mediaDevices() {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      this.data.mediaDevices = devices.map((device) => ({
        kind: device.kind,
        label: device.label || "(permission needed)",
        deviceId: device.deviceId ? device.deviceId.slice(0, 16) + "..." : null,
        groupId: device.groupId ? device.groupId.slice(0, 16) + "..." : null,
      }));
      this.data.mediaDeviceCounts = {
        audioinput: devices.filter((d) => d.kind === "audioinput").length,
        audiooutput: devices.filter((d) => d.kind === "audiooutput").length,
        videoinput: devices.filter((d) => d.kind === "videoinput").length,
      };
    } catch {
      this.data.mediaDevices = null;
    }
  }

  async webrtc() {
    try {
      const ips = new Set();
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel("zje");
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await new Promise((resolve) => {
        const timeout = setTimeout(resolve, 3000);
        pc.onicecandidate = (event) => {
          if (!event.candidate) {
            clearTimeout(timeout);
            resolve();
            return;
          }
          const parts = event.candidate.candidate.split(" ");
          const ip = parts[4];
          if (ip && (ip.includes(".") || ip.includes(":"))) {
            ips.add(ip);
          }
        };
      });
      pc.close();
      this.data.webrtc = { localIPs: [...ips], available: true };
    } catch {
      this.data.webrtc = { available: false };
    }
  }

  async storage() {
    this.data.storage = {
      localStorage: this._testStorage("localStorage"),
      sessionStorage: this._testStorage("sessionStorage"),
      indexedDB: !!window.indexedDB,
      cookies: navigator.cookieEnabled,
      serviceWorker: !!navigator.serviceWorker,
      cacheAPI: !!window.caches,
      opfs: !!navigator.storage?.getDirectory,
    };
    if (navigator.storage?.estimate) {
      try {
        const estimate = await navigator.storage.estimate();
        this.data.storage.quota = estimate.quota;
        this.data.storage.usage = estimate.usage;
      } catch {
        // ignore
      }
    }
  }

  _testStorage(kind) {
    try {
      const storage = window[kind];
      storage.setItem("__zje_fp", "1");
      storage.removeItem("__zje_fp");
      return true;
    } catch {
      return false;
    }
  }

  async battery() {
    try {
      const battery = await navigator.getBattery();
      this.data.battery = {
        charging: battery.charging,
        level: battery.level,
        chargingTime: battery.chargingTime,
        dischargingTime: battery.dischargingTime,
      };
    } catch {
      this.data.battery = null;
    }
  }

  async network() {
    this.data.networkApi = navigator.connection
      ? {
          effectiveType: navigator.connection.effectiveType,
          downlink: navigator.connection.downlink,
          rtt: navigator.connection.rtt,
          saveData: navigator.connection.saveData,
          type: navigator.connection.type,
        }
      : null;
  }

  async permissions() {
    const names = [
      "geolocation", "notifications", "push", "camera", "microphone",
      "speaker", "bluetooth", "persistent-storage", "clipboard-read",
      "clipboard-write", "screen-wake-lock", "idle-detection",
    ];
    const results = {};
    for (const name of names) {
      try {
        const status = await navigator.permissions.query({ name });
        results[name] = status.state;
      } catch {
        results[name] = "unsupported";
      }
    }
    this.data.permissions = results;
  }

  async speechVoices() {
    try {
      const voices = await new Promise((resolve) => {
        const current = speechSynthesis.getVoices();
        if (current.length) return resolve(current);
        speechSynthesis.onvoiceschanged = () => resolve(speechSynthesis.getVoices());
        setTimeout(() => resolve([]), 2000);
      });
      this.data.speechVoices = {
        count: voices.length,
        voices: voices.map((voice) => ({ name: voice.name, lang: voice.lang, local: voice.localService })),
      };
    } catch {
      this.data.speechVoices = null;
    }
  }

  async hardware() {
    this.data.hardware = {
      hardwareConcurrency: navigator.hardwareConcurrency,
      deviceMemory: navigator.deviceMemory,
      maxTouchPoints: navigator.maxTouchPoints,
      touchEvent: "ontouchstart" in window,
      pointerEvent: !!window.PointerEvent,
      hoverSupport: window.matchMedia("(hover: hover)").matches,
      anyHover: window.matchMedia("(any-hover: hover)").matches,
      pointerFine: window.matchMedia("(pointer: fine)").matches,
      pointerCoarse: window.matchMedia("(pointer: coarse)").matches,
      gamepads: !!navigator.getGamepads,
      bluetooth: !!navigator.bluetooth,
      usb: !!navigator.usb,
      serial: !!navigator.serial,
      hid: !!navigator.hid,
      xr: !!navigator.xr,
      gpu: !!navigator.gpu,
      wakeLock: !!navigator.wakeLock,
    };
    if (navigator.gpu) {
      try {
        const adapter = await navigator.gpu.requestAdapter();
        if (adapter) {
          this.data.hardware.webgpu = {
            vendor: adapter.info?.vendor,
            architecture: adapter.info?.architecture,
            device: adapter.info?.device,
            description: adapter.info?.description,
            features: [...adapter.features],
          };
        }
      } catch {
        // ignore
      }
    }
  }

  async features() {
    this.data.features = {
      webAssembly: !!window.WebAssembly,
      sharedArrayBuffer: !!window.SharedArrayBuffer,
      crossOriginIsolated: window.crossOriginIsolated,
      webSocket: !!window.WebSocket,
      webWorker: !!window.Worker,
      sharedWorker: !!window.SharedWorker,
      webRTC: !!window.RTCPeerConnection,
      webGL: !!document.createElement("canvas").getContext("webgl"),
      webGL2: !!document.createElement("canvas").getContext("webgl2"),
      webGPU: !!navigator.gpu,
      offscreenCanvas: !!window.OffscreenCanvas,
      intersectionObserver: !!window.IntersectionObserver,
      resizeObserver: !!window.ResizeObserver,
      mutationObserver: !!window.MutationObserver,
      performanceObserver: !!window.PerformanceObserver,
      reportingObserver: !!window.ReportingObserver,
      scheduler: !!window.scheduler,
      structuredClone: !!window.structuredClone,
      broadcastChannel: !!window.BroadcastChannel,
      writableStream: !!window.WritableStream,
      readableStream: !!window.ReadableStream,
      compressionStream: !!window.CompressionStream,
      fileSystemAccess: !!window.showOpenFilePicker,
      eyeDropper: !!window.EyeDropper,
      barcodeDetector: !!window.BarcodeDetector,
      faceDetector: !!window.FaceDetector,
      credentialsAPI: !!navigator.credentials,
      webAuthn: !!window.PublicKeyCredential,
      paymentRequest: !!window.PaymentRequest,
      contentIndex: !!window.self?.ContentIndex,
      cookieStore: !!window.cookieStore,
    };
  }

  async css() {
    const mq = (query) => window.matchMedia(query).matches;
    this.data.css = {
      prefersColorScheme: mq("(prefers-color-scheme: dark)") ? "dark" : "light",
      prefersReducedMotion: mq("(prefers-reduced-motion: reduce)"),
      prefersReducedData: mq("(prefers-reduced-data: reduce)"),
      prefersContrast: mq("(prefers-contrast: more)")
        ? "more"
        : mq("(prefers-contrast: less)")
          ? "less"
          : "no-preference",
      prefersReducedTransparency: mq("(prefers-reduced-transparency: reduce)"),
      forcedColors: mq("(forced-colors: active)"),
      invertedColors: mq("(inverted-colors: inverted)"),
      colorGamut: mq("(color-gamut: p3)") ? "p3" : mq("(color-gamut: srgb)") ? "srgb" : "unknown",
      hdr: mq("(dynamic-range: high)"),
      displayMode: mq("(display-mode: standalone)")
        ? "standalone"
        : mq("(display-mode: fullscreen)")
          ? "fullscreen"
          : "browser",
      orientation: mq("(orientation: portrait)") ? "portrait" : "landscape",
      monochrome: mq("(monochrome)"),
    };
  }

  async math() {
    this.data.math = {
      acos: Math.acos(0.5),
      acosh: Math.acosh(2),
      asin: Math.asin(0.5),
      atanh: Math.atanh(0.5),
      cbrt: Math.cbrt(2),
      cosh: Math.cosh(1),
      expm1: Math.expm1(1),
      log1p: Math.log1p(0.5),
      sinh: Math.sinh(1),
      tanh: Math.tanh(1),
      e: Math.E,
      pi: Math.PI,
      ln2: Math.LN2,
      log2e: Math.LOG2E,
      sqrt2: Math.SQRT2,
    };
  }

  async plugins() {
    const plugins = [];
    if (navigator.plugins) {
      for (let i = 0; i < navigator.plugins.length; i += 1) {
        const plugin = navigator.plugins[i];
        const mimes = [];
        for (let j = 0; j < plugin.length; j += 1) {
          mimes.push({ type: plugin[j].type, suffixes: plugin[j].suffixes });
        }
        plugins.push({
          name: plugin.name,
          description: plugin.description,
          filename: plugin.filename,
          mimes,
        });
      }
    }
    this.data.plugins = { list: plugins, count: plugins.length };

    const mimeTypes = [];
    if (navigator.mimeTypes) {
      for (let i = 0; i < navigator.mimeTypes.length; i += 1) {
        mimeTypes.push({
          type: navigator.mimeTypes[i].type,
          description: navigator.mimeTypes[i].description,
          suffixes: navigator.mimeTypes[i].suffixes,
        });
      }
    }
    this.data.mimeTypes = mimeTypes;
  }

  async performance() {
    this.data.performance = {
      timeOrigin: performance.timeOrigin,
      memory: performance.memory
        ? {
            jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
            totalJSHeapSize: performance.memory.totalJSHeapSize,
            usedJSHeapSize: performance.memory.usedJSHeapSize,
          }
        : null,
      navigation: performance.navigation
        ? {
            type: performance.navigation.type,
            redirectCount: performance.navigation.redirectCount,
          }
        : null,
    };
  }

  async intl() {
    const dtf = Intl.DateTimeFormat().resolvedOptions();
    const nf = Intl.NumberFormat().resolvedOptions();
    this.data.intl = {
      dateTimeFormat: {
        locale: dtf.locale,
        calendar: dtf.calendar,
        numberingSystem: dtf.numberingSystem,
        timeZone: dtf.timeZone,
      },
      numberFormat: {
        locale: nf.locale,
        numberingSystem: nf.numberingSystem,
        style: nf.style,
        currency: nf.currency,
      },
      listFormat: !!Intl.ListFormat,
      pluralRules: !!Intl.PluralRules,
      relativeTime: !!Intl.RelativeTimeFormat,
      displayNames: !!Intl.DisplayNames,
      segmenter: !!Intl.Segmenter,
    };
  }

  async quirks() {
    this.data.quirks = {};
    try {
      null[0];
    } catch (error) {
      this.data.quirks.errorStackSignature = error.stack?.split("\n")[0];
    }
    this.data.quirks.evalToString = eval.toString().length;
    this.data.quirks.functionBind = Function.prototype.bind.toString().length;
    this.data.quirks.arrayToString = [].toString.call([1, 2, 3]);
    this.data.quirks.dateString = new Date(0).toString();
    this.data.quirks.toLocaleString = new Date(0).toLocaleString("en-US");
    this.data.quirks.numberToLocale = (3500).toLocaleString("en-US");
    this.data.quirks.notificationPermission = window.Notification?.permission;
    this.data.quirks.webdriver = navigator.webdriver;
    this.data.quirks.hasChrome = !!window.chrome;
    this.data.quirks.phantom = !!window._phantom || !!window.__nightmare || !!window.callPhantom;
    this.data.quirks.selenium = !!window.__selenium_evaluate || !!document.__selenium_unwrapped;
    this.data.quirks.domAutomation = !!window.domAutomation || !!window.domAutomationController;
    this.data.quirks.outerDimMatch = window.outerWidth > 0 && window.outerHeight > 0;
  }

  async _sha256(str) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async computeHash() {
    const stable = JSON.stringify({
      ua: this.data.navigator?.userAgent,
      platform: this.data.navigator?.platform,
      lang: this.data.navigator?.languages,
      cores: this.data.hardware?.hardwareConcurrency,
      mem: this.data.hardware?.deviceMemory,
      screen: this.data.screen,
      tz: this.data.timezone?.iana,
      webgl: this.data.webgl?.unmaskedRenderer,
      canvas: this.data.canvas?.hash,
      audio: this.data.audio?.hash,
      fonts: this.data.fonts?.count,
      math: this.data.math,
      plugins: this.data.plugins?.count,
    });
    return this._sha256(stable);
  }
}

function countSignals(input) {
  if (input === null || input === undefined) return 0;
  if (Array.isArray(input)) return input.reduce((sum, item) => sum + countSignals(item), 0);
  if (typeof input === "object") {
    return Object.values(input).reduce((sum, item) => sum + countSignals(item), 0) || Object.keys(input).length;
  }
  return 1;
}

(async () => {
  const jsonEl = document.getElementById("fp-json");
  if (!jsonEl) return;

  const fp = new BrowserFingerprint();
  const startTime = performance.now();
  const data = await fp.collectAll();
  const elapsed = (performance.now() - startTime).toFixed(0);

  const response = await fetch("/fp/collect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  const combined = await response.json();

  document.getElementById("fp-hash").textContent = data.hash;
  document.getElementById("fp-time").textContent = `${elapsed}ms`;
  document.getElementById("fp-field-count").textContent = `${countSignals(combined)} signals`;
  jsonEl.textContent = JSON.stringify(combined, null, 2);
  document.getElementById("fp-loading").style.display = "none";
  document.getElementById("fp-results").style.display = "block";
})();
