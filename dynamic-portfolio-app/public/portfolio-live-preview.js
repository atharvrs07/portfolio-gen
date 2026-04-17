(function () {
  function writeIframe(iframe, html) {
    if (!iframe) return;
    var doc = iframe.contentDocument || (iframe.contentWindow && iframe.contentWindow.document);
    if (!doc) return;
    doc.open();
    doc.write(html);
    doc.close();
  }

  function buildFormBody(form, beforeRead) {
    if (typeof beforeRead === "function") {
      beforeRead();
    }
    var fd = new FormData(form);
    fd.delete("profileImageFile");
    fd.delete("companyLogoFile");

    var params = new URLSearchParams();
    fd.forEach(function (value, key) {
      if (value instanceof File) return;
      params.append(key, String(value == null ? "" : value));
    });
    return params.toString();
  }

  function fetchRenderedPortfolioHtml(form, options) {
    options = options || {};
    var body = buildFormBody(form, options.beforeRead);
    return fetch("/api/portfolio/preview", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest"
      },
      credentials: "same-origin",
      body: body
    }).then(function (response) {
      if (!response.ok) {
        throw new Error("Preview failed with status " + response.status);
      }
      return response.text();
    });
  }

  function attachPortfolioLivePreview(options) {
    var form = options.form;
    var iframe = options.iframe;
    if (!form || !iframe) return;

    var raf = null;
    var requestSerial = 0;

    function renderError() {
      writeIframe(
        iframe,
        "<!doctype html><html><body style='margin:0;padding:1rem;font-family:Inter,Arial,sans-serif;background:#05070d;color:#f5f8ff;'><p style='margin:0;font-weight:600;'>Live preview unavailable right now.</p><p style='margin:.45rem 0 0;opacity:.82;'>Continue editing and try again.</p></body></html>"
      );
    }

    function run() {
      requestSerial += 1;
      var currentRequest = requestSerial;
      fetchRenderedPortfolioHtml(form, { beforeRead: options.beforeRead })
        .then(function (html) {
          if (currentRequest !== requestSerial) return;
          writeIframe(iframe, html);
        })
        .catch(function () {
          if (currentRequest !== requestSerial) return;
          renderError();
        });
    }

    function schedule() {
      if (raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(function () {
        raf = null;
        run();
      });
    }

    form.addEventListener("input", schedule);
    form.addEventListener("change", schedule);
    form.addEventListener(
      "click",
      function (e) {
        var target = e.target;
        if (!target || !target.closest) return;
        if (target.closest(".experience-add-btn") || target.closest(".experience-remove-btn")) {
          requestAnimationFrame(schedule);
        }
      },
      true
    );
    form.addEventListener("dragend", schedule, true);

    run();
    return { refresh: run };
  }

  function openPortfolioPreviewInNewTab(form, _mode, beforeRead) {
    if (!form) return;
    fetchRenderedPortfolioHtml(form, { beforeRead: beforeRead })
      .then(function (html) {
        var w = window.open("", "_blank");
        if (!w) return;
        w.document.open();
        w.document.write(html);
        w.document.close();
      })
      .catch(function () {
        var w = window.open("", "_blank");
        if (!w) return;
        w.document.open();
        w.document.write(
          "<!doctype html><html><body style='margin:0;padding:1rem;font-family:Inter,Arial,sans-serif;'><p>Could not open preview right now.</p></body></html>"
        );
        w.document.close();
      });
  }

  window.attachPortfolioLivePreview = attachPortfolioLivePreview;
  window.openPortfolioPreviewInNewTab = openPortfolioPreviewInNewTab;
})();
