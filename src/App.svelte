<script>
  import hljs from 'highlight.js/lib/core';
  import javascript from 'highlight.js/lib/languages/javascript';
  import 'highlight.js/styles/github-dark-dimmed.css';

  hljs.registerLanguage('javascript', javascript);

  const HIGHLIGHT_LIMIT = 1_200_000;
  const FUNCTION_HIGHLIGHT_LIMIT = 200_000;
  const SOURCE_PLACEHOLDER = `// Paste a JavaScript bundle here
fetch('/api/v1/users', { method: 'POST' });`;

  let sourceInput = '';
  let loading = false;
  let statusMessage = '';
  let errorMessage = '';
  let warningMessage = '';
  let activeTab = 'endpoints';
  let results = null;
  let beautifiedSource = '';
  let analysisMeta = null;
  let sourceActionStatus = '';
  let expandedFunctionKey = '';
  let expandedFunctionCode = '';
  let functionCopyStatus = '';
  let functionCopyTimer;
  let functionCopyRequestId = 0;

  $: highlightedSource =
    beautifiedSource && beautifiedSource.length <= HIGHLIGHT_LIMIT
      ? hljs.highlight(beautifiedSource, { language: 'javascript', ignoreIllegals: true }).value
      : '';

  $: tabs = [
    { id: 'endpoints', label: 'Endpoints', count: results?.endpoints?.length ?? 0 },
    { id: 'sensitive', label: 'Secrets', count: results?.sensitiveFindings?.length ?? 0 },
    { id: 'requests', label: 'Ajax / Fetch', count: results?.ajaxCalls?.length ?? 0 },
    { id: 'dom-xss', label: 'Potential DOM XSS', count: results?.domXssFindings?.length ?? 0 },
    { id: 'functions', label: 'Functions', count: results?.interestingFunctions?.length ?? 0 },
    { id: 'source', label: 'Beautified source', count: null }
  ];

  function runAnalysisInWorker(source) {
    return new Promise((resolve, reject) => {
      const worker = new Worker(new URL('./lib/analysis.worker.js', import.meta.url), {
        type: 'module'
      });
      let settled = false;

      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        worker.terminate();
        callback(value);
      };

      worker.onmessage = ({ data }) => {
        if (data?.type === 'status') {
          statusMessage = data.message;
        } else if (data?.type === 'result') {
          finish(resolve, data);
        } else if (data?.type === 'error') {
          finish(reject, new Error(data.message || 'Analysis worker failed.'));
        }
      };

      worker.onerror = (event) => {
        finish(reject, new Error(event.message || 'Analysis worker failed to load.'));
      };

      worker.postMessage({ source });
    });
  }

  async function handleAnalyze() {
    errorMessage = '';
    warningMessage = '';
    sourceActionStatus = '';

    const source = sourceInput;
    if (!source.trim()) {
      errorMessage = 'Paste JavaScript source code before starting the analysis.';
      return;
    }

    loading = true;
    results = null;
    beautifiedSource = '';
    analysisMeta = null;
    expandedFunctionKey = '';
    expandedFunctionCode = '';
    resetFunctionCopyFeedback();
    activeTab = 'endpoints';
    statusMessage = 'Beautifying pasted source...';

    const startedAt = performance.now();

    try {
      const workerResult = await runAnalysisInWorker(source);
      beautifiedSource = workerResult.beautifiedSource;
      results = workerResult.results;
      warningMessage = workerResult.warningMessage;
      analysisMeta = {
        sourceBytes: new TextEncoder().encode(source).byteLength,
        durationMs: Math.round(performance.now() - startedAt),
        lineCount: source.split(/\r?\n/).length
      };
    } catch (error) {
      errorMessage = error.message || 'Analysis failed unexpectedly.';
    } finally {
      loading = false;
      statusMessage = '';
    }
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / 1024 ** index;
    return `${value.toFixed(index === 0 || value >= 10 ? 0 : 1)} ${units[index]}`;
  }

  async function copySource() {
    try {
      await navigator.clipboard.writeText(beautifiedSource);
      sourceActionStatus = 'Copied';
    } catch {
      sourceActionStatus = 'Copy failed';
    }
    setTimeout(() => (sourceActionStatus = ''), 1800);
  }

  function resetAnalysis() {
    results = null;
    beautifiedSource = '';
    analysisMeta = null;
    warningMessage = '';
    sourceActionStatus = '';
    expandedFunctionKey = '';
    expandedFunctionCode = '';
    resetFunctionCopyFeedback();
  }

  function functionKey(finding, index) {
    return `${finding.line || 0}:${finding.name}:${index}`;
  }

  function resetFunctionCopyFeedback() {
    functionCopyRequestId += 1;
    clearTimeout(functionCopyTimer);
    functionCopyTimer = undefined;
    functionCopyStatus = '';
  }

  function toggleFunction(finding, index) {
    const key = functionKey(finding, index);
    if (expandedFunctionKey === key) {
      expandedFunctionKey = '';
      expandedFunctionCode = '';
      resetFunctionCopyFeedback();
      return;
    }

    const hasValidOffsets =
      Number.isInteger(finding.start) &&
      Number.isInteger(finding.end) &&
      finding.start >= 0 &&
      finding.end > finding.start &&
      finding.end <= beautifiedSource.length;

    expandedFunctionKey = key;
    resetFunctionCopyFeedback();
    expandedFunctionCode = hasValidOffsets
      ? beautifiedSource.slice(finding.start, finding.end)
      : finding.code || '';
  }

  async function copyFunctionCode() {
    if (!expandedFunctionCode) return;

    resetFunctionCopyFeedback();
    const activeKey = expandedFunctionKey;
    const activeCode = expandedFunctionCode;
    const requestId = functionCopyRequestId;
    try {
      await navigator.clipboard.writeText(activeCode);
      if (requestId !== functionCopyRequestId || expandedFunctionKey !== activeKey) return;
      functionCopyStatus = 'Copied';
    } catch {
      if (requestId !== functionCopyRequestId || expandedFunctionKey !== activeKey) return;
      functionCopyStatus = 'Copy failed';
    }

    functionCopyTimer = setTimeout(() => {
      if (expandedFunctionKey === activeKey) functionCopyStatus = '';
      functionCopyTimer = undefined;
    }, 1800);
  }

  function highlightFunction(code) {
    return hljs.highlight(code, { language: 'javascript', ignoreIllegals: true }).value;
  }

  function domXssSnippet(finding) {
    const hasValidOffsets =
      Number.isInteger(finding.start) &&
      Number.isInteger(finding.end) &&
      finding.start >= 0 &&
      finding.end > finding.start &&
      finding.end <= beautifiedSource.length;

    return hasValidOffsets
      ? beautifiedSource.slice(finding.start, finding.end)
      : finding.evidence || '';
  }

  function clearSource() {
    sourceInput = '';
    errorMessage = '';
    resetAnalysis();
  }

  function handleSourceChanged() {
    errorMessage = '';
    if (results) resetAnalysis();
  }

  async function pasteSource() {
    try {
      sourceInput = await navigator.clipboard.readText();
      errorMessage = '';
      resetAnalysis();
    } catch {
      errorMessage = 'Clipboard access was denied. Click inside the editor and use Ctrl+V instead.';
    }
  }

  function downloadSource() {
    const blob = new Blob([beautifiedSource], { type: 'application/javascript;charset=utf-8' });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = 'pasted-source.beautified.js';
    link.click();
    URL.revokeObjectURL(downloadUrl);
  }
</script>

<svelte:head>
  <title>JS Recon Lab — Client-side JavaScript Analyzer</title>
  <meta
    name="description"
    content="Analyze JavaScript bundles for endpoints, sensitive strings, request parameters, potential DOM XSS flows, and security-relevant functions."
  />
</svelte:head>

<div class="min-h-screen bg-slate-950 text-slate-100 selection:bg-emerald-400/30 selection:text-emerald-100">
  <div class="pointer-events-none fixed inset-0 overflow-hidden" aria-hidden="true">
    <div class="absolute left-1/2 top-[-16rem] h-[36rem] w-[36rem] -translate-x-1/2 rounded-full bg-emerald-500/10 blur-[120px]"></div>
    <div class="absolute bottom-[-18rem] right-[-12rem] h-[34rem] w-[34rem] rounded-full bg-cyan-500/10 blur-[120px]"></div>
    <div class="cyber-grid absolute inset-0 opacity-30"></div>
  </div>

  <header class="relative border-b border-white/5 bg-slate-950/75 backdrop-blur-xl">
    <div class="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
      <div class="flex items-center gap-3">
        <div class="grid h-10 w-10 place-items-center rounded-xl border border-emerald-400/30 bg-emerald-400/10 shadow-glow">
          <svg viewBox="0 0 24 24" class="h-5 w-5 text-emerald-300" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
            <path d="m8 9-3 3 3 3M16 9l3 3-3 3M14 5l-4 14" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </div>
        <div>
          <p class="font-mono text-sm font-semibold tracking-[0.18em] text-white">JS RECON LAB</p>
          <p class="text-xs text-slate-500">Static bundle intelligence</p>
        </div>
      </div>
      <div class="hidden items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/5 px-3 py-1.5 text-xs text-emerald-300 sm:flex">
        <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.9)]"></span>
        Analysis runs locally
      </div>
    </div>
  </header>

  <main class="relative mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8 lg:py-14">
    <section class="mx-auto max-w-4xl text-center">
      <p class="mb-3 font-mono text-xs uppercase tracking-[0.28em] text-emerald-400">Browser-based reconnaissance</p>
      <h1 class="text-balance text-3xl font-semibold tracking-tight text-white sm:text-5xl">
        Turn tangled JavaScript into
        <span class="text-emerald-300">actionable attack-surface clues.</span>
      </h1>
      <p class="mx-auto mt-4 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
        Paste a JavaScript bundle to uncover hidden routes, request payloads, potential DOM XSS flows, and sensitive actions entirely in your browser.
      </p>
    </section>

    <section class="mx-auto mt-9 max-w-5xl rounded-2xl border border-white/10 bg-slate-900/70 p-4 shadow-2xl shadow-black/30 backdrop-blur-xl sm:p-6">
      <form on:submit|preventDefault={handleAnalyze}>
        <div class="mb-2 flex items-center justify-between gap-3">
          <label for="source-input" class="block text-sm font-medium text-slate-200">JavaScript source</label>
          <span class="font-mono text-[11px] text-slate-500">{sourceInput.length.toLocaleString()} characters</span>
        </div>

        <div class="overflow-hidden rounded-xl border border-white/10 bg-slate-950/80 transition focus-within:border-emerald-400/50 focus-within:ring-4 focus-within:ring-emerald-400/10">
          <div class="flex items-center justify-between border-b border-white/5 bg-white/[0.025] px-4 py-2.5">
            <div class="flex items-center gap-1.5" aria-hidden="true">
              <span class="h-2.5 w-2.5 rounded-full bg-rose-400/70"></span>
              <span class="h-2.5 w-2.5 rounded-full bg-amber-400/70"></span>
              <span class="h-2.5 w-2.5 rounded-full bg-emerald-400/70"></span>
            </div>
            <span class="font-mono text-[10px] uppercase tracking-wider text-slate-600">pasted-source.js</span>
          </div>

          <textarea
            id="source-input"
            bind:value={sourceInput}
            on:input={handleSourceChanged}
            rows="14"
            placeholder={SOURCE_PLACEHOLDER}
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            disabled={loading}
            class="block min-h-72 w-full resize-y bg-transparent p-4 font-mono text-[13px] leading-6 text-slate-200 outline-none placeholder:text-slate-700 disabled:cursor-wait disabled:opacity-60"
          ></textarea>
        </div>

        <div class="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div class="flex items-center gap-2">
            <button
              type="button"
              on:click={pasteSource}
              disabled={loading}
              class="source-action h-10 px-3"
            >
              Paste from clipboard
            </button>
            <button
              type="button"
              on:click={clearSource}
              disabled={loading || !sourceInput}
              class="source-action h-10 px-3 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Clear
            </button>
          </div>

          <button
            type="submit"
            disabled={loading || !sourceInput.trim()}
            class="inline-flex h-12 shrink-0 items-center justify-center gap-2 rounded-xl bg-emerald-400 px-5 text-sm font-semibold text-slate-950 shadow-lg shadow-emerald-950/30 transition hover:bg-emerald-300 focus:outline-none focus:ring-4 focus:ring-emerald-400/20 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {#if loading}
              <svg class="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle class="opacity-30" cx="12" cy="12" r="9" stroke="currentColor" stroke-width="3"></circle>
                <path class="opacity-90" d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" stroke-width="3" stroke-linecap="round"></path>
              </svg>
              Analyzing…
            {:else}
              <svg viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="1.9" aria-hidden="true">
                <path d="m21 21-4.3-4.3M19 11a8 8 0 1 1-16 0 8 8 0 0 1 16 0Z" stroke-linecap="round" />
              </svg>
              Beautify &amp; Analyze
            {/if}
          </button>
        </div>

        <p class="mt-3 text-xs text-slate-500">
          The pasted source stays in this browser and is analyzed as text—it is never executed.
        </p>
      </form>

      <div aria-live="polite" aria-atomic="true">
        {#if loading}
          <div class="mt-4 flex items-center gap-3 rounded-xl border border-cyan-400/10 bg-cyan-400/5 px-4 py-3 text-sm text-cyan-200">
            <span class="relative flex h-2 w-2">
              <span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-300 opacity-70"></span>
              <span class="relative inline-flex h-2 w-2 rounded-full bg-cyan-300"></span>
            </span>
            {statusMessage}
          </div>
        {/if}
        {#if errorMessage}
          <div class="mt-4 rounded-xl border border-rose-400/20 bg-rose-400/10 px-4 py-3 text-sm text-rose-200">
            {errorMessage}
          </div>
        {/if}
        {#if warningMessage}
          <div class="mt-4 rounded-xl border border-amber-400/20 bg-amber-400/10 px-4 py-3 text-sm leading-5 text-amber-100/90">
            {warningMessage}
          </div>
        {/if}
      </div>
    </section>

    {#if results}
      <section class="mt-8" aria-label="Analysis results">
        <div class="mb-4 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div class="min-w-0">
            <p class="text-sm font-semibold text-white">Analysis complete</p>
            <p class="mt-1 font-mono text-xs text-slate-500">Pasted JavaScript source</p>
          </div>
          <div class="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] uppercase tracking-wider text-slate-500">
            <span>{formatBytes(analysisMeta.sourceBytes)}</span>
            <span>{analysisMeta.lineCount.toLocaleString()} input lines</span>
            <span>{analysisMeta.durationMs} ms</span>
          </div>
        </div>

        <div class="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-5">
          {#each [
            { label: 'Endpoints', value: results.endpoints.length, color: 'text-cyan-300' },
            { label: 'Sensitive hits', value: results.sensitiveFindings.length, color: 'text-amber-300' },
            { label: 'Network calls', value: results.ajaxCalls.length, color: 'text-violet-300' },
            { label: 'DOM XSS leads', value: results.domXssFindings.length, color: 'text-rose-300' },
            { label: 'Action functions', value: results.interestingFunctions.length, color: 'text-emerald-300' }
          ] as stat}
            <div class="rounded-xl border border-white/8 bg-slate-900/60 px-4 py-4">
              <p class="text-xs text-slate-500">{stat.label}</p>
              <p class={`mt-1 font-mono text-2xl font-semibold ${stat.color}`}>{stat.value}</p>
            </div>
          {/each}
        </div>

        <div class="overflow-hidden rounded-2xl border border-white/10 bg-slate-900/70 shadow-2xl shadow-black/20 backdrop-blur-xl">
          <div class="overflow-x-auto border-b border-white/10" role="tablist" aria-label="Finding categories">
            <div class="flex min-w-max px-2 pt-2">
              {#each tabs as tab}
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  on:click={() => (activeTab = tab.id)}
                  class={`relative flex items-center gap-2 rounded-t-lg px-4 py-3 text-sm transition ${
                    activeTab === tab.id
                      ? 'bg-white/5 font-medium text-emerald-300'
                      : 'text-slate-500 hover:bg-white/[0.025] hover:text-slate-300'
                  }`}
                >
                  {tab.label}
                  {#if tab.count !== null}
                    <span class={`rounded-full px-1.5 py-0.5 font-mono text-[10px] ${activeTab === tab.id ? 'bg-emerald-400/10 text-emerald-300' : 'bg-slate-800 text-slate-500'}`}>
                      {tab.count}
                    </span>
                  {/if}
                  {#if activeTab === tab.id}
                    <span class="absolute inset-x-2 bottom-0 h-px bg-emerald-300 shadow-[0_0_8px_rgba(110,231,183,0.8)]"></span>
                  {/if}
                </button>
              {/each}
            </div>
          </div>

          <div class="min-h-[24rem] p-4 sm:p-6">
            {#if activeTab === 'endpoints'}
              {#if results.endpoints.length}
                <div class="space-y-2">
                  {#each results.endpoints as endpoint}
                    <article class="flex flex-col gap-2 rounded-xl border border-white/5 bg-slate-950/55 px-4 py-3 sm:flex-row sm:items-start sm:justify-between">
                      <code class="min-w-0 break-all font-mono text-sm leading-6 text-cyan-100">{endpoint.value}</code>
                      <div class="flex shrink-0 items-center gap-2">
                        <span class="rounded-md bg-cyan-400/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-cyan-300">{endpoint.type}</span>
                        {#if endpoint.line}
                          <span class="font-mono text-[11px] text-slate-600">L{endpoint.line}</span>
                        {/if}
                      </div>
                    </article>
                  {/each}
                </div>
              {:else}
                <div class="empty-state"><p>No endpoint-like strings were found.</p></div>
              {/if}
            {:else if activeTab === 'sensitive'}
              {#if results.sensitiveFindings.length}
                <div class="space-y-3">
                  {#each results.sensitiveFindings as finding}
                    <article class="rounded-xl border border-amber-400/10 bg-amber-400/[0.035] p-4">
                      <div class="flex flex-wrap items-center gap-2">
                        <span class="rounded-md bg-amber-400/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-amber-300">{finding.keyword}</span>
                        {#if finding.line}<span class="font-mono text-[11px] text-slate-600">L{finding.line}</span>{/if}
                        <code class="break-all font-mono text-sm text-amber-100">{finding.value}</code>
                      </div>
                      {#if finding.context}
                        <pre class="mt-3 overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-slate-950/70 p-3 font-mono text-xs leading-5 text-slate-400">{finding.context}</pre>
                      {/if}
                    </article>
                  {/each}
                </div>
              {:else}
                <div class="empty-state"><p>No configured sensitive keywords were found.</p></div>
              {/if}
            {:else if activeTab === 'requests'}
              {#if results.ajaxCalls.length}
                <div class="grid gap-3 lg:grid-cols-2">
                  {#each results.ajaxCalls as call}
                    <article class="rounded-xl border border-violet-400/10 bg-violet-400/[0.035] p-4">
                      <div class="flex flex-wrap items-center gap-2">
                        <span class="rounded-md bg-violet-400/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-violet-300">{call.type}</span>
                        <span class="rounded-md border border-white/5 px-2 py-1 font-mono text-[10px] font-semibold text-slate-300">{call.method || 'UNKNOWN'}</span>
                        {#if call.line}<span class="ml-auto font-mono text-[11px] text-slate-600">L{call.line}</span>{/if}
                      </div>
                      <p class="mt-3 break-all font-mono text-sm leading-6 text-white">{call.url || '(dynamic URL expression)'}</p>
                      <div class="mt-4">
                        <p class="mb-2 text-[11px] uppercase tracking-wider text-slate-600">Detected parameters</p>
                        {#if call.parameters?.length}
                          <div class="flex flex-wrap gap-1.5">
                            {#each call.parameters as parameter}
                              <code class="rounded-md border border-white/5 bg-slate-950/70 px-2 py-1 font-mono text-xs text-slate-300">{parameter}</code>
                            {/each}
                          </div>
                        {:else}
                          <p class="text-xs text-slate-600">No static parameter keys recovered.</p>
                        {/if}
                      </div>
                    </article>
                  {/each}
                </div>
              {:else}
                <div class="empty-state"><p>No fetch, jQuery Ajax, or XMLHttpRequest calls were identified.</p></div>
              {/if}
            {:else if activeTab === 'dom-xss'}
              {#if results.domXssFindings.length}
                <div class="mb-4 rounded-xl border border-rose-400/15 bg-rose-400/[0.045] px-4 py-3 text-xs leading-5 text-rose-100/75">
                  These are static-analysis leads, not confirmed vulnerabilities. Validate whether attacker-controlled data can actually reach the reported sink without effective sanitization.
                </div>
                <div class="space-y-3">
                  {#each results.domXssFindings as finding}
                    <article class="rounded-xl border border-rose-400/15 bg-slate-950/55 p-4">
                      <div class="flex flex-wrap items-center gap-2">
                        <span class="rounded-md bg-rose-400/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-rose-300">Potential DOM XSS</span>
                        <span class={`rounded-md px-2 py-1 font-mono text-[10px] font-semibold uppercase tracking-wider ${
                          finding.severity === 'high' || finding.severity === 'critical'
                            ? 'bg-rose-400/15 text-rose-200'
                            : finding.severity === 'medium'
                              ? 'bg-amber-400/10 text-amber-200'
                              : 'bg-slate-700/60 text-slate-300'
                        }`}>{finding.severity || 'review'}</span>
                        <span class="rounded-md border border-white/5 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-slate-400">
                          {finding.confidence || 'unknown'} confidence
                        </span>
                        {#if finding.line}<span class="ml-auto font-mono text-[11px] text-slate-600">L{finding.line}</span>{/if}
                      </div>

                      <div class="mt-4 grid gap-3 sm:grid-cols-[1fr_auto_1fr] sm:items-center">
                        <div class="min-w-0 rounded-lg border border-white/5 bg-slate-900/60 p-3">
                          <p class="mb-1.5 text-[10px] uppercase tracking-wider text-slate-600">Untrusted source</p>
                          <code class="break-all font-mono text-xs text-cyan-200">{finding.source || 'Unresolved / sink-only'}</code>
                        </div>
                        <svg viewBox="0 0 20 20" class="mx-auto h-4 w-4 rotate-90 text-rose-400/60 sm:rotate-0" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                          <path d="M3 10h13m-4-4 4 4-4 4" stroke-linecap="round" stroke-linejoin="round" />
                        </svg>
                        <div class="min-w-0 rounded-lg border border-rose-400/10 bg-rose-400/[0.035] p-3">
                          <p class="mb-1.5 text-[10px] uppercase tracking-wider text-slate-600">Dangerous sink</p>
                          <code class="break-all font-mono text-xs text-rose-200">{finding.sink}</code>
                        </div>
                      </div>

                      {#if finding.path?.length}
                        <div class="mt-4">
                          <p class="mb-2 text-[10px] uppercase tracking-wider text-slate-600">Observed flow</p>
                          <div class="flex flex-wrap items-center gap-1.5">
                            {#each finding.path as step, pathIndex}
                              <code class="rounded-md border border-white/5 bg-slate-900/70 px-2 py-1 font-mono text-[11px] text-slate-300">{step}</code>
                              {#if pathIndex < finding.path.length - 1}
                                <span class="text-xs text-rose-400/60" aria-hidden="true">→</span>
                              {/if}
                            {/each}
                          </div>
                        </div>
                      {/if}

                      {#if domXssSnippet(finding)}
                        <div class="mt-4 overflow-hidden rounded-lg border border-white/5 bg-[#0d1117]">
                          <p class="border-b border-white/5 px-3 py-2 text-[10px] uppercase tracking-wider text-slate-600">Evidence</p>
                          <pre class="max-h-64 overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-xs leading-5 text-slate-300">{domXssSnippet(finding)}</pre>
                        </div>
                      {/if}
                    </article>
                  {/each}
                </div>
              {:else}
                <div class="empty-state">
                  <p>No potential DOM XSS flows or dangerous sink usage were identified.</p>
                </div>
              {/if}
            {:else if activeTab === 'functions'}
              {#if results.interestingFunctions.length}
                <p class="mb-3 text-xs text-slate-500">Select a function to reveal its extracted source code.</p>
                <div class="space-y-3">
                  {#each results.interestingFunctions as fn, index}
                    <article class={`overflow-hidden rounded-xl border bg-emerald-400/[0.035] transition ${expandedFunctionKey === functionKey(fn, index) ? 'border-emerald-400/30' : 'border-emerald-400/10 hover:border-emerald-400/20'}`}>
                      <button
                        type="button"
                        on:click={() => toggleFunction(fn, index)}
                        aria-expanded={expandedFunctionKey === functionKey(fn, index)}
                        aria-controls={`function-code-${index}`}
                        class="block w-full p-4 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-emerald-400/50"
                      >
                        <div class="flex items-start justify-between gap-3">
                          <code class="break-all font-mono text-sm font-semibold text-emerald-200">{fn.name}</code>
                          <div class="flex shrink-0 items-center gap-3">
                            {#if fn.line}<span class="font-mono text-[11px] text-slate-600">L{fn.line}</span>{/if}
                            <svg
                              viewBox="0 0 20 20"
                              class={`h-4 w-4 text-emerald-300 transition-transform ${expandedFunctionKey === functionKey(fn, index) ? 'rotate-180' : ''}`}
                              fill="none"
                              stroke="currentColor"
                              stroke-width="1.8"
                              aria-hidden="true"
                            >
                              <path d="m5 7.5 5 5 5-5" stroke-linecap="round" stroke-linejoin="round" />
                            </svg>
                          </div>
                        </div>
                        <div class="mt-3 flex flex-wrap items-center gap-2">
                          <span class="rounded-md bg-emerald-400/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-emerald-300">{fn.matchedAction}</span>
                          {#if fn.signature}<code class="break-all font-mono text-xs text-slate-500">{fn.signature}</code>{/if}
                        </div>
                      </button>

                      {#if expandedFunctionKey === functionKey(fn, index)}
                        <div
                          id={`function-code-${index}`}
                          role="region"
                          aria-label={`${fn.name} source code`}
                          class="border-t border-emerald-400/10 bg-[#0d1117]"
                        >
                          {#if expandedFunctionCode}
                            <div class="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
                              <span class="font-mono text-[10px] uppercase tracking-wider text-slate-600">Function source</span>
                              <button
                                type="button"
                                on:click={copyFunctionCode}
                                class="source-action inline-flex items-center gap-1.5"
                                aria-label={`Copy ${fn.name} source code to clipboard`}
                                title="Copy function code to clipboard"
                              >
                                <svg viewBox="0 0 20 20" class="h-3.5 w-3.5" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                                  <rect x="6.5" y="6.5" width="9" height="9" rx="1.5"></rect>
                                  <path d="M13.5 6.5V5A1.5 1.5 0 0 0 12 3.5H5A1.5 1.5 0 0 0 3.5 5v7A1.5 1.5 0 0 0 5 13.5h1.5" stroke-linecap="round"></path>
                                </svg>
                                <span>{functionCopyStatus || 'Copy to clipboard'}</span>
                              </button>
                              <span class="sr-only" role="status" aria-live="polite">
                                {functionCopyStatus ? `${fn.name}: ${functionCopyStatus}` : ''}
                              </span>
                            </div>
                            {#if expandedFunctionCode.length > FUNCTION_HIGHLIGHT_LIMIT}
                              <p class="border-b border-amber-400/10 bg-amber-400/5 px-4 py-2 text-xs text-amber-200/70">
                                Syntax highlighting is disabled for this large function.
                              </p>
                            {/if}
                            <pre class="max-h-[32rem] overflow-auto p-4 text-[12px] leading-5"><code class="font-mono text-slate-300">{#if expandedFunctionCode.length <= FUNCTION_HIGHLIGHT_LIMIT}{@html highlightFunction(expandedFunctionCode)}{:else}{expandedFunctionCode}{/if}</code></pre>
                          {:else}
                            <p class="px-4 py-5 text-sm text-slate-500">Source code was not recoverable for this function.</p>
                          {/if}
                        </div>
                      {/if}
                    </article>
                  {/each}
                </div>
              {:else}
                <div class="empty-state"><p>No function names matched the configured sensitive actions.</p></div>
              {/if}
            {:else if activeTab === 'source'}
              <div class="overflow-hidden rounded-xl border border-white/10 bg-[#0d1117]">
                <div class="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
                  <div class="flex items-center gap-1.5" aria-hidden="true">
                    <span class="h-2.5 w-2.5 rounded-full bg-rose-400/70"></span>
                    <span class="h-2.5 w-2.5 rounded-full bg-amber-400/70"></span>
                    <span class="h-2.5 w-2.5 rounded-full bg-emerald-400/70"></span>
                  </div>
                  <div class="flex items-center gap-2">
                    <span class="min-w-12 text-right text-[11px] text-emerald-300" aria-live="polite">{sourceActionStatus}</span>
                    <button type="button" on:click={copySource} class="source-action">Copy</button>
                    <button type="button" on:click={downloadSource} class="source-action">Download</button>
                  </div>
                </div>
                {#if beautifiedSource.length > HIGHLIGHT_LIMIT}
                  <div class="border-b border-amber-400/10 bg-amber-400/5 px-4 py-2 text-xs text-amber-200/70">
                    Syntax highlighting is disabled for this large bundle to keep the viewer responsive.
                  </div>
                {/if}
                <pre class="max-h-[70vh] overflow-auto p-4 text-[12px] leading-5"><code class="font-mono text-slate-300">{#if highlightedSource}{@html highlightedSource}{:else}{beautifiedSource}{/if}</code></pre>
              </div>
            {/if}
          </div>
        </div>
      </section>
    {:else if !loading}
      <section class="mx-auto mt-10 grid max-w-5xl gap-3 sm:grid-cols-3" aria-label="Analyzer capabilities">
        {#each [
          { index: '01', title: 'Map attack surface', copy: 'Recover absolute URLs, relative routes, API paths, and server-side script targets.' },
          { index: '02', title: 'Trace data flow', copy: 'Inspect fetch, jQuery Ajax, XHR methods, and statically recoverable payload keys.' },
          { index: '03', title: 'Trace DOM XSS risk', copy: 'Correlate browser-controlled values with dangerous HTML and script execution sinks.' }
        ] as feature}
          <article class="rounded-xl border border-white/5 bg-slate-900/30 p-4">
            <p class="font-mono text-[10px] tracking-widest text-emerald-400/60">{feature.index}</p>
            <h2 class="mt-2 text-sm font-medium text-slate-200">{feature.title}</h2>
            <p class="mt-2 text-xs leading-5 text-slate-500">{feature.copy}</p>
          </article>
        {/each}
      </section>
    {/if}
  </main>

  <footer class="relative border-t border-white/5 px-4 py-5 text-center text-xs text-slate-600">
    Use only on assets you own or are explicitly authorized to assess. Findings require manual validation.
  </footer>
</div>
