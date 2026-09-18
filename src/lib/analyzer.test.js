import { describe, expect, test } from 'bun:test';
import {
  analyzeJavaScript,
  extractAjaxCalls,
  extractDomXssFindings,
  extractEndpoints,
  extractInterestingFunctions,
  extractSensitiveFindings
} from './analyzer.js';

describe('Potential DOM XSS extraction', () => {
  test('detects a direct location.hash to innerHTML flow with a revealable range', () => {
    const source = `const output = document.querySelector('#output');
output.innerHTML = location.hash;`;
    const findings = extractDomXssFindings(source);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toEqual(
      expect.objectContaining({
        sink: 'innerHTML',
        source: 'location.hash',
        line: 2,
        severity: 'high',
        confidence: 'high',
        path: ['location.hash', 'innerHTML']
      })
    );
    expect(source.slice(findings[0].start, findings[0].end)).toBe(
      'output.innerHTML = location.hash;'
    );
  });

  test('tracks aliases, concatenation, and templates into HTML sinks', () => {
    const source = `const raw = location.search;
const alias = '<strong>' + raw + '</strong>';
const markup = \`<section>\${alias}</section>\`;
panel.innerHTML = markup;`;
    const [finding] = extractDomXssFindings(source);

    expect(finding.source).toBe('location.search');
    expect(finding.path).toEqual(['location.search', 'raw', 'alias', 'markup', 'innerHTML']);
    expect(finding.confidence).toBe('high');
  });

  test('detects insertAdjacentHTML, document.write, eval, and jQuery html', () => {
    const source = `node.insertAdjacentHTML('beforeend', location.search);
document.write(document.URL);
eval(window.location.hash);
$('#preview').html(event.data);`;
    const findings = extractDomXssFindings(source);

    expect(findings.map(({ sink }) => sink)).toEqual([
      'insertAdjacentHTML',
      'document.write',
      'eval',
      'jQuery.html'
    ]);
    expect(findings.every(({ severity }) => severity === 'high')).toBe(true);
    expect(findings.map(({ source: findingSource }) => findingSource)).toEqual([
      'location.search',
      'document.URL',
      'window.location.hash',
      'event.data'
    ]);
  });

  test('detects both call and constructor forms of the Function code sink', () => {
    const source = `Function(location.hash);
new Function(location.search);`;
    const findings = extractDomXssFindings(source);

    expect(findings.map(({ sink }) => sink)).toEqual([
      'Function constructor',
      'Function constructor'
    ]);
    expect(findings.map(({ source: findingSource }) => findingSource)).toEqual([
      'location.hash',
      'location.search'
    ]);
  });

  test('detects tainted React dangerouslySetInnerHTML props', () => {
    const source = `React.createElement('div', {
  dangerouslySetInnerHTML: { __html: location.hash }
});
React.createElement('div', {
  dangerouslySetInnerHTML: { __html: '<strong>constant</strong>' }
});`;
    const findings = extractDomXssFindings(source);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toEqual(
      expect.objectContaining({
        sink: 'React.dangerouslySetInnerHTML',
        source: 'location.hash',
        confidence: 'high'
      })
    );
  });

  test('propagates a tainted call argument into a function parameter sink', () => {
    const source = `function renderPreview(markup) {
  preview.innerHTML = markup;
}
renderPreview(location.hash);`;
    const [finding] = extractDomXssFindings(source);

    expect(finding).toEqual(
      expect.objectContaining({
        sink: 'innerHTML',
        source: 'location.hash',
        line: 2,
        confidence: 'high'
      })
    );
    expect(finding.path).toEqual(['location.hash', 'markup', 'innerHTML']);
  });

  test('does not report textContent, constants, or obviously sanitized HTML', () => {
    const source = `safeNode.textContent = location.hash;
constantNode.innerHTML = '<strong>Known-safe constant</strong>';
const clean = DOMPurify.sanitize(location.search);
sanitizedNode.innerHTML = clean;
const policy = trustedTypes.createPolicy('app', { createHTML: value => DOMPurify.sanitize(value) });
trustedNode.innerHTML = policy.createHTML(location.hash);`;

    expect(extractDomXssFindings(source)).toEqual([]);
  });

  test('does not trust an identity Trusted Types policy as a sanitizer', () => {
    const source = `const unsafePolicy = trustedTypes.createPolicy('unsafe', {
  createHTML: value => value
});
target.innerHTML = unsafePolicy.createHTML(location.hash);`;
    const [finding] = extractDomXssFindings(source);

    expect(finding).toEqual(
      expect.objectContaining({
        sink: 'innerHTML',
        source: 'location.hash',
        severity: 'high'
      })
    );
  });

  test('does not blindly suppress custom sanitizer-named functions', () => {
    const source = `function sanitizeHTML(value) { return value; }
target.innerHTML = sanitizeHTML(location.hash);`;
    const [finding] = extractDomXssFindings(source);

    expect(finding).toEqual(
      expect.objectContaining({
        sink: 'innerHTML',
        source: 'location.hash',
        confidence: 'high'
      })
    );
  });

  test('detects high-risk jQuery insertion methods', () => {
    const source = `$('#one').append(location.hash);
$('#two').prepend(location.search);
$('#three').before(document.URL);
$('#four').after(event.data);
$('#five').replaceWith(window.location.hash);`;

    expect(extractDomXssFindings(source).map(({ sink }) => sink)).toEqual([
      'jQuery.append',
      'jQuery.prepend',
      'jQuery.before',
      'jQuery.after',
      'jQuery.replaceWith'
    ]);
  });

  test('detects static srcdoc and event-handler setAttribute sinks', () => {
    const source = `frame.setAttribute('srcdoc', location.hash);
button.setAttribute('onclick', location.search);
button.setAttribute(dynamicName, location.hash);`;
    const findings = extractDomXssFindings(source);

    expect(findings.map(({ sink }) => sink)).toEqual([
      'setAttribute(srcdoc)',
      'setAttribute(onclick)'
    ]);
    expect(findings.every(({ confidence }) => confidence === 'high')).toBe(true);
  });

  test('preserves taint through URLSearchParams and common string transforms', () => {
    const source = `const params = new URLSearchParams(location.search);
const query = params.get('q').slice(1).trim();
result.innerHTML = query;`;
    const [finding] = extractDomXssFindings(source);

    expect(finding).toEqual(
      expect.objectContaining({
        sink: 'innerHTML',
        source: 'location.search',
        confidence: 'high'
      })
    );
    expect(finding.path).toEqual(
      expect.arrayContaining(['URLSearchParams()', 'params', 'query', 'innerHTML'])
    );
  });

  test('reports unresolved dynamic HTML as low-confidence sink-only evidence', () => {
    const [finding] = extractDomXssFindings(`target.outerHTML = serverResponse;`);
    expect(finding).toEqual(
      expect.objectContaining({
        sink: 'outerHTML',
        source: 'Unresolved dynamic value',
        severity: 'medium',
        confidence: 'low',
        path: ['outerHTML']
      })
    );
  });

  test('uses source-to-sink regex recovery when malformed code prevents parsing', () => {
    const source = `const broken = ;
const payload = location.hash;
target.innerHTML = payload;`;
    const analysis = analyzeJavaScript(source);

    expect(analysis.parseError).toBeString();
    expect(analysis.domXssFindings).toHaveLength(1);
    expect(analysis.domXssFindings[0]).toEqual(
      expect.objectContaining({
        sink: 'innerHTML',
        source: 'location.hash',
        line: 3,
        severity: 'high',
        confidence: 'high'
      })
    );
    expect(source.slice(analysis.domXssFindings[0].start, analysis.domXssFindings[0].end)).toBe(
      'target.innerHTML = payload;'
    );
  });
});

describe('endpoint extraction', () => {
  test('finds and classifies common endpoint forms without duplicates', () => {
    const source = `
      const absolute = 'https://target.test/api/users';
      const api = '/api/v1/files';
      const handler = 'handlers/upload.ashx?mode=create';
      const apiAgain = '/api/v1/files';
    `;

    expect(extractEndpoints(source)).toEqual([
      { value: 'https://target.test/api/users', type: 'absolute', line: 2 },
      { value: '/api/v1/files', type: 'api', line: 3 },
      { value: 'handlers/upload.ashx?mode=create', type: 'server-script', line: 4 }
    ]);
  });
});

describe('sensitive finding extraction', () => {
  test('reports sensitive variables, properties, and strings with context', () => {
    const source = `
      const api_key = 'demo-key';
      const config = { password: 'hunter2' };
      console.log('Bearer ey.example');
    `;

    const findings = extractSensitiveFindings(source);
    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ keyword: 'api_key', value: "'demo-key'", line: 2 }),
        expect.objectContaining({ keyword: 'password', value: "'hunter2'", line: 3 }),
        expect.objectContaining({ keyword: 'bearer', value: 'Bearer ey.example', line: 4 })
      ])
    );
  });
});

describe('Ajax extraction', () => {
  test('resolves fetch URLs, methods, query fields, and JSON body keys', () => {
    const source = `
      const base = '/api/v1';
      const payload = { oldName: 'a', newName: 'b', meta: { admin: true } };
      fetch(base + '/rename?id=12', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
    `;

    expect(extractAjaxCalls(source)).toEqual([
      {
        type: 'fetch',
        url: '/api/v1/rename?id=12',
        method: 'POST',
        parameters: ['oldName', 'newName', 'meta', 'admin', 'id'],
        line: 4
      }
    ]);
  });

  test('extracts jQuery ajax options and data keys', () => {
    const source = `
      $.ajax({
        url: '/admin/create.php',
        type: 'PUT',
        data: { username: user, role: 'admin' }
      });
    `;

    expect(extractAjaxCalls(source)).toEqual([
      {
        type: 'jquery.ajax',
        url: '/admin/create.php',
        method: 'PUT',
        parameters: ['username', 'role'],
        line: 2
      }
    ]);
  });

  test('correlates XMLHttpRequest open/send and FormData keys', () => {
    const source = `
      const form = new FormData();
      form.append('file', selectedFile);
      form.append('destination', '/tmp');
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/v2/upload?overwrite=true');
      xhr.send(form);
    `;

    expect(extractAjaxCalls(source)).toEqual([
      {
        type: 'XMLHttpRequest',
        url: '/api/v2/upload?overwrite=true',
        method: 'POST',
        parameters: ['overwrite', 'file', 'destination'],
        line: 6
      }
    ]);
  });
});

describe('interesting function extraction', () => {
  test('handles declarations, arrow functions, object methods, and class methods', () => {
    const source = `
      function uploadAvatar(file) { return file; }
      const deleteUser = async (id) => id;
      const actions = { renameAsset(from, to) { return [from, to]; } };
      class Controller { executeCommand(command) { return command; } }
    `;

    const functions = extractInterestingFunctions(source);
    expect(functions.map(({ name, matchedAction }) => ({ name, matchedAction }))).toEqual([
      { name: 'uploadAvatar', matchedAction: 'upload' },
      { name: 'deleteUser', matchedAction: 'delete' },
      { name: 'renameAsset', matchedAction: 'rename' },
      { name: 'executeCommand', matchedAction: 'execute' }
    ]);
    expect(functions.every((finding) => finding.signature.includes('('))).toBe(true);
    expect(functions.map(({ start, end }) => source.slice(start, end))).toEqual([
      'function uploadAvatar(file) { return file; }',
      'const deleteUser = async (id) => id;',
      'renameAsset(from, to) { return [from, to]; }',
      'executeCommand(command) { return command; }'
    ]);
  });

  test('preserves exact multiline ranges and useful enclosing syntax', () => {
    const source = `export async function uploadReport(file) {
  const closingBrace = "}";
  return { file, closingBrace };
}

window.deleteAccount = function (id) {
  return request(id);
};

const actions = {
  renameAsset: (from, to) => {
    return { from, to };
  }
};`;

    const functions = extractInterestingFunctions(source);
    const snippets = Object.fromEntries(
      functions.map((finding) => [finding.name, source.slice(finding.start, finding.end)])
    );

    expect(snippets.uploadReport).toBe(`export async function uploadReport(file) {
  const closingBrace = "}";
  return { file, closingBrace };
}`);
    expect(snippets['window.deleteAccount']).toBe(`window.deleteAccount = function (id) {
  return request(id);
};`);
    expect(snippets.renameAsset).toBe(`renameAsset: (from, to) => {
    return { from, to };
  }`);
    expect(
      functions.every(
        ({ start, end }) => Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start
      )
    ).toBe(true);
  });

  test('recovers balanced function ranges when malformed source forces regex fallback', () => {
    const source = `const broken = ;
function uploadFallback(file) {
  const closingBrace = "}";
  return file;
}
const deleteFallback = (id) => {
  // A brace in a comment must not end the function: }
  return id;
};
const renameFallback = value => value.trim();
function createDangling(value)`;

    const analysis = analyzeJavaScript(source);
    const snippets = Object.fromEntries(
      analysis.interestingFunctions.map((finding) => [
        finding.name,
        source.slice(finding.start, finding.end)
      ])
    );

    expect(analysis.parseError).toBeString();
    expect(snippets.uploadFallback).toBe(`function uploadFallback(file) {
  const closingBrace = "}";
  return file;
}`);
    expect(snippets.deleteFallback).toBe(`const deleteFallback = (id) => {
  // A brace in a comment must not end the function: }
  return id;
};`);
    expect(snippets.renameFallback).toBe('const renameFallback = value => value.trim();');
    expect(snippets.createDangling).toBe('function createDangling(value)');
  });
});

describe('combined analysis', () => {
  test('returns a stable serializable shape and survives malformed JavaScript', () => {
    const valid = analyzeJavaScript(`fetch('/api/files', { body: { token: value } })`);
    expect(valid.parseError).toBeNull();
    expect(valid.endpoints[0]).toEqual({ value: '/api/files', type: 'api', line: 1 });
    expect(JSON.parse(JSON.stringify(valid))).toEqual(valid);

    const malformed = analyzeJavaScript(`const api_key = ; fetch('/fallback.php')`);
    expect(malformed.parseError).toBeString();
    expect(malformed.endpoints).toContainEqual({
      value: '/fallback.php',
      type: 'server-script',
      line: 1
    });
    expect(malformed.ajaxCalls).toContainEqual(
      expect.objectContaining({ type: 'fetch', url: '/fallback.php', method: 'GET' })
    );
  });

  test('uses fallbacks for all request styles and arrow functions after a parse error', () => {
    const source = `
      const broken = ;
      fetch('/fallback-fetch', { method: 'PATCH', body: { itemId: 7 } });
      $.ajax({ url: '/fallback-ajax.php', type: 'POST', data: { role: 'admin' } });
      const form = new FormData();
      form.append('file', selectedFile);
      form.set('overwrite', true);
      const request = new XMLHttpRequest();
      request.open('PUT', '/fallback-xhr.ashx?mode=replace');
      request.send(form);
      const deleteFallback = id => id;
    `;

    const analysis = analyzeJavaScript(source);
    expect(analysis.parseError).toBeString();
    expect(analysis.ajaxCalls).toEqual([
      expect.objectContaining({
        type: 'fetch',
        url: '/fallback-fetch',
        method: 'PATCH',
        parameters: ['itemId'],
        line: 3
      }),
      expect.objectContaining({
        type: 'jquery.ajax',
        url: '/fallback-ajax.php',
        method: 'POST',
        parameters: ['role'],
        line: 4
      }),
      expect.objectContaining({
        type: 'XMLHttpRequest',
        url: '/fallback-xhr.ashx?mode=replace',
        method: 'PUT',
        parameters: ['mode', 'file', 'overwrite'],
        line: 9
      })
    ]);
    expect(analysis.interestingFunctions).toContainEqual(
      expect.objectContaining({
        name: 'deleteFallback',
        matchedAction: 'delete',
        signature: 'deleteFallback(id)'
      })
    );
  });
});
