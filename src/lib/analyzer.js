import { parse } from 'acorn';

export const SENSITIVE_KEYWORDS = [
  'api_key',
  'token',
  'secret',
  'admin',
  'password',
  'bearer',
  'auth'
];

export const INTERESTING_ACTIONS = [
  'upload',
  'delete',
  'rename',
  'admin',
  'execute',
  'create'
];

const SERVER_SCRIPT_RE = /\.(?:aspx?|ashx|php|jsp|cgi)(?:[/?#]|$)/i;
const API_PATH_RE = /(?:^|\/)api(?:\/v\d+(?:\.\d+)?)?(?=\/|[?#]|$)/i;
const MAX_DISPLAY_LENGTH = 300;

function parseSource(source) {
  const options = {
    ecmaVersion: 'latest',
    locations: true,
    allowAwaitOutsideFunction: true,
    allowReturnOutsideFunction: true,
    allowHashBang: true
  };

  try {
    return { ast: parse(source, { ...options, sourceType: 'module' }), error: null };
  } catch (moduleError) {
    try {
      return { ast: parse(source, { ...options, sourceType: 'script' }), error: null };
    } catch (scriptError) {
      return {
        ast: null,
        error: scriptError?.message || moduleError?.message || 'Unable to parse source'
      };
    }
  }
}

function walk(node, enter, parent = null, grandparent = null) {
  if (!node || typeof node.type !== 'string') return;
  enter(node, parent, grandparent);

  for (const [key, child] of Object.entries(node)) {
    if (key === 'loc' || key === 'start' || key === 'end') continue;
    if (Array.isArray(child)) {
      for (const item of child) walk(item, enter, node, parent);
    } else if (child && typeof child === 'object' && typeof child.type === 'string') {
      walk(child, enter, node, parent);
    }
  }
}

function lineOf(node) {
  return node?.loc?.start?.line || 1;
}

function lineAt(source, index) {
  return source.slice(0, Math.max(0, index)).split('\n').length;
}

function compact(value, limit = MAX_DISPLAY_LENGTH) {
  const normalized = String(value ?? '').replace(/\s+/g, ' ').trim();
  return normalized.length > limit ? `${normalized.slice(0, limit - 3)}...` : normalized;
}

function sourceFor(node, source, limit = MAX_DISPLAY_LENGTH) {
  if (!node || typeof node.start !== 'number' || typeof node.end !== 'number') return '';
  return compact(source.slice(node.start, node.end), limit);
}

function propertyName(node, computed = false) {
  if (!node) return null;
  if (node.type === 'Identifier' && !computed) return node.name;
  if (node.type === 'PrivateIdentifier') return node.name;
  if (node.type === 'Literal') return String(node.value);
  return null;
}

function memberPropertyName(member) {
  return member?.type === 'MemberExpression'
    ? propertyName(member.property, member.computed)
    : null;
}

function expressionName(node, source) {
  if (!node) return '';
  if (node.type === 'Identifier' || node.type === 'PrivateIdentifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    const object = expressionName(node.object, source);
    const property = propertyName(node.property, node.computed) || sourceFor(node.property, source);
    return node.computed ? `${object}[${property}]` : `${object}.${property}`;
  }
  return sourceFor(node, source);
}

function callName(node, source) {
  return node?.type === 'CallExpression' || node?.type === 'NewExpression'
    ? expressionName(node.callee, source)
    : '';
}

function getObjectProperty(objectNode, wantedName, bindings, seen = new Set()) {
  const object = unwrapBinding(objectNode, bindings, seen);
  if (object?.type !== 'ObjectExpression') return null;

  for (const property of object.properties) {
    if (property.type !== 'Property') continue;
    const name = propertyName(property.key, property.computed);
    if (name?.toLowerCase() === wantedName.toLowerCase()) return property.value;
  }
  return null;
}

function unwrapBinding(node, bindings, seen = new Set()) {
  let current = node;
  while (current?.type === 'ChainExpression') current = current.expression;
  if (current?.type !== 'Identifier' || seen.has(current.name)) return current;
  const binding = bindings.get(current.name);
  if (!binding) return current;
  seen.add(current.name);
  return unwrapBinding(binding, bindings, seen);
}

function resolveValue(node, source, bindings, depth = 0, seen = new Set()) {
  if (!node || depth > 8) return '';
  if (node.type === 'ChainExpression') {
    return resolveValue(node.expression, source, bindings, depth + 1, seen);
  }
  if (node.type === 'Literal') return String(node.value ?? '');
  if (node.type === 'Identifier') {
    if (!bindings.has(node.name) || seen.has(node.name)) return node.name;
    const nextSeen = new Set(seen).add(node.name);
    return resolveValue(bindings.get(node.name), source, bindings, depth + 1, nextSeen);
  }
  if (node.type === 'TemplateLiteral') {
    let result = '';
    node.quasis.forEach((quasi, index) => {
      result += quasi.value.cooked ?? quasi.value.raw;
      if (node.expressions[index]) {
        const expression = node.expressions[index];
        const resolved = resolveValue(expression, source, bindings, depth + 1, new Set(seen));
        result += `\${${resolved || sourceFor(expression, source)}}`;
      }
    });
    return result;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return (
      resolveValue(node.left, source, bindings, depth + 1, new Set(seen)) +
      resolveValue(node.right, source, bindings, depth + 1, new Set(seen))
    );
  }
  return sourceFor(node, source);
}

function buildIndex(ast, source) {
  const bindings = new Map();
  const formData = new Map();
  const xhrVariables = new Set();
  const calls = [];

  walk(ast, (node) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init) {
      bindings.set(node.id.name, node.init);
      if (node.init.type === 'NewExpression' && callName(node.init, source).endsWith('FormData')) {
        formData.set(node.id.name, new Set());
      }
      if (node.init.type === 'NewExpression' && callName(node.init, source).endsWith('XMLHttpRequest')) {
        xhrVariables.add(node.id.name);
      }
    }

    if (
      node.type === 'AssignmentExpression' &&
      node.operator === '=' &&
      node.left.type === 'Identifier'
    ) {
      bindings.set(node.left.name, node.right);
      if (node.right.type === 'NewExpression' && callName(node.right, source).endsWith('FormData')) {
        formData.set(node.left.name, new Set());
      }
      if (node.right.type === 'NewExpression' && callName(node.right, source).endsWith('XMLHttpRequest')) {
        xhrVariables.add(node.left.name);
      }
    }

    if (node.type === 'CallExpression') calls.push(node);
  });

  calls.sort((a, b) => a.start - b.start);
  for (const call of calls) {
    if (call.callee.type !== 'MemberExpression') continue;
    const method = memberPropertyName(call.callee)?.toLowerCase();
    const object = call.callee.object;
    if ((method === 'append' || method === 'set') && object.type === 'Identifier') {
      const field = resolveValue(call.arguments[0], source, bindings);
      if (field && formData.has(object.name)) formData.get(object.name).add(field);
    }
  }

  return { bindings, formData, xhrVariables, calls };
}

function matchedSensitiveKeywords(value) {
  const text = String(value ?? '').toLowerCase();
  const compactText = text.replace(/[_-]/g, '');
  return SENSITIVE_KEYWORDS.filter((keyword) => {
    if (keyword === 'api_key') return compactText.includes('apikey');
    return text.includes(keyword);
  });
}

function matchedAction(name) {
  const lower = String(name ?? '').toLowerCase();
  return INTERESTING_ACTIONS.find((action) => lower.includes(action)) || null;
}

function endpointType(value) {
  const candidate = String(value).trim();
  if (/^(?:https?:)?\/\//i.test(candidate)) return 'absolute';
  if (SERVER_SCRIPT_RE.test(candidate)) return 'server-script';
  if (API_PATH_RE.test(candidate)) return 'api';
  return 'relative';
}

function isEndpoint(value) {
  if (typeof value !== 'string') return false;
  const candidate = value.trim();
  if (!candidate || /[\r\n]/.test(candidate) || candidate.length > 2048) return false;
  return (
    /^(?:https?:)?\/\//i.test(candidate) ||
    /^(?:\.\.\/|\.\/|\/)[^\s]+/.test(candidate) ||
    SERVER_SCRIPT_RE.test(candidate) ||
    API_PATH_RE.test(candidate)
  );
}

function addUnique(list, seen, key, item) {
  if (!key || seen.has(key)) return;
  seen.add(key);
  list.push(item);
}

function quotedStrings(source) {
  const results = [];
  const pattern = /(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/g;
  let match;
  while ((match = pattern.exec(source))) {
    const value = match[2]
      .replace(/\\\//g, '/')
      .replace(/\\(["'`\\])/g, '$1')
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r');
    results.push({ value, index: match.index, line: lineAt(source, match.index) });
  }
  return results;
}

function extractEndpointsFromAst(source, ast) {
  const endpoints = [];
  const seen = new Set();

  walk(ast, (node) => {
    let value = null;
    if (node.type === 'Literal' && typeof node.value === 'string') value = node.value;
    if (node.type === 'TemplateLiteral') value = resolveValue(node, source, new Map());
    if (!isEndpoint(value)) return;
    const trimmed = value.trim();
    addUnique(endpoints, seen, trimmed, {
      value: trimmed,
      type: endpointType(trimmed),
      line: lineOf(node)
    });
  });

  return endpoints;
}

export function extractEndpoints(source, suppliedAst = undefined) {
  const ast = suppliedAst === undefined ? parseSource(source).ast : suppliedAst;
  if (ast) return extractEndpointsFromAst(source, ast);

  const endpoints = [];
  const seen = new Set();
  for (const string of quotedStrings(source)) {
    if (!isEndpoint(string.value)) continue;
    const value = string.value.trim();
    addUnique(endpoints, seen, value, {
      value,
      type: endpointType(value),
      line: string.line
    });
  }
  return endpoints;
}

function extractSensitiveFromAst(source, ast) {
  const findings = [];
  const seen = new Set();

  const add = (textToMatch, value, line, context) => {
    for (const keyword of matchedSensitiveKeywords(textToMatch)) {
      const displayValue = compact(value);
      const key = `${keyword}|${displayValue}|${line}|${context}`;
      addUnique(findings, seen, key, { keyword, value: displayValue, line, context });
    }
  };

  walk(ast, (node, parent) => {
    if (node.type === 'VariableDeclarator') {
      const name = expressionName(node.id, source);
      add(name, node.init ? sourceFor(node.init, source) : name, lineOf(node), `variable ${name}`);
      return;
    }

    if (node.type === 'Property' || node.type === 'PropertyDefinition') {
      const name = propertyName(node.key, node.computed);
      if (name) add(name, sourceFor(node.value, source), lineOf(node), `property ${name}`);
      return;
    }

    if (node.type === 'AssignmentExpression') {
      const name = expressionName(node.left, source);
      add(name, sourceFor(node.right, source), lineOf(node), `assignment ${name}`);
      return;
    }

    if (
      node.type === 'Literal' &&
      typeof node.value === 'string' &&
      !(parent?.type === 'Property' && parent.key === node)
    ) {
      add(node.value, node.value, lineOf(node), 'string literal');
    }

    if (node.type === 'TemplateElement') {
      const value = node.value.cooked ?? node.value.raw;
      add(value, value, lineOf(node), 'template string');
    }
  });

  return findings;
}

export function extractSensitiveFindings(source, suppliedAst = undefined) {
  const ast = suppliedAst === undefined ? parseSource(source).ast : suppliedAst;
  if (ast) return extractSensitiveFromAst(source, ast);

  const findings = [];
  const seen = new Set();
  source.split(/\r?\n/).forEach((line, index) => {
    for (const keyword of matchedSensitiveKeywords(line)) {
      const value = compact(line);
      const key = `${keyword}|${value}|${index + 1}`;
      addUnique(findings, seen, key, {
        keyword,
        value,
        line: index + 1,
        context: 'source line'
      });
    }
  });
  return findings;
}

function collectObjectKeys(node, source, index, output, seen = new Set(), depth = 0) {
  if (!node || depth > 8) return;
  if (node.type === 'ChainExpression') {
    collectObjectKeys(node.expression, source, index, output, seen, depth + 1);
    return;
  }
  if (node.type === 'Identifier') {
    if (index.formData.has(node.name)) {
      for (const key of index.formData.get(node.name)) output.add(key);
      return;
    }
    if (seen.has(node.name)) return;
    const binding = index.bindings.get(node.name);
    if (binding) {
      seen.add(node.name);
      collectObjectKeys(binding, source, index, output, seen, depth + 1);
    }
    return;
  }
  if (node.type === 'ObjectExpression') {
    for (const property of node.properties) {
      if (property.type === 'SpreadElement') {
        collectObjectKeys(property.argument, source, index, output, seen, depth + 1);
        continue;
      }
      if (property.type !== 'Property') continue;
      const key = propertyName(property.key, property.computed) || sourceFor(property.key, source);
      if (key) output.add(key);
      if (property.value?.type === 'ObjectExpression') {
        collectObjectKeys(property.value, source, index, output, seen, depth + 1);
      }
    }
    return;
  }
  if (node.type === 'CallExpression' || node.type === 'NewExpression') {
    const name = callName(node, source);
    if (/^(?:JSON\.stringify|URLSearchParams)$/.test(name) || name.endsWith('.URLSearchParams')) {
      collectObjectKeys(node.arguments[0], source, index, output, seen, depth + 1);
    }
    return;
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    for (const match of node.value.matchAll(/(?:^|[?&])([^=&?#\s]+)=/g)) {
      try {
        output.add(decodeURIComponent(match[1]));
      } catch {
        output.add(match[1]);
      }
    }
  }
}

function parametersFor(node, url, source, index) {
  const parameters = new Set();
  collectObjectKeys(node, source, index, parameters);
  for (const match of String(url || '').matchAll(/[?&]([^=&?#\s]+)=/g)) {
    try {
      parameters.add(decodeURIComponent(match[1]));
    } catch {
      parameters.add(match[1]);
    }
  }
  return [...parameters];
}

function isFetchCall(call, source) {
  const name = callName(call, source);
  return name === 'fetch' || name.endsWith('.fetch');
}

function isJqueryAjaxCall(call) {
  if (call.callee.type !== 'MemberExpression') return false;
  if (memberPropertyName(call.callee)?.toLowerCase() !== 'ajax') return false;
  const object = call.callee.object;
  return object.type === 'Identifier' && (object.name === '$' || object.name === 'jQuery');
}

function ajaxFromFetch(call, source, index) {
  const url = resolveValue(call.arguments[0], source, index.bindings);
  const options = call.arguments[1];
  const methodNode = getObjectProperty(options, 'method', index.bindings);
  const bodyNode = getObjectProperty(options, 'body', index.bindings);
  return {
    type: 'fetch',
    url: compact(url),
    method: compact(resolveValue(methodNode, source, index.bindings) || 'GET').toUpperCase(),
    parameters: parametersFor(bodyNode, url, source, index),
    line: lineOf(call)
  };
}

function ajaxFromJquery(call, source, index) {
  let options = call.arguments[0];
  let urlNode;
  if (unwrapBinding(options, index.bindings)?.type === 'ObjectExpression') {
    urlNode = getObjectProperty(options, 'url', index.bindings);
  } else {
    urlNode = options;
    options = call.arguments[1];
  }
  const methodNode =
    getObjectProperty(options, 'method', index.bindings) ||
    getObjectProperty(options, 'type', index.bindings);
  const dataNode =
    getObjectProperty(options, 'data', index.bindings) ||
    getObjectProperty(options, 'body', index.bindings);
  const url = resolveValue(urlNode, source, index.bindings);
  return {
    type: 'jquery.ajax',
    url: compact(url),
    method: compact(resolveValue(methodNode, source, index.bindings) || 'GET').toUpperCase(),
    parameters: parametersFor(dataNode, url, source, index),
    line: lineOf(call)
  };
}

function extractAjaxFromAst(source, ast) {
  const index = buildIndex(ast, source);
  const calls = [];
  const xhrState = new Map();

  for (const call of index.calls) {
    if (isFetchCall(call, source)) {
      calls.push(ajaxFromFetch(call, source, index));
      continue;
    }
    if (isJqueryAjaxCall(call)) {
      calls.push(ajaxFromJquery(call, source, index));
      continue;
    }

    if (call.callee.type !== 'MemberExpression' || call.callee.object.type !== 'Identifier') continue;
    const variable = call.callee.object.name;
    if (!index.xhrVariables.has(variable)) continue;
    const methodName = memberPropertyName(call.callee)?.toLowerCase();
    if (methodName === 'open') {
      const method = resolveValue(call.arguments[0], source, index.bindings).toUpperCase() || 'GET';
      const url = resolveValue(call.arguments[1], source, index.bindings);
      const record = {
        type: 'XMLHttpRequest',
        url: compact(url),
        method: compact(method),
        parameters: parametersFor(null, url, source, index),
        line: lineOf(call)
      };
      calls.push(record);
      xhrState.set(variable, record);
    } else if (methodName === 'send' && xhrState.has(variable)) {
      const record = xhrState.get(variable);
      record.parameters = [
        ...new Set([
          ...record.parameters,
          ...parametersFor(call.arguments[0], record.url, source, index)
        ])
      ];
    }
  }

  return calls;
}

function findClosingDelimiter(source, openIndex, opening, closing) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let index = openIndex; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (character === '\n') lineComment = false;
      continue;
    }
    if (blockComment) {
      if (character === '*' && next === '/') {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === '/' && next === '/') {
      lineComment = true;
      index += 1;
      continue;
    }
    if (character === '/' && next === '*') {
      blockComment = true;
      index += 1;
      continue;
    }
    if (character === '"' || character === "'" || character === '`') {
      quote = character;
      continue;
    }
    if (character === opening) depth += 1;
    if (character === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function findClosingParenthesis(source, openIndex) {
  return findClosingDelimiter(source, openIndex, '(', ')');
}

function findClosingBrace(source, openIndex) {
  return findClosingDelimiter(source, openIndex, '{', '}');
}

function splitTopLevelArguments(value) {
  const parts = [];
  let start = 0;
  let quote = null;
  let escaped = false;
  let round = 0;
  let square = 0;
  let curly = 0;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'" || character === '`') {
      quote = character;
      continue;
    }
    if (character === '(') round += 1;
    else if (character === ')') round -= 1;
    else if (character === '[') square += 1;
    else if (character === ']') square -= 1;
    else if (character === '{') curly += 1;
    else if (character === '}') curly -= 1;
    else if (character === ',' && round === 0 && square === 0 && curly === 0) {
      parts.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(value.slice(start).trim());
  return parts;
}

function fallbackValue(value) {
  const trimmed = String(value || '').trim();
  if (trimmed.length >= 2 && /["'`]/.test(trimmed[0]) && trimmed.at(-1) === trimmed[0]) {
    return trimmed
      .slice(1, -1)
      .replace(/\\\//g, '/')
      .replace(/\\(["'`\\])/g, '$1');
  }
  return compact(trimmed);
}

function fallbackParameterKeys(value) {
  const keys = new Set();
  const text = String(value || '');
  for (const match of text.matchAll(/(?:^|[{,]\s*)(?:["']([^"']+)["']|([A-Za-z_$][\w$-]*))\s*:/g)) {
    keys.add(match[1] || match[2]);
  }
  const literal = fallbackValue(text);
  for (const match of literal.matchAll(/(?:^|[?&])([^=&?#\s]+)=/g)) {
    try {
      keys.add(decodeURIComponent(match[1]));
    } catch {
      keys.add(match[1]);
    }
  }
  return [...keys];
}

function fallbackFormData(source) {
  const forms = new Map();
  for (const match of source.matchAll(/\b([A-Za-z_$][\w$]*)\s*=\s*new\s+(?:window\.)?FormData\s*\(/g)) {
    forms.set(match[1], new Set());
  }
  for (const name of forms.keys()) {
    const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const appendPattern = new RegExp(
      `\\b${escapedName}\\s*\\.\\s*(?:append|set)\\s*\\(\\s*(["'\x60])((?:\\\\.|(?!\\1)[\\s\\S])*?)\\1`,
      'g'
    );
    for (const match of source.matchAll(appendPattern)) forms.get(name).add(fallbackValue(`${match[1]}${match[2]}${match[1]}`));
  }
  return forms;
}

function extractStandaloneAjaxFallback(source) {
  const calls = [];
  const callPattern = /(?:\bfetch|\$\s*\.\s*ajax|\bjQuery\s*\.\s*ajax)\s*\(/g;
  let match;
  while ((match = callPattern.exec(source))) {
    const openIndex = source.indexOf('(', match.index);
    const closeIndex = findClosingParenthesis(source, openIndex);
    if (closeIndex < 0) continue;
    const snippet = source.slice(match.index, closeIndex + 1);
    const parsed = parseSource(`${snippet};`);
    if (parsed.ast) {
      const baseLine = lineAt(source, match.index) - 1;
      for (const call of extractAjaxFromAst(`${snippet};`, parsed.ast)) {
        calls.push({ ...call, line: call.line + baseLine });
      }
    } else {
      const argumentsList = splitTopLevelArguments(source.slice(openIndex + 1, closeIndex));
      const isFetch = /^fetch\b/.test(match[0]);
      const urlMatch = (isFetch ? argumentsList[0] : snippet.match(/\burl\s*:\s*(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/i)?.[0]) || '';
      const quotedUrl = urlMatch.match(/(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/);
      const url = quotedUrl ? fallbackValue(quotedUrl[0]) : compact(argumentsList[0]);
      calls.push({
        type: isFetch ? 'fetch' : 'jquery.ajax',
        url,
        method: 'GET',
        parameters: fallbackParameterKeys(snippet),
        line: lineAt(source, match.index)
      });
    }
    callPattern.lastIndex = closeIndex + 1;
  }
  return calls;
}

function extractXhrFallback(source) {
  const calls = [];
  const forms = fallbackFormData(source);
  const constructorPattern = /\b([A-Za-z_$][\w$]*)\s*=\s*new\s+(?:window\.)?XMLHttpRequest\s*\(/g;

  for (const constructorMatch of source.matchAll(constructorPattern)) {
    const variable = constructorMatch[1];
    const escapedVariable = variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const openPattern = new RegExp(`\\b${escapedVariable}\\s*\\.\\s*open\\s*\\(`, 'g');
    openPattern.lastIndex = constructorMatch.index;
    let openMatch;
    while ((openMatch = openPattern.exec(source))) {
      const openIndex = source.indexOf('(', openMatch.index);
      const closeIndex = findClosingParenthesis(source, openIndex);
      if (closeIndex < 0) break;
      const args = splitTopLevelArguments(source.slice(openIndex + 1, closeIndex));
      const method = fallbackValue(args[0] || 'GET').toUpperCase();
      const url = fallbackValue(args[1] || '');
      const parameters = new Set(fallbackParameterKeys(url));

      const sendPattern = new RegExp(`\\b${escapedVariable}\\s*\\.\\s*send\\s*\\(`, 'g');
      sendPattern.lastIndex = closeIndex + 1;
      const sendMatch = sendPattern.exec(source);
      const nextOpen = openPattern.exec(source);
      if (sendMatch && (!nextOpen || sendMatch.index < nextOpen.index)) {
        const sendOpen = source.indexOf('(', sendMatch.index);
        const sendClose = findClosingParenthesis(source, sendOpen);
        if (sendClose > sendOpen) {
          const body = source.slice(sendOpen + 1, sendClose).trim();
          if (forms.has(body)) {
            for (const key of forms.get(body)) parameters.add(key);
          } else {
            for (const key of fallbackParameterKeys(body)) parameters.add(key);
          }
        }
      }

      calls.push({
        type: 'XMLHttpRequest',
        url: compact(url),
        method: compact(method),
        parameters: [...parameters],
        line: lineAt(source, openMatch.index)
      });
      if (!nextOpen) break;
      openPattern.lastIndex = nextOpen.index;
    }
  }
  return calls;
}

function extractAjaxFallback(source) {
  return [...extractStandaloneAjaxFallback(source), ...extractXhrFallback(source)].sort(
    (a, b) => a.line - b.line
  );
}

export function extractAjaxCalls(source, suppliedAst = undefined) {
  const ast = suppliedAst === undefined ? parseSource(source).ast : suppliedAst;
  return ast ? extractAjaxFromAst(source, ast) : extractAjaxFallback(source);
}

function functionDetails(node, parent, grandparent, source) {
  if (node.type === 'FunctionDeclaration') {
    if (!node.id) return null;
    const codeNode = /Export(?:Default|Named)Declaration/.test(parent?.type || '') ? parent : node;
    return { name: node.id.name, functionNode: node, codeNode };
  }
  if (
    (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') &&
    parent?.type === 'VariableDeclarator'
  ) {
    const codeNode = grandparent?.type === 'VariableDeclaration' ? grandparent : parent;
    return { name: expressionName(parent.id, source), functionNode: node, codeNode };
  }
  if (
    (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') &&
    parent?.type === 'AssignmentExpression'
  ) {
    const codeNode = grandparent?.type === 'ExpressionStatement' ? grandparent : parent;
    return { name: expressionName(parent.left, source), functionNode: node, codeNode };
  }
  if (node.type === 'FunctionExpression' && node.id) {
    return { name: node.id.name, functionNode: node, codeNode: node };
  }
  if (node.type === 'MethodDefinition' || node.type === 'PropertyDefinition') {
    const name = propertyName(node.key, node.computed);
    if (
      name &&
      (node.type === 'MethodDefinition' ||
        node.value?.type === 'FunctionExpression' ||
        node.value?.type === 'ArrowFunctionExpression')
    ) {
      return { name, functionNode: node.value || node, codeNode: node };
    }
  }
  if (node.type === 'Property' && (node.method || /FunctionExpression$/.test(node.value?.type || ''))) {
    const name = propertyName(node.key, node.computed);
    return name ? { name, functionNode: node.value, codeNode: node } : null;
  }
  return null;
}

function signatureFor(name, node, source) {
  const params = (node?.params || []).map((param) => sourceFor(param, source, 80)).join(', ');
  const prefix = node?.async ? 'async ' : '';
  const generator = node?.generator ? '*' : '';
  return compact(`${prefix}${generator}${name}(${params})`, 200);
}

function extendThroughSemicolon(source, end) {
  let cursor = end;
  while (source[cursor] === ' ' || source[cursor] === '\t') cursor += 1;
  return source[cursor] === ';' ? cursor + 1 : end;
}

function findFallbackExpressionEnd(source, start) {
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  let round = 0;
  let square = 0;
  let curly = 0;

  for (let index = start; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (character === '\n') {
        lineComment = false;
        if (round === 0 && square === 0 && curly === 0) return index;
      }
      continue;
    }
    if (blockComment) {
      if (character === '*' && next === '/') {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === '/' && next === '/') {
      if (round === 0 && square === 0 && curly === 0) return index;
      lineComment = true;
      index += 1;
      continue;
    }
    if (character === '/' && next === '*') {
      blockComment = true;
      index += 1;
      continue;
    }
    if (character === '"' || character === "'" || character === '`') {
      quote = character;
      continue;
    }
    if (character === '(') round += 1;
    else if (character === ')') round = Math.max(0, round - 1);
    else if (character === '[') square += 1;
    else if (character === ']') square = Math.max(0, square - 1);
    else if (character === '{') curly += 1;
    else if (character === '}') curly = Math.max(0, curly - 1);
    else if (character === ';' && round === 0 && square === 0 && curly === 0) return index + 1;
    else if (character === '\n' && round === 0 && square === 0 && curly === 0) return index;
  }
  return source.length;
}

function fallbackFunctionRange(source, match, kind) {
  const start = match.index;
  const minimumEnd = start + match[0].length;
  let bodyStart = minimumEnd;
  while (/\s/.test(source[bodyStart] || '')) bodyStart += 1;

  if (source[bodyStart] === '{') {
    const closingBrace = findClosingBrace(source, bodyStart);
    if (closingBrace >= 0) {
      return { start, end: extendThroughSemicolon(source, closingBrace + 1) };
    }
  } else if (kind === 'arrow' && bodyStart < source.length) {
    return { start, end: Math.max(minimumEnd, findFallbackExpressionEnd(source, bodyStart)) };
  }

  return { start, end: minimumEnd };
}

function extractFunctionsFromAst(source, ast) {
  const functions = [];
  const seen = new Set();
  walk(ast, (node, parent, grandparent) => {
    const details = functionDetails(node, parent, grandparent, source);
    if (!details?.name) return;
    const action = matchedAction(details.name);
    if (!action) return;
    const line = lineOf(details.codeNode || node);
    const key = `${details.name}|${line}`;
    addUnique(functions, seen, key, {
      name: details.name,
      matchedAction: action,
      line,
      signature: signatureFor(details.name, details.functionNode, source),
      start: (details.codeNode || details.functionNode).start,
      end: (details.codeNode || details.functionNode).end
    });
  });
  return functions;
}

function extractFunctionsFallback(source) {
  const functions = [];
  const seen = new Set();
  const patterns = [
    {
      kind: 'function',
      pattern: /(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/g
    },
    {
      kind: 'arrow',
      pattern: /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>/g
    },
    {
      kind: 'function',
      pattern: /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\*?(?:\s+[A-Za-z_$][\w$]*)?\s*\(([^)]*)\)/g
    }
  ];
  for (const { kind, pattern } of patterns) {
    let match;
    while ((match = pattern.exec(source))) {
      const action = matchedAction(match[1]);
      if (!action) continue;
      const line = lineAt(source, match.index);
      const key = `${match[1]}|${line}`;
      const range = fallbackFunctionRange(source, match, kind);
      addUnique(functions, seen, key, {
        name: match[1],
        matchedAction: action,
        line,
        signature: compact(`${match[1]}(${match[2] || match[3] || ''})`, 200),
        start: range.start,
        end: range.end
      });
    }
  }
  return functions;
}

export function extractInterestingFunctions(source, suppliedAst = undefined) {
  const ast = suppliedAst === undefined ? parseSource(source).ast : suppliedAst;
  return ast ? extractFunctionsFromAst(source, ast) : extractFunctionsFallback(source);
}

const DOM_XSS_SOURCE_MEMBER_RE = /^(?:(?:window|self)\.)?location\.(?:hash|search|href|pathname|origin)$|^(?:(?:window|self)\.)?document\.(?:URL|documentURI|referrer|cookie|location)$|^(?:(?:window|self)\.)?window\.name$|^(?:window\.)?name$|^history\.state$/i;
const DOM_XSS_EVENT_DATA_RE = /^(?:event|evt|messageEvent|message|e)\.data$/i;
const DOM_XSS_HTML_PROPERTIES = new Map([
  ['innerhtml', 'innerHTML'],
  ['outerhtml', 'outerHTML'],
  ['srcdoc', 'srcdoc']
]);
const DOM_XSS_PASSTHROUGH_CALL_RE = /^(?:decodeURI(?:Component)?|encodeURI(?:Component)?|String|atob|btoa|URL|URLSearchParams)$/;
const DOM_XSS_PASSTHROUGH_METHODS = new Set([
  'slice',
  'substring',
  'substr',
  'replace',
  'replaceall',
  'trim',
  'trimstart',
  'trimend',
  'tolowercase',
  'touppercase',
  'tostring',
  'concat',
  'normalize',
  'get',
  'getall',
  'decode'
]);
const DOM_XSS_JQUERY_HTML_METHODS = new Set([
  'html',
  'append',
  'prepend',
  'before',
  'after',
  'replacewith'
]);

function emptyDomFlow(dynamic = false, sanitized = false) {
  return { sources: [], dynamic, sanitized };
}

function domSourceFlow(name) {
  return {
    sources: [{ name, path: [name], confidence: 'high' }],
    dynamic: true,
    sanitized: false
  };
}

function domConfidenceRank(value) {
  return value === 'high' ? 3 : value === 'medium' ? 2 : 1;
}

function mergeDomFlows(...flows) {
  const sources = new Map();
  let dynamic = false;
  let sanitized = false;

  for (const flow of flows.flat()) {
    if (!flow) continue;
    dynamic ||= Boolean(flow.dynamic);
    sanitized ||= Boolean(flow.sanitized);
    for (const source of flow.sources || []) {
      const current = sources.get(source.name);
      if (
        !current ||
        domConfidenceRank(source.confidence) > domConfidenceRank(current.confidence) ||
        (source.confidence === current.confidence && source.path.length < current.path.length)
      ) {
        sources.set(source.name, {
          name: source.name,
          path: [...source.path],
          confidence: source.confidence
        });
      }
    }
  }

  return { sources: [...sources.values()], dynamic, sanitized };
}

function extendDomFlow(flow, step, confidence = null) {
  if (!flow) return emptyDomFlow();
  return {
    ...flow,
    sources: flow.sources.map((source) => ({
      ...source,
      confidence:
        confidence && domConfidenceRank(confidence) < domConfidenceRank(source.confidence)
          ? confidence
          : source.confidence,
      path: source.path.at(-1) === step ? [...source.path] : [...source.path, step]
    }))
  };
}

function domMemberSource(node, source) {
  if (node?.type !== 'MemberExpression') return null;
  const name = expressionName(node, source).replace(/\?\./g, '.');
  if (DOM_XSS_SOURCE_MEMBER_RE.test(name) || DOM_XSS_EVENT_DATA_RE.test(name)) return name;

  const property = memberPropertyName(node)?.toLowerCase();
  if (property === 'innerhtml' || property === 'outerhtml') return name;
  if (property !== 'value') return null;

  const object = node.object?.type === 'ChainExpression' ? node.object.expression : node.object;
  if (object?.type === 'CallExpression') {
    const getter = callName(object, source);
    if (/(?:getElementById|querySelector|querySelectorAll|getElementsBy\w+)$/.test(getter)) {
      return name;
    }
  }
  return null;
}

function isDomSanitizerCall(node, source, context) {
  if (node?.type !== 'CallExpression' && node?.type !== 'NewExpression') return false;
  const name = callName(node, source).replace(/\?\./g, '.');
  if (/^(?:window\.)?DOMPurify\.sanitize$/i.test(name)) return true;
  if (/^(?:window\.)?Sanitizer$/i.test(name)) return true;

  if (node.callee?.type === 'MemberExpression') {
    const method = memberPropertyName(node.callee)?.toLowerCase();
    const receiver = node.callee.object;
    if (
      (method === 'sanitize' || method === 'sanitizefor') &&
      ((receiver?.type === 'Identifier' && context.sanitizerInstances.has(receiver.name)) ||
        (receiver?.type === 'NewExpression' &&
          /^(?:window\.)?Sanitizer$/i.test(callName(receiver, source))))
    ) {
      return true;
    }
    if (
      method === 'createhtml' &&
      receiver?.type === 'Identifier' &&
      context.trustedPolicies.has(receiver.name)
    ) {
      return true;
    }
  }
  return false;
}

function trustedPolicyUsesDomPurify(call, source) {
  if (call?.type !== 'CallExpression') return false;
  if (!/^(?:window\.)?trustedTypes\.createPolicy$/i.test(callName(call, source))) return false;
  const options = call.arguments[1];
  if (options?.type !== 'ObjectExpression') return false;
  const createHtml = options.properties.find(
    (property) =>
      property.type === 'Property' &&
      propertyName(property.key, property.computed)?.toLowerCase() === 'createhtml'
  );
  if (!createHtml) return false;
  const implementation = createHtml.value;
  if (expressionName(implementation, source) === 'DOMPurify.sanitize') return true;
  if (implementation?.type !== 'FunctionExpression' && implementation?.type !== 'ArrowFunctionExpression') {
    return false;
  }

  const isDirectDomPurifyReturn = (expression) =>
    expression?.type === 'CallExpression' &&
    /^(?:window\.)?DOMPurify\.sanitize$/i.test(callName(expression, source));
  if (implementation.body.type !== 'BlockStatement') {
    return isDirectDomPurifyReturn(implementation.body);
  }
  return implementation.body.body.some(
    (statement) => statement.type === 'ReturnStatement' && isDirectDomPurifyReturn(statement.argument)
  );
}

function isLikelyJqueryReceiver(node, source, context) {
  let receiver = node;
  if (receiver?.type === 'ChainExpression') receiver = receiver.expression;
  if (receiver?.type === 'Identifier') {
    return receiver.name.startsWith('$') || context.jqueryObjects.has(receiver.name);
  }
  if (receiver?.type !== 'CallExpression') return false;
  const name = callName(receiver, source).replace(/\?\./g, '.');
  if (name === '$' || name === 'jQuery') return true;
  if (receiver.callee?.type !== 'MemberExpression') return false;
  return isLikelyJqueryReceiver(receiver.callee.object, source, context);
}

function domCallSource(node, source) {
  if (node?.type !== 'CallExpression') return null;
  const name = callName(node, source).replace(/\?\./g, '.');
  if (/^(?:(?:window|self)\.)?prompt$/i.test(name)) return name;
  if (/^(?:(?:window|self)\.)?(?:localStorage|sessionStorage)\.getItem$/i.test(name)) {
    return name;
  }
  return null;
}

function staticDomString(node) {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node?.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0]?.value?.cooked ?? node.quasis[0]?.value?.raw ?? '';
  }
  return null;
}

function collectDomFunctions(ast, source) {
  const functions = new Map();
  const allFunctions = new Set();
  walk(ast, (node, parent) => {
    if (
      node.type === 'FunctionDeclaration' ||
      node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression'
    ) {
      allFunctions.add(node);
    }
    if (node.type === 'FunctionDeclaration' && node.id) {
      functions.set(node.id.name, node);
      return;
    }
    if (
      (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') &&
      parent?.type === 'VariableDeclarator' &&
      parent.id.type === 'Identifier'
    ) {
      functions.set(parent.id.name, node);
      return;
    }
    if (
      (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') &&
      parent?.type === 'AssignmentExpression'
    ) {
      functions.set(expressionName(parent.left, source), node);
      return;
    }
    if (
      (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') &&
      (parent?.type === 'Property' || parent?.type === 'MethodDefinition')
    ) {
      const name = propertyName(parent.key, parent.computed);
      if (name) functions.set(name, node);
    }
  });
  return { functions, allFunctions };
}

function domStatementRange(node, context) {
  const statement = context.currentStatement;
  if (
    statement &&
    typeof statement.start === 'number' &&
    typeof statement.end === 'number' &&
    statement.start <= node.start &&
    statement.end >= node.end
  ) {
    return statement;
  }
  return node;
}

function addDomXssFinding(context, node, sink, flow) {
  if (!flow.sources.length && (!flow.dynamic || flow.sanitized)) return;
  const range = domStatementRange(node, context);
  const tainted = flow.sources.length > 0;
  const orderedSources = [...flow.sources].sort(
    (a, b) => domConfidenceRank(b.confidence) - domConfidenceRank(a.confidence)
  );
  const best = orderedSources[0];
  const confidence = tainted ? best.confidence : 'low';
  const path = tainted ? [...best.path, sink] : [sink];
  const finding = {
    sink,
    source: tainted ? orderedSources.map((item) => item.name).join(', ') : 'Unresolved dynamic value',
    line: lineOf(node),
    severity: tainted ? 'high' : 'medium',
    confidence,
    evidence: sourceFor(range, context.source, 500),
    path,
    start: range.start,
    end: range.end
  };
  const key = `${node.start}|${sink}`;
  const current = context.findings.get(key);
  if (!current || domConfidenceRank(finding.confidence) > domConfidenceRank(current.confidence)) {
    context.findings.set(key, finding);
  }
}

function setDomBinding(environment, name, flow) {
  if (!name) return;
  environment.set(name, extendDomFlow(flow, name));
}

function setDomPatternBindings(environment, pattern, flow) {
  if (!pattern) return;
  if (pattern.type === 'Identifier') {
    setDomBinding(environment, pattern.name, flow);
    return;
  }
  if (pattern.type === 'AssignmentPattern') {
    setDomPatternBindings(environment, pattern.left, flow);
    return;
  }
  if (pattern.type === 'RestElement') {
    setDomPatternBindings(environment, pattern.argument, flow);
    return;
  }
  if (pattern.type === 'ArrayPattern') {
    for (const element of pattern.elements) setDomPatternBindings(environment, element, flow);
    return;
  }
  if (pattern.type === 'ObjectPattern') {
    for (const property of pattern.properties) {
      setDomPatternBindings(
        environment,
        property.type === 'RestElement' ? property.argument : property.value,
        flow
      );
    }
  }
}

function trackDomSpecialBinding(name, value, context) {
  if (!name || !value) return;
  const called =
    value.type === 'CallExpression' || value.type === 'NewExpression'
      ? callName(value, context.source).replace(/\?\./g, '.')
      : '';
  if (/^(?:window\.)?trustedTypes\.createPolicy$/i.test(called)) {
    if (trustedPolicyUsesDomPurify(value, context.source)) context.trustedPolicies.add(name);
    else context.trustedPolicies.delete(name);
  }
  if (value.type === 'NewExpression' && /^(?:window\.)?Sanitizer$/i.test(called)) {
    context.sanitizerInstances.add(name);
  }
  if (
    value.type === 'CallExpression' &&
    isLikelyJqueryReceiver(value, context.source, context)
  ) {
    context.jqueryObjects.add(name);
  }
}

function evaluateDomExpression(node, environment, context, depth = 0) {
  if (!node || depth > 20) return emptyDomFlow(true);
  if (node.type === 'ChainExpression') {
    return evaluateDomExpression(node.expression, environment, context, depth + 1);
  }

  if (node.type === 'Literal') return emptyDomFlow(false);
  if (node.type === 'Identifier') {
    if (/^(?:location)$/i.test(node.name)) return domSourceFlow(node.name);
    return environment.has(node.name) ? environment.get(node.name) : emptyDomFlow(true);
  }
  if (node.type === 'ThisExpression' || node.type === 'MetaProperty') return emptyDomFlow(true);
  if (node.type === 'TemplateLiteral') {
    return mergeDomFlows(
      emptyDomFlow(node.expressions.length > 0),
      node.expressions.map((expression) =>
        evaluateDomExpression(expression, environment, context, depth + 1)
      )
    );
  }
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
    return mergeDomFlows(
      evaluateDomExpression(node.left, environment, context, depth + 1),
      evaluateDomExpression(node.right, environment, context, depth + 1)
    );
  }
  if (node.type === 'ConditionalExpression') {
    return mergeDomFlows(
      evaluateDomExpression(node.consequent, environment, context, depth + 1),
      evaluateDomExpression(node.alternate, environment, context, depth + 1)
    );
  }
  if (node.type === 'UnaryExpression') {
    if (node.operator === 'typeof' || node.operator === 'delete' || node.operator === '!') {
      return emptyDomFlow(false);
    }
    return evaluateDomExpression(node.argument, environment, context, depth + 1);
  }
  if (node.type === 'AwaitExpression' || node.type === 'YieldExpression') {
    return evaluateDomExpression(node.argument, environment, context, depth + 1);
  }
  if (node.type === 'SequenceExpression') {
    let result = emptyDomFlow(false);
    for (const expression of node.expressions) {
      result = evaluateDomExpression(expression, environment, context, depth + 1);
    }
    return result;
  }
  if (node.type === 'ArrayExpression') {
    return mergeDomFlows(
      emptyDomFlow(false),
      node.elements.map((element) => evaluateDomExpression(element, environment, context, depth + 1))
    );
  }
  if (node.type === 'ObjectExpression') {
    for (const property of node.properties) {
      if (
        property.type !== 'Property' ||
        propertyName(property.key, property.computed)?.toLowerCase() !==
          'dangerouslysetinnerhtml'
      ) {
        continue;
      }
      let htmlValue = property.value;
      if (htmlValue?.type === 'ObjectExpression') {
        const htmlProperty = htmlValue.properties.find(
          (candidate) =>
            candidate.type === 'Property' &&
            propertyName(candidate.key, candidate.computed)?.toLowerCase() === '__html'
        );
        if (!htmlProperty) continue;
        htmlValue = htmlProperty?.value;
      }
      const flow = evaluateDomExpression(htmlValue, environment, context, depth + 1);
      addDomXssFinding(context, property, 'React.dangerouslySetInnerHTML', flow);
    }
    return mergeDomFlows(
      emptyDomFlow(false),
      node.properties.map((property) =>
        evaluateDomExpression(
          property.type === 'SpreadElement' ? property.argument : property.value,
          environment,
          context,
          depth + 1
        )
      )
    );
  }
  if (node.type === 'MemberExpression') {
    const sourceName = domMemberSource(node, context.source);
    if (sourceName) return domSourceFlow(sourceName);
    const exactName = expressionName(node, context.source);
    if (environment.has(exactName)) return environment.get(exactName);
    return mergeDomFlows(
      evaluateDomExpression(node.object, environment, context, depth + 1),
      node.computed
        ? evaluateDomExpression(node.property, environment, context, depth + 1)
        : emptyDomFlow(false)
    );
  }
  if (node.type === 'AssignmentExpression') {
    const right = evaluateDomExpression(node.right, environment, context, depth + 1);
    if (node.left.type === 'Identifier') {
      setDomBinding(environment, node.left.name, right);
      trackDomSpecialBinding(node.left.name, node.right, context);
    } else if (node.left.type === 'MemberExpression') {
      const property = memberPropertyName(node.left)?.toLowerCase();
      if (DOM_XSS_HTML_PROPERTIES.has(property)) {
        addDomXssFinding(context, node, DOM_XSS_HTML_PROPERTIES.get(property), right);
      } else {
        setDomBinding(environment, expressionName(node.left, context.source), right);
      }
    }
    return right;
  }
  if (node.type === 'CallExpression' || node.type === 'NewExpression') {
    const name = callName(node, context.source).replace(/\?\./g, '.');
    const sourceName = domCallSource(node, context.source);
    if (sourceName) return domSourceFlow(sourceName);
    if (isDomSanitizerCall(node, context.source, context)) {
      return emptyDomFlow(false, true);
    }

    const argumentFlows = node.arguments.map((argument) =>
      evaluateDomExpression(
        argument.type === 'SpreadElement' ? argument.argument : argument,
        environment,
        context,
        depth + 1
      )
    );
    const method =
      node.callee?.type === 'MemberExpression'
        ? memberPropertyName(node.callee)?.toLowerCase()
        : name.toLowerCase();
    const receiverFlow =
      node.callee?.type === 'MemberExpression'
        ? evaluateDomExpression(node.callee.object, environment, context, depth + 1)
        : emptyDomFlow(false);

    if (/^(?:window\.)?eval$/i.test(name)) {
      addDomXssFinding(context, node, 'eval', argumentFlows[0] || emptyDomFlow(false));
    } else if (/^(?:window\.)?(?:setTimeout|setInterval)$/i.test(name)) {
      const first = node.arguments[0];
      if (first?.type !== 'FunctionExpression' && first?.type !== 'ArrowFunctionExpression') {
        addDomXssFinding(
          context,
          node,
          name.replace(/^window\./i, ''),
          argumentFlows[0] || emptyDomFlow(false)
        );
      }
    } else if (/^(?:window\.)?Function$/i.test(name)) {
      addDomXssFinding(
        context,
        node,
        'Function constructor',
        argumentFlows.at(-1) || emptyDomFlow(false)
      );
    } else if (/^(?:window\.)?document\.(?:write|writeln)$/i.test(name)) {
      addDomXssFinding(context, node, name.replace(/^window\./i, ''), mergeDomFlows(argumentFlows));
    } else if (method === 'insertadjacenthtml') {
      addDomXssFinding(
        context,
        node,
        'insertAdjacentHTML',
        argumentFlows[1] || emptyDomFlow(false)
      );
    } else if (method === 'sethtmlunsafe') {
      addDomXssFinding(context, node, 'setHTMLUnsafe', argumentFlows[0] || emptyDomFlow(false));
    } else if (method === 'createcontextualfragment') {
      addDomXssFinding(
        context,
        node,
        'createContextualFragment',
        argumentFlows[0] || emptyDomFlow(false)
      );
    } else if (
      DOM_XSS_JQUERY_HTML_METHODS.has(method) &&
      isLikelyJqueryReceiver(node.callee?.object, context.source, context)
    ) {
      addDomXssFinding(
        context,
        node,
        `jQuery.${method === 'replacewith' ? 'replaceWith' : method}`,
        mergeDomFlows(argumentFlows)
      );
    } else if (method === 'setattribute') {
      const attribute = node.arguments[0];
      const staticAttribute = staticDomString(attribute);
      if (staticAttribute !== null) {
        const attributeName = staticAttribute.toLowerCase();
        if (attributeName === 'srcdoc' || /^on[a-z]/.test(attributeName)) {
          addDomXssFinding(
            context,
            node,
            `setAttribute(${attributeName})`,
            argumentFlows[1] || emptyDomFlow(false)
          );
        }
      }
    } else if (method === 'execcommand') {
      const command = node.arguments[0];
      if (command?.type === 'Literal' && /^insertHTML$/i.test(String(command.value))) {
        addDomXssFinding(context, node, 'execCommand(insertHTML)', argumentFlows[2] || emptyDomFlow(false));
      }
    }

    const targetFunction = context.functions.get(name) || context.functions.get(name.split('.').at(-1));
    if (targetFunction && !context.activeFunctions.has(targetFunction)) {
      const result = evaluateDomFunction(targetFunction, argumentFlows, environment, context, depth + 1);
      if (result.sources.length || result.dynamic) return result;
    }

    const combined = mergeDomFlows(
      argumentFlows,
      DOM_XSS_PASSTHROUGH_METHODS.has(method) ? receiverFlow : emptyDomFlow(false)
    );
    if (!combined.sources.length) return { ...combined, dynamic: true };
    const confidence =
      DOM_XSS_PASSTHROUGH_CALL_RE.test(name) || DOM_XSS_PASSTHROUGH_METHODS.has(method)
        ? null
        : 'medium';
    return extendDomFlow(combined, `${name || 'call'}()`, confidence);
  }
  if (node.type === 'TaggedTemplateExpression') {
    return evaluateDomExpression(node.quasi, environment, context, depth + 1);
  }
  if (node.type === 'UpdateExpression') return emptyDomFlow(false);
  if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
    return emptyDomFlow(false);
  }

  return emptyDomFlow(true);
}

function evaluateDomStatement(node, environment, context, returns, depth = 0) {
  if (!node || depth > 30) return;
  const previousStatement = context.currentStatement;
  if (/Statement$/.test(node.type) || node.type === 'VariableDeclaration') {
    context.currentStatement = node;
  }

  if (node.type === 'Program' || node.type === 'BlockStatement') {
    for (const statement of node.body) {
      evaluateDomStatement(statement, environment, context, returns, depth + 1);
    }
  } else if (node.type === 'VariableDeclaration') {
    for (const declaration of node.declarations) {
      if (!declaration.init) {
        setDomPatternBindings(environment, declaration.id, emptyDomFlow(true));
        continue;
      }
      const flow = evaluateDomExpression(declaration.init, environment, context, depth + 1);
      setDomPatternBindings(environment, declaration.id, flow);
      if (declaration.id.type === 'Identifier') {
        trackDomSpecialBinding(declaration.id.name, declaration.init, context);
      }
    }
  } else if (node.type === 'ExpressionStatement') {
    evaluateDomExpression(node.expression, environment, context, depth + 1);
  } else if (node.type === 'ReturnStatement') {
    returns.push(evaluateDomExpression(node.argument, environment, context, depth + 1));
  } else if (node.type === 'IfStatement') {
    evaluateDomExpression(node.test, environment, context, depth + 1);
    evaluateDomStatement(node.consequent, new Map(environment), context, returns, depth + 1);
    evaluateDomStatement(node.alternate, new Map(environment), context, returns, depth + 1);
  } else if (/^(?:For|While|DoWhile)Statement$/.test(node.type)) {
    if (node.init?.type?.endsWith('Declaration')) {
      evaluateDomStatement(node.init, environment, context, returns, depth + 1);
    } else {
      evaluateDomExpression(node.init, environment, context, depth + 1);
    }
    evaluateDomExpression(node.test, environment, context, depth + 1);
    evaluateDomExpression(node.update, environment, context, depth + 1);
    evaluateDomStatement(node.body, new Map(environment), context, returns, depth + 1);
  } else if (node.type === 'ForInStatement' || node.type === 'ForOfStatement') {
    evaluateDomExpression(node.right, environment, context, depth + 1);
    evaluateDomStatement(node.body, new Map(environment), context, returns, depth + 1);
  } else if (node.type === 'TryStatement') {
    evaluateDomStatement(node.block, new Map(environment), context, returns, depth + 1);
    evaluateDomStatement(node.handler?.body, new Map(environment), context, returns, depth + 1);
    evaluateDomStatement(node.finalizer, new Map(environment), context, returns, depth + 1);
  } else if (node.type === 'SwitchStatement') {
    evaluateDomExpression(node.discriminant, environment, context, depth + 1);
    for (const switchCase of node.cases) {
      evaluateDomExpression(switchCase.test, environment, context, depth + 1);
      for (const statement of switchCase.consequent) {
        evaluateDomStatement(statement, new Map(environment), context, returns, depth + 1);
      }
    }
  } else if (node.type === 'ThrowStatement') {
    evaluateDomExpression(node.argument, environment, context, depth + 1);
  } else if (node.type === 'LabeledStatement' || node.type === 'WithStatement') {
    evaluateDomStatement(node.body, environment, context, returns, depth + 1);
  } else if (node.type === 'ExportDefaultDeclaration' || node.type === 'ExportNamedDeclaration') {
    if (node.declaration && !/FunctionDeclaration|ClassDeclaration/.test(node.declaration.type)) {
      evaluateDomStatement(node.declaration, environment, context, returns, depth + 1);
    }
  }

  context.currentStatement = previousStatement;
}

function evaluateDomFunction(node, argumentFlows, parentEnvironment, context, depth = 0) {
  if (!node || depth > 20) return emptyDomFlow(true);
  const environment = new Map(parentEnvironment);
  node.params.forEach((parameter, index) => {
    setDomPatternBindings(environment, parameter, argumentFlows[index] || emptyDomFlow(true));
  });
  const returns = [];
  context.activeFunctions.add(node);
  const previousStatement = context.currentStatement;
  if (node.body.type === 'BlockStatement') {
    evaluateDomStatement(node.body, environment, context, returns, depth + 1);
  } else {
    returns.push(evaluateDomExpression(node.body, environment, context, depth + 1));
  }
  context.currentStatement = previousStatement;
  context.activeFunctions.delete(node);
  return returns.length ? mergeDomFlows(returns) : emptyDomFlow(false);
}

function extractDomXssFromAst(source, ast) {
  const collectedFunctions = collectDomFunctions(ast, source);
  const context = {
    source,
    findings: new Map(),
    functions: collectedFunctions.functions,
    activeFunctions: new Set(),
    trustedPolicies: new Set(),
    sanitizerInstances: new Set(),
    jqueryObjects: new Set(),
    currentStatement: null
  };
  const globalEnvironment = new Map();
  evaluateDomStatement(ast, globalEnvironment, context, [], 0);

  // Scan every function once with unknown parameters. A later tainted call-site replaces
  // the low-confidence sink-only record because findings are keyed by the sink node.
  for (const functionNode of collectedFunctions.allFunctions) {
    evaluateDomFunction(
      functionNode,
      functionNode.params.map(() => emptyDomFlow(true)),
      globalEnvironment,
      context
    );
  }

  return [...context.findings.values()].sort(
    (a, b) => a.line - b.line || a.start - b.start || a.sink.localeCompare(b.sink)
  );
}

function fallbackDomSource(expression, aliases) {
  const value = String(expression || '');
  const sanitizerStart = value.match(
    /^\s*(?:window\s*\.\s*)?DOMPurify\s*\.\s*sanitize\s*\(/i
  );
  if (sanitizerStart) {
    const open = value.indexOf('(', sanitizerStart.index);
    const close = findClosingParenthesis(value, open);
    if (close >= 0 && !value.slice(close + 1).trim()) {
      return { flow: emptyDomFlow(false, true), constant: false };
    }
  }
  const direct = value.match(
    /(?:(?:window|self)\s*\.\s*)?location\s*\.\s*(?:hash|search|href|pathname|origin)|document\s*\.\s*(?:URL|documentURI|referrer|cookie)|(?:event|evt|messageEvent|message|e)\s*\.\s*data|(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(/i
  );
  if (direct) {
    const name = direct[0].replace(/\s+/g, '').replace(/\($/, '');
    return { flow: domSourceFlow(name), constant: false };
  }
  for (const [name, flow] of aliases) {
    if (new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(value)) {
      return { flow: extendDomFlow(flow, name), constant: false };
    }
  }
  const trimmed = value.trim();
  const constant =
    /^(?:["'`](?:\\.|[^"'`])*["'`]|null|undefined|true|false|\d+(?:\.\d+)?)$/.test(trimmed) ||
    (!/[A-Za-z_$]/.test(trimmed) && trimmed.length > 0);
  return { flow: emptyDomFlow(!constant), constant };
}

function fallbackDomRange(source, index, minimumEnd) {
  let start = source.lastIndexOf('\n', index - 1) + 1;
  while (/\s/.test(source[start] || '') && source[start] !== '\n') start += 1;
  let end = findFallbackExpressionEnd(source, Math.max(minimumEnd, index + 1));
  if (end <= minimumEnd) end = minimumEnd;
  return { start, end };
}

function extractDomXssFallback(source) {
  const aliases = new Map();
  const findings = new Map();
  const context = { source, findings, currentStatement: null };
  const bindingPattern = /\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\r\n]+)/g;

  // A few fixed-point passes recover simple aliases even when declarations are out of order.
  for (let pass = 0; pass < 4; pass += 1) {
    bindingPattern.lastIndex = 0;
    let binding;
    while ((binding = bindingPattern.exec(source))) {
      const result = fallbackDomSource(binding[2], aliases);
      if (result.flow.sources.length && !result.flow.sanitized) {
        aliases.set(binding[1], extendDomFlow(result.flow, binding[1]));
      } else if (result.flow.sanitized) {
        aliases.delete(binding[1]);
      }
    }
  }

  const assignmentPattern = /\.\s*(innerHTML|outerHTML|srcdoc)\s*=\s*([^;\r\n]+)/gi;
  let match;
  while ((match = assignmentPattern.exec(source))) {
    const range = fallbackDomRange(source, match.index, assignmentPattern.lastIndex);
    context.currentStatement = { ...range, loc: { start: { line: lineAt(source, range.start) } } };
    const flow = fallbackDomSource(match[2], aliases).flow;
    addDomXssFinding(
      context,
      { start: match.index, end: assignmentPattern.lastIndex, loc: { start: { line: lineAt(source, match.index) } } },
      DOM_XSS_HTML_PROPERTIES.get(match[1].toLowerCase()),
      flow
    );
  }

  const reactHtmlPattern = /\bdangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([^}\r\n]+)/gi;
  while ((match = reactHtmlPattern.exec(source))) {
    const range = fallbackDomRange(source, match.index, reactHtmlPattern.lastIndex);
    context.currentStatement = { ...range, loc: { start: { line: lineAt(source, range.start) } } };
    addDomXssFinding(
      context,
      {
        start: match.index,
        end: reactHtmlPattern.lastIndex,
        loc: { start: { line: lineAt(source, match.index) } }
      },
      'React.dangerouslySetInnerHTML',
      fallbackDomSource(match[1], aliases).flow
    );
  }

  const callPatterns = [
    { pattern: /\binsertAdjacentHTML\s*\(/gi, sink: 'insertAdjacentHTML', argument: 1 },
    { pattern: /\bdocument\s*\.\s*(write|writeln)\s*\(/gi, sink: null, argument: 0 },
    { pattern: /(?:^|[^\w$.])eval\s*\(/g, sink: 'eval', argument: 0 },
    {
      pattern: /\b(?:new\s+)?(?:window\s*\.\s*)?Function\s*\(/g,
      sink: 'Function constructor',
      argument: 0,
      mergeArguments: true
    },
    {
      pattern:
        /(?:\$|jQuery)\s*\([^)]*\)\s*\.\s*(html|append|prepend|before|after|replaceWith)\s*\(/gi,
      sink: (callMatch) => `jQuery.${callMatch[1]}`,
      argument: 0,
      mergeArguments: true
    }
  ];
  for (const definition of callPatterns) {
    definition.pattern.lastIndex = 0;
    while ((match = definition.pattern.exec(source))) {
      const open = source.indexOf('(', match.index);
      const close = findClosingParenthesis(source, open);
      if (close < 0) continue;
      const args = splitTopLevelArguments(source.slice(open + 1, close));
      const flow = definition.mergeArguments
        ? mergeDomFlows(args.map((argument) => fallbackDomSource(argument, aliases).flow))
        : fallbackDomSource(args[definition.argument], aliases).flow;
      const sink =
        typeof definition.sink === 'function'
          ? definition.sink(match)
          : definition.sink || `document.${String(match[1] || 'write').replace(/\s+/g, '')}`;
      const range = fallbackDomRange(source, match.index, close + 1);
      context.currentStatement = { ...range, loc: { start: { line: lineAt(source, range.start) } } };
      addDomXssFinding(
        context,
        { start: match.index, end: close + 1, loc: { start: { line: lineAt(source, match.index) } } },
        sink,
        flow
      );
      definition.pattern.lastIndex = close + 1;
    }
  }

  const setAttributePattern = /\.\s*setAttribute\s*\(/gi;
  while ((match = setAttributePattern.exec(source))) {
    const open = source.indexOf('(', match.index);
    const close = findClosingParenthesis(source, open);
    if (close < 0) continue;
    const args = splitTopLevelArguments(source.slice(open + 1, close));
    const attributeMatch = String(args[0] || '').trim().match(/^(?:["'])([^"']+)(?:["'])$/);
    const attribute = attributeMatch?.[1]?.toLowerCase();
    if (attribute !== 'srcdoc' && !/^on[a-z]/.test(attribute || '')) {
      setAttributePattern.lastIndex = close + 1;
      continue;
    }
    const flow = fallbackDomSource(args[1], aliases).flow;
    const range = fallbackDomRange(source, match.index, close + 1);
    context.currentStatement = { ...range, loc: { start: { line: lineAt(source, range.start) } } };
    addDomXssFinding(
      context,
      { start: match.index, end: close + 1, loc: { start: { line: lineAt(source, match.index) } } },
      `setAttribute(${attribute})`,
      flow
    );
    setAttributePattern.lastIndex = close + 1;
  }

  return [...findings.values()].sort(
    (a, b) => a.line - b.line || a.start - b.start || a.sink.localeCompare(b.sink)
  );
}

export function extractDomXssFindings(source, suppliedAst = undefined) {
  if (typeof source !== 'string') throw new TypeError('JavaScript source must be a string');
  const ast = suppliedAst === undefined ? parseSource(source).ast : suppliedAst;
  return ast ? extractDomXssFromAst(source, ast) : extractDomXssFallback(source);
}

export function analyzeJavaScript(source) {
  if (typeof source !== 'string') throw new TypeError('JavaScript source must be a string');
  const parsed = parseSource(source);
  const endpoints = extractEndpoints(source, parsed.ast);
  const sensitiveFindings = extractSensitiveFindings(source, parsed.ast);
  const ajaxCalls = extractAjaxCalls(source, parsed.ast);
  const endpointValues = new Set(endpoints.map((endpoint) => endpoint.value));

  for (const call of ajaxCalls) {
    if (!isEndpoint(call.url) || endpointValues.has(call.url)) continue;
    endpointValues.add(call.url);
    endpoints.push({ value: call.url, type: endpointType(call.url), line: call.line });
  }

  endpoints.sort((a, b) => a.line - b.line || a.value.localeCompare(b.value));
  sensitiveFindings.sort((a, b) => a.line - b.line || a.keyword.localeCompare(b.keyword));
  ajaxCalls.sort((a, b) => a.line - b.line);
  const interestingFunctions = extractInterestingFunctions(source, parsed.ast).sort(
    (a, b) => a.line - b.line || a.name.localeCompare(b.name)
  );
  const domXssFindings = extractDomXssFindings(source, parsed.ast);

  return {
    endpoints,
    sensitiveFindings,
    ajaxCalls,
    interestingFunctions,
    domXssFindings,
    parseError: parsed.error
  };
}

export default analyzeJavaScript;
