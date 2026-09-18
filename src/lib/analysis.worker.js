import { js as beautifyJavaScript } from 'js-beautify';
import { analyzeJavaScript } from './analyzer.js';

const BEAUTIFY_OPTIONS = {
  indent_size: 2,
  indent_char: ' ',
  preserve_newlines: true,
  max_preserve_newlines: 2,
  end_with_newline: true,
  wrap_line_length: 120,
  space_in_empty_paren: false
};

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error || 'Analysis failed unexpectedly.');
}

self.addEventListener('message', ({ data }) => {
  const source = data?.source;

  try {
    if (typeof source !== 'string') {
      throw new TypeError('JavaScript source must be a string');
    }

    self.postMessage({
      type: 'status',
      phase: 'beautifying',
      message: 'Beautifying pasted source...'
    });

    let beautifiedSource = source;
    let warningMessage = '';

    try {
      beautifiedSource = beautifyJavaScript(source, BEAUTIFY_OPTIONS);
    } catch (error) {
      warningMessage = `Beautification failed, so the original source was analyzed: ${errorMessage(error)}`;
    }

    self.postMessage({
      type: 'status',
      phase: 'analyzing',
      message: 'Extracting routes, requests, DOM XSS leads, and functions...'
    });

    const results = analyzeJavaScript(beautifiedSource);
    if (results.parseError) {
      warningMessage = [
        warningMessage,
        `AST parsing was not possible; regex fallbacks still produced results. ${results.parseError}`
      ]
        .filter(Boolean)
        .join(' ');
    }

    self.postMessage({
      type: 'result',
      beautifiedSource,
      results,
      warningMessage
    });
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: errorMessage(error)
    });
  }
});
