'use client';
import { useMemo } from 'react';
import { CopyButton, cx } from './ui';

/** Lightweight JSON syntax highlighter (no dependency). */
function highlight(json: string): string {
  const esc = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return esc.replace(
    /("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
    (m) => {
      let cls = 'json-num';
      if (m.startsWith('"')) cls = m.endsWith(':') ? 'json-key' : 'json-str';
      else if (m === 'true' || m === 'false') cls = 'json-bool';
      else if (m === 'null') cls = 'json-null';
      return '<span class="' + cls + '">' + m + '</span>';
    },
  );
}

export function JsonView({ value, className, maxHeight = 'max-h-[60vh]', title }: { value: unknown; className?: string; maxHeight?: string; title?: string }) {
  const text = useMemo(() => JSON.stringify(value, null, 2), [value]);
  const html = useMemo(() => highlight(text), [text]);
  return (
    <div className={cx('rounded-lg border border-line bg-[#0b1016]', className)}>
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line">
        <span className="text-[11px] text-muted mono">{title ?? 'JSON'} · {(text.length / 1024).toFixed(1)} KB</span>
        <CopyButton text={text} />
      </div>
      <pre className={cx('mono text-[11.5px] leading-[1.5] overflow-auto p-3 text-fg-2', maxHeight)} dangerouslySetInnerHTML={{ __html: html }} />
    </div>
  );
}
