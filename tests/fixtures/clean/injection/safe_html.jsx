// SAFE: proper HTML rendering patterns
import React from 'react';
import DOMPurify from 'dompurify';

// SAFE: JSX auto-escapes user content
function Comment({ content }) {
  return <div>{content}</div>;
}

// SAFE: textContent does not parse HTML
function renderMessage(message) {
  document.getElementById('output').textContent = message;
}

// SAFE: use createTextNode for user content instead of innerHTML
function renderRichContent(text) {
  const container = document.getElementById('content');
  container.textContent = '';
  container.appendChild(document.createTextNode(text));
}
