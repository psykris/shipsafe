// Intentionally vulnerable: XSS via unsafe HTML insertion
import React from 'react';

// VULNERABLE: dangerouslySetInnerHTML with user content
function Comment({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// VULNERABLE: direct innerHTML assignment
function renderMessage(message) {
  document.getElementById('output').innerHTML = message;
}

// VULNERABLE: document.write with user data
function displayTitle(title) {
  document.write(title);
}

// VULNERABLE: Angular-style innerHTML binding
const template = `<div [innerHTML]="userContent"></div>`;
