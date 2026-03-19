// Safe: LLM output rendered using safe DOM methods only
import React, { useState } from 'react';

function SafeChatApp() {
  const [llmOutput, setLlmOutput] = useState('');

  // Safe: textContent escapes all HTML — no injection risk
  return (
    <div>
      <p>{llmOutput}</p>
    </div>
  );
}

function SafeTextRender() {
  const aiOutput = "some response";

  // Safe: textContent is never interpreted as HTML
  document.getElementById('output').textContent = aiOutput;

  return null;
}

export default SafeChatApp;
