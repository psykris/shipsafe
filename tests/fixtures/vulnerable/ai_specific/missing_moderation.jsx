// Vulnerable: LLM output rendered as raw HTML without sanitization
import React, { useState } from 'react';

function ChatApp() {
  const [llmOutput, setLlmOutput] = useState('');
  const [aiResponse, setAiResponse] = useState('');

  // AI007: dangerouslySetInnerHTML with llmOutput
  return (
    <div>
      <div dangerouslySetInnerHTML={{__html: llmOutput}} />
    </div>
  );
}

function DirectRender() {
  let aiResponse = "some response from LLM";

  // AI007: innerHTML with llmOutput variable
  document.getElementById('output').innerHTML = llmOutput;

  // AI007: innerHTML with aiResponse variable
  document.getElementById('chat').innerHTML = aiResponse;

  return null;
}

export default ChatApp;
