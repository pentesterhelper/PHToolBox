const axios = require('axios');

const apiKey = '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'; // 🔐 Replace with your real API key

async function getChatResponse(prompt) {
  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: 'You are a helpful assistant.' },
        { role: 'user', content: prompt }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    console.log('Response:', response.data.choices[0].message.content);
  } catch (error) {
    console.error('Error:', error.response ? error.response.data : error.message);
  }
}

getChatResponse('Hello! How are you?');
