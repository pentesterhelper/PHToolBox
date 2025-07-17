const express = require('express');
const fs = require('fs');
const cors = require('cors');
const app = express();
const PORT = 9999;

app.use(cors());

// GET checklist
app.get('/api/checklist', (req, res) => {
  const data = JSON.parse(fs.readFileSync('./static_web_application_checklist.json', 'utf8'));
  res.json(data.static_web_application_checkList);
});

app.listen(PORT, () => {
  console.log(`✅ Checklist API running on http://localhost:${PORT}`);
});
