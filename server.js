const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const VT_API_KEY = "34660ddc4edc889fea5a86fb203770496f8c50dd93ebcbad598602755540228d";

if (!VT_API_KEY) {
  throw new Error('No VirusTotal API key configured on server');
}

app.post('/api/check-url', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {

    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: {
        'x-apikey': VT_API_KEY,
      }
    });

    if (response.status === 404) {
      return res.json({
        safe: true, 
        stats: { harmless: 0, malicious: 0, suspicious: 0, undetected: 0, timeout: 0 },
        message: '✅ This URL has not been analyzed before by VirusTotal.'
      });
    }

    if (!response.ok) {
      const text = await response.text();
      console.log('VirusTotal API error:', text);
      return res.status(response.status).json({ error: 'Error fetching data from VirusTotal API.' });
    }

    const result = await response.json();

    const stats = result.data.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    const safe = malicious === 0 && suspicious === 0;

    res.json({
      safe,
      stats,
      message: safe ? '✅ URL appears to be safe.' : '⚠️ This URL is potentially dangerous!'
    });

  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'An internal server error occurred.' });
  }
});

app.get('/', (req, res) => {
  res.send('Server running. Use POST /api/check-url to check URLs.');
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));