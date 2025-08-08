import express from 'express';
import fetch from 'node-fetch';
const router = express.Router();
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
router.get('/api/cisa-kev', async (_req, res) => {
    try {
        const response = await fetch(CISA_KEV_URL);
        const data = await response.text();
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.status(response.status).type('application/json').send(data);
    }
    catch (err) {
        res.header('Access-Control-Allow-Origin', '*');
        res.status(500).json({ error: err.message });
    }
});
export default router;
