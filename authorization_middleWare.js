const fs = require('fs');
const path = require('path');

const detailDbPath = path.join(__dirname, './authorization/details.json');
const authenticationMiddleWare = (req, res, next) => {
	const authorize = req.headers;
	console.log(authorize);
	if (!authorize.api_key) {
		return res.status(400).json({ error: 'No api_key' });
	}
	fs.readFile(detailDbPath, 'utf-8', (err, data) => {
		if (err) {
			return res.status(404).json({ error: 'No detail' });
		}
		const detaToJson = JSON.parse(data);
		console.log(detaToJson);
		const details = detaToJson.find((detail) => {
			return detail.api_key === authorize.api_key;
		});
		if (details) {
			req.detail = details;
			next();
		} else {
			return res.status(401).json({ error: 'Not autheticate' });
		}
	});
};

const authorizationMiddleWare = (req, res, next) => {
	if (req.detail.level_type !== 'admin') {
		return res.status(401).json({ error: 'Not authorise' });
	}

	next();
};

module.exports = {
	authenticationMiddleWare,
	authorizationMiddleWare,
};
