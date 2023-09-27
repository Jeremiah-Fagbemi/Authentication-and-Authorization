const middleWareFunction = (req, res, next) => {
	if (!req.body) {
		res.status(404).json({ error: 'No body Found' });
	}
	next();
};
module.exports = {
	middleWarecheck: middleWareFunction,
};
