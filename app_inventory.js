const express = require('express');
const controller = require('./control_function');
const middleWare = require('./middleWare');
const authenticate = require('./authorization_middleWare');
// const bodyParser = require('body-parser');

// const PORT = 5000;
// const app = express();
const app_router = express.Router();
app_router.use(authenticate.authenticationMiddleWare);

app_router.get(
	'/',
	authenticate.authenticationMiddleWare,
	controller.getFunction
);
app_router.get(
	'/:id',
	authenticate.authenticationMiddleWare,
	controller.getOneFunction
);
app_router.post(
	'/',
	authenticate.authorizationMiddleWare,
	middleWare.middleWarecheck,
	controller.postFunction
);
app_router.put(
	'/:id',
	authenticate.authorizationMiddleWare,
	middleWare.middleWarecheck,
	controller.putFunction
);
app_router.delete(
	'/',
	authenticate.authorizationMiddleWare,
	middleWare.middleWarecheck,
	controller.deleteFunction
);
// app.listen(PORT, () => {
// 	console.log(`Server started at localhost:${PORT}`);
// });
module.exports = app_router;
