const express = require('express');
const inventoryApp = require('./app_inventory');
const bodyParser = require('body-parser');
const detailsApp = require('./authorization/details_router.js');
const PORT = 5000;

const app = express();
app.use(bodyParser.json());

app.use(express.json());

app.use('/v1/details', detailsApp);
app.use('/v1/inventory', inventoryApp);

app.listen(PORT, () => {
	console.log(`You started server localhost:${PORT}`);
});
