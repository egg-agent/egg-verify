// Vercel serverless entry: export the Express app; all routes via vercel.json rewrite.
const { app } = require("../server.js");
module.exports = app;
