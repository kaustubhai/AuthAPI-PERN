const express = require('express')
const Auth = require('./router/auth')
const User = require('./router/user')
const app = express()

const dotenv = require('dotenv')
dotenv.config()

const cookies = require('cookie-parser')

app.use(express.json());
app.use(cookies());
app.use('/api/auth', Auth);
app.use('/api/user', User);

const PORT = process.env.PORT || 5000
app.listen(PORT, console.log(`Server Running on ${PORT}`))