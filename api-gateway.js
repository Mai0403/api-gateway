const express = require('express');
const app = express()

const httpProxy = require('http-proxy')
const proxy = httpProxy.createProxyServer();

const jwt = require('jsonwebtoken')
require('dotenv').config()
const JWT_SECRETE = process.env.JWT_SECRET;


const port = 5001;


app.get("/", (req, res) => {
    console.log("API Gateway is running..")
    return res.send("API Gateway is running..")
})

function authToken(req, res, next) {
    console.log(req.headers.authorization)
    const header = req?.headers.authorization;
    const token = header && header.split(' ')[1];

    if (token == null) return res.status(401).json("Please send token");

    jwt.verify(token, JWT_SECRETE, (err, user) => {
        if (err) return res.status(403).json("Invalid token", err);
        req.user = user;
        next()
    })
}

function authRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json("Unauthorized");
        }
        next();
    }
}

app.use('/auth', (req, res) => {
    proxy.web(req, res, { target: 'http://54.158.162.73:5002' });
})

app.use('/books/user', authToken, authRole("user", "admin"), (req, res) => {
    console.log("INSIDE API GATEWAY ORDER VIEW")
    proxy.web(req, res, { target: 'http://18.204.197.163:5003/user' });
})


app.use('/books/admin', authToken, authRole("admin"), (req, res) => {
    console.log("INSIDE API GATEWAY ORDER VIEW")
    proxy.web(req, res, { target: 'http://18.204.197.163:5003/admin' });
})

app.listen(port, () => {
    console.log("API Gateway Service is running on PORT NO : ", port)
})