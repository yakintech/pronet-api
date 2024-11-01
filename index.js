const express = require('express')
const app = express()
const cors = require('cors')
const morgan = require('morgan')
const jwt = require('jsonwebtoken')
const employees = require('./data/employees')
const { v4: uuidv4 } = require("uuid");
const users = require('./data/users')
const cookieParser = require('cookie-parser')
const rateLimit = require('express-rate-limit')
const { authMiddleware, roleMiddleware, checkPermission } = require('./middleware/authMiddleware')
app.use(morgan('dev'))

app.use(express.json())
app.use(cors())
app.use(cookieParser())
app.use(rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5
}))


app.get('/api/hello', (req, res) => {
    setTimeout(() => {
        res.json({ message: 'Hello from the server!' })
    }, 5000);
})

app.get("/check", authMiddleware, (req, res) => {
    res.json({ message: "Hello" })
})


app.get("/api/employees", authMiddleware, checkPermission(1), (req, res) => {
    res.json(employees)
})


let refreshTokens = []

app.post("/api/login", (req, res) => {

    const { email, password } = req.body

    if (users.find(x => x.email === email && x.password === password)){
        const token = jwt.sign({ email }, 'my_secret_key', { expiresIn: '10m' })

        //GUID ile bir refresh token oluşturuyoruz
        let refreshToken = {
            token: uuidv4(),
            expiresIn: Date.now() + 1000 * 60 * 60 * 24 * 30, // 1 month
            revoked: false,
            email: email
        }

        refreshTokens.push(refreshToken)


        res.cookie('token', token, {
            httpOnly: false, // javascript ile erişimi engeller
            secure: false, // sadece https üzerinden çalışır
            // sameSite: 'strict' // sadece aynı domain üzerinden çalışır
        })

        res.json({
            token: token,
            refreshToken: refreshToken.token
        })
    }

})


app.post("/api/refreshToken", (req, res) => {

    console.log("refreshTokens", refreshTokens)

    const { refreshToken, email } = req.body

    const token = refreshTokens.find(x => x.token === refreshToken)

    if (!token) {
        return res.sendStatus(401)
    }

    if (token.revoked) {
        return res.sendStatus(401)
    }

    //date check
    if (Date.now() > token.expiresIn) {
        return res.sendStatus(401)
    }


    //refresh token süresi geçmemiş ve token geçerli ise yeni bir accessToken oluşturuyorum.
    const newAccessToken = jwt.sign({ email }, 'my_secret_key', { expiresIn: '10m' })

    res.json({
        token: newAccessToken
    })

})

app.listen(3002, () => {
    console.log('Server is running on port 3002')
})
