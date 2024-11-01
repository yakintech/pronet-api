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
const multer = require('multer')
const session = require('express-session')

// Morgan middleware'ini kullanın
app.use(morgan('dev'))

app.use(express.json())
app.use(cookieParser())
app.use(cors())
app.use(session({
    secret: "my_secret_key2",
    cookie: { secure: true }
}))


app.use(rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 50
}))

// Multer ayarları
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
})

const upload = multer({ storage: storage })


const generateCsrftoken = () => {
    return uuidv4()
}


app.get('/csrf-token', (req, res) => {
    const csrfToken = generateCsrftoken()
    req.session.cookie.csrf = csrfToken

    res.cookie('csrfToken', csrfToken, {
        httpOnly: false,
        secure: false
    })

    res.json({ csrfToken })
})


//CSRF middleware
const csrfMiddleware = (req, res, next) => {

    const csrfTokenFromClient = req.headers['csrf-token']
    const csrfTokenFromSession = req.session.cookie.csrf

    console.log("req.session", req.session)

    if (csrfTokenFromClient !== csrfTokenFromSession) {
        return res.sendStatus(403)
    }
    return next()
}


app.post('/api/login-with-csrf', (req, res) => {


    return res.json({ message: 'Login successful' })
})

app.get('/api/hello', (req, res) => {
    setTimeout(() => {
        res.json({ message: 'Hello from the server!' })
    }, 5000);
})

app.get("/check", authMiddleware, (req, res) => {
    let token = req.headers.authorization.split(" ")[1]
    let email = jwt.verify(token, 'my_secret_key').email
    let roles = users.find(x => x.email === email).roles
    let pageRoles = users.find(x => x.email === email).pageRoles
    res.json({ email, roles, pageRoles })
})

app.get("/api/employees", authMiddleware, checkPermission(1), (req, res) => {
    res.json(employees)
})


app.get("/api/employees-2", (req, res) => {
    res.json(employees)
})


let refreshTokens = []

app.post("/api/login", (req, res) => {
    const { email, password } = req.body

    if (users.find(x => x.email === email && x.password === password)) {
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
        let roles = users.find(x => x.email === email).roles
        let pageRoles = users.find(x => x.email === email).pageRoles

        res.json({
            token: token,
            refreshToken: refreshToken.token,
            user: {
                email: email,
                roles: roles,
                pageRoles: pageRoles
            }
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

// Dosya yükleme endpointi
const uploadLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 2 // limit each IP to 2 requests per windowMs
})

app.post('/upload', uploadLimiter, upload.single('file'), (req, res) => {
    res.json({ message: 'File uploaded successfully', file: req.file })
})

app.listen(3002, () => {
    console.log('Server is running on port 3002')
})