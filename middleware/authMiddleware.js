const jwt = require('jsonwebtoken');
const users = require('../data/users');


const authMiddleware = (req, res, next) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({ message: 'No token, authorization denied' });
        }

        const decoded = jwt.verify(token, "my_secret_key");
        req.user = decoded.user;
        console.log("decoded", decoded)
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};


const checkPermission = (permission) => {
    return (req, res, next) => {

        let token = req.header('Authorization').replace('Bearer ', '');
        let decoded = jwt.verify(token, 'my_secret_key');
        let role = users.find(x => x.email === decoded.email).roles;

        if (role.includes(permission)) {
            return next();
        } else {
            return res.status(403).json({ error: 'Access denied' });
        }
    };
};


module.exports = {
    authMiddleware,
    checkPermission
}



