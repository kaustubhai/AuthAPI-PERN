const jwt = require('jsonwebtoken')
const pool = require('../utils/connectDB')

module.exports = async function (req, res, next) {
    const token = req.cookies.token

    if (!token)
        return res.status(401).json({ msg: "Unathorised Access" })
    try {
        const decoded = jwt.verify(token, process.env.SECURITY_KEY)
        const result = await pool.query("SELECT * FROM userBase WHERE _id = $1", [decoded.user])
        const user = result.rows[0];
        if (!user)
            return res.status(401).json({msg: "No user founded"})
        req.user = decoded.user
        next()
    }
    catch (err) {
        console.log(err)
        res.status(500).json({ msg: "Token is not Valid" })
    }
}