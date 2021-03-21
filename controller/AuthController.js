const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs');
const pool = require('../utils/connectDB')

module.exports = {
    register: async (req, res) => {
        try {
            const { name, email, password, pin } = req.body;
            let { rows } = await pool.query("SELECT * FROM userBase WHERE email = $1", [email]);
            if (rows.length > 0)
                return res.status(400).json({msg: "User already exists"});
            if(!email.match(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/))
                return res.status(400).json({msg: "Invalid Mail Provided"});
            if (password.length < 8)
                return res.status(400).json({msg: "Password should be of 8 characters atleast"})
            if (pin.match(/[^0-9]/g))
                return res.status(400).json({msg: "Pin should consist only numbers"})
            if (pin.length !== 4)
                return res.status(400).json({msg: "Pin should be exactly 4 length"})
            const user = { name, email, password, pin };
            user.password = await bcrypt.hash(user.password, 8);
            user.pin = await bcrypt.hash(user.pin, 4);
            await pool.query("INSERT INTO userBase(name, email, password, pin) VALUES ($1, $2, $3, $4) RETURNING *", [user.name, user.email, user.password, user.pin]);
            // console.log(msg.rows[0]);
            res.json({ msg: "User Created. Login!" })
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },

    loginWithPin: async (req, res) => {
        try {
            const { email, pin } = req.body;
            const result = await pool.query("SELECT * FROM userbase WHERE email = $1", [email]);
            const user = result.rows[0];
            if (!user)
                return res.status(400).json({msg: "No User Founded"});
            if (!await bcrypt.compare(pin, user.pin))
                return res.status(400).json({ msg: "Pin Mismatched" })
            const token = jwt.sign(
                { user: user._id.toString() },
                process.env.DATABASE_PASSWORD, {
                    expiresIn: 360000
            })
            res.cookie('token', token, { httpOnly: true }).json(token)
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },

    loginWithPassword: async (req, res) => {
        try {
            const { email, password } = req.body;
            const result = await pool.query("SELECT * FROM userbase WHERE email = $1", [email]);
            const user = result.rows[0];
            if (!user)
                return res.status(400).json({msg: "No User Founded"});
            if (!await bcrypt.compare(password, user.password))
                return res.status(400).json({msg: "Password Mismatched"})
            const token = jwt.sign(
                { user: user._id.toString() },
                process.env.DATABASE_PASSWORD, {
                    expiresIn: 360000
            })
            res.cookie('token', token, { httpOnly: true }).json(token)
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },

    forgotPasswordRequest: async (req, res) => {
        try {
            const { email } = req.body
            const result = await pool.query("SELECT * FROM userbase WHERE email = $1", [email]);
            const user = result.rows[0];
            if (!user)
                return res.status(400).json({ msg: "No User Founded" });
            const payload = {
                password: user.password
            }
            const token = jwt.sign(payload, user.password, {
                expiresIn: 3600
            })
            res.json(token)
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },

    resetPassword: async (req, res) => {
        let tokenValid = true;
        try {
            const { email, password } = req.body
            const result = await pool.query("SELECT * FROM userbase WHERE email = $1", [email]);
            const user = result.rows[0];
            const token = req.params.requestId
            jwt.verify(token, user.password, (err) => {
                if(err){
                    tokenValid = false
                    return res.status(400).json({msg: "Token Expired"})
                }
            })
            if(tokenValid){
                const passwordHashed = await bcrypt.hash(password, 8)
                await pool.query("UPDATE userBase SET password = $1", [passwordHashed]);
                res.json({ msg: "Password Changed Succesfully" })
            }
        } catch (error) {
            console.log(error)
            if(tokenValid)
                res.status(500).json({ msg: "Internal Server Error" })
        }
    }
}