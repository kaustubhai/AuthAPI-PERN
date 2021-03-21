const bcrypt = require('bcryptjs')
const pool = require('../utils/connectDB')

module.exports = {
    getUser: async (req, res) => {
        try {
            const result = await pool.query("SELECT * FROM userBase WHERE _id = $1", [req.user])
            const user = result.rows[0]
            res.json({
                name: user.name,
                email: user.email
            })
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },
    updateName: async (req, res) => {
        try {
            const { name } = req.body
            await pool.query("UPDATE userBase SET name = $1 WHERE _id = $2", [name, req.user]);
            res.json({msg: "Name Updated Succesfully"})
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },
    updateEmail: async (req, res) => {
        try {
            const { email } = req.body
            let result = await pool.query("SELECT * FROM userBase WHERE email = $1", [email])
            let user = result.rows[0];
            if (user)
                return res.status(400).json({msg: "User already exists"});
            if(!email.match(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/))
                return res.status(400).json({msg: "Invalid Mail Provided"});
            await pool.query("UPDATE userBase SET email = $1 WHERE _id = $2", [email, req.user]);
            res.json({msg: "Email Updated Succesfully"})
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },
    resetPin: async (req, res) => {
        try {
            const { newPin, password } = req.body;
            if (newPin.match(/[^0-9]/g))
                return res.status(400).json({msg: "Pin should consist only numbers"})
            if (newPin.length !== 4)
                return res.status(400).json({msg: "Pin should be exactly 4 length"})
            const result = await pool.query("SELECT * FROM userBase WHERE _id = $1", [req.user])
            const user = result.rows[0];
            if (!await bcrypt.compare(password, user.password))
                return res.status(400).json({msg: "Invalid Password"});
            const hashed = await bcrypt.hash(newPin, 4);
            await pool.query("UPDATE userBase SET pin = $1", [hashed]);
            res.json({msg: "Pin Updated"})
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },
    resetPassword: async (req, res) => {
        try {
            const { password, newPassword } = req.body;
            if (newPassword.length < 8)
                return res.status(400).json({msg: "Password should be of 8 characters atleast"})
            const result = await pool.query("SELECT * FROM userBase WHERE _id = $1", [req.user]);
            const user = result.rows[0]
            if (!await bcrypt.compare(password, user.password))
                return res.status(400).json({msg: "Invalid Password"});
            const hashed = await bcrypt.hash(newPassword, 8);
            await pool.query("UPDATE userBase SET password = $1", [hashed]);
            res.json({msg: "Password Updated"})
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    },
    logoutUser: async (req, res) => {
        try {
            res.clearCookie('token')
            res.json({msg: "User logged out"})
        } catch (error) {
            console.log(error)
            res.status(500).json({msg: "Internal Server Error"})
        }
    }
}