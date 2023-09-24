const express = require('express')
const cors = require('cors')
const app = express()

const bodyParser = require('body-parser')
const jsonParser = bodyParser.json()

const bcrypt = require('bcrypt')
const saltRound = 10

const jwt = require('jsonwebtoken')
const secret = 'Fullstack-Login'

const mysql = require('mysql2')
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '100718',
    database: 'mydb',
})

app.use(cors())
// app.use(jsonParser)

app.post('/register', jsonParser, (req, res) => {

    const { email, password, fname, lname } = req.body
    const sql = 'INSERT INTO user (email, password, fname, lname) VALUES (?, ?, ?, ?)'

    //callback function
    const saveToDb = (hashPassword) => {
        connection.query(sql,
            [email, hashPassword, fname, lname],
            (err, results,) => {
                if (err) {
                    res.json({ status: 'error', message: err })
                    return
                }
    
                res.json({ status: 'ok' })
            })
    }

    bcrypt.hash(password, saltRound, (err, hash) =>{
        saveToDb(hash)
    })

})

app.post('/login', jsonParser, (req, res) => {

    const {email, password} = req.body
    const sql = 'SELECT * FROM user WHERE email = ?'
    connection.query(sql, [email], (err, users, fields) => {

        if(err){
            res.json({
                status: 'error',
                message: err
            })
            return
        }

        if(users.length == 0){
            res.json({
                status: 'error',
                message: 'no user found'
            })

            return
        }

        bcrypt.compare(password, users[0].password, (err, isLogin) => {
            if(isLogin){
                const token = jwt.sign({email: users[0].email}, secret, {expiresIn: '1h'})
                res.json({status: 'ok', message: 'login success', token})
            }
            else{
                res.json({status: 'error', message: 'login failed'})
            }
        })
    })
})

app.post('/authen', jsonParser, (req, res) =>{

    try{
        const token = req.headers.authorization.split(' ')[1]
        const decoded = jwt.verify(token, secret)
        res.json({status: 'ok', decoded})
    } catch(err){
        res.json({status: 'error', message: err})
    }

})

app.listen(8080, () => {
    console.log('COR-enabled web sever listening on port 8080')
})