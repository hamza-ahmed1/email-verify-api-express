const express = require('express');
const sql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors=require('cors')
//cookie
const cookieParser = require('cookie-parser');
//apply cookie-parser middleware





const app=express();
const db=sql.createConnection({
    host:'localhost',
    user:'root',
    password:'daniyal',
    database:'db_verify'
})
app.use(express.json());
app.use(cookieParser())
app.use(cors())
db.connect((err)=>{
    if(err) throw err;
    console.log('connected to db')
})
app.get('/',(req,res)=>{
    res.send('Hello World');
})
// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'k233039@nu.edu.pk',
        pass: 'Xojfw7ne'
    }
});

// Registration endpoint
app.get('/register',(req,res)=>{
    res.send('register');
})
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    console.log(req.body);
    const redirectUrl = `http://localhost:3000/login`;  
    try {
      // Await the hashed password
      const hashedPassword = await bcrypt.hash(password, 10);
      const verificationCode = crypto.randomBytes(32).toString('hex');
      console.log(email, password, hashedPassword, verificationCode);
  
      // Insert the user into the database
      db.query('INSERT INTO users (email, password, verificationCode) VALUES (?, ?, ?)',
        [email, hashedPassword, verificationCode], (err, result) => {
          if (err) return res.status(500).send(err);
  
          // Set up the email options
          const mailOptions = {
            from: 'k233039@nu.edu.pk',
            to: email,
            subject: 'Verify your email',
            text: `Click this link to verify your email: http://localhost:3001/verify-email?code=${verificationCode}&redirectUrl=${encodeURIComponent(redirectUrl)}`
          };
  
          // Send the verification email
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) return res.status(500).send(error.toString());
            res.status(200).send('Registration successful! Please check your email to verify your account.');
          });
        });
    } catch (err) {
      res.status(500).send(err);
    }
  });
  

// Email verification endpoint
app.get('/verify-email', (req, res) => {
    const { code, redirectUrl } = req.query;
    db.query('SELECT * FROM users WHERE verificationCode = ?', [code], (err, result) => {
        if (err) return res.status(500).send(err);
        if (result.length === 0) return res.status(400).send('Invalid verification code');

        db.query('UPDATE users SET isEmailVerified = TRUE WHERE id = ?', [result[0].id], (err) => {
            if (err) return res.status(500).send(err);
            if(redirectUrl)
            {
                res.status(200).redirect(redirectUrl);
            }
           
        });
    });
});
// Login endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, result) => {
        if (err) return res.status(500).send(err);
        if (result.length === 0) return res.status(400).send('User not found');
        if (!result[0].isEmailVerified) return res.status(400).send('Email not verified');

        const user = result[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(400).send('Invalid credentials');

        const token = jwt.sign({ id: user.id, email: user.email }, 'your_jwt_secret', { expiresIn: '1h' });
        res.status(200).json({ token });
    });
});
app.listen(3001,()=>{
    console.log('Server is running on port 3001');
})