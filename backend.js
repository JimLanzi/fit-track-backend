"use strict";
var express = require('express');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
var exjwt = require('express-jwt');
var mysql = require('mysql');
var config = require('./config.js');
var pwlib = require('./password.js');

// Establish Database connection
var connection = mysql.createConnection(config.dbconfig);

connection.connect( (err) => {
    if(!err)
    {
        console.log('Database is connected ...');
    }
    else
    {
        console.log('Error connecting to database.');
    }
});


// Start Express App
var app = express();

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.setHeader('Access-Control-Allow-Headers', 'Content-type,Authorization');
    next();
});

// Set up body parser to use json and set it to req.body
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

// instantiate express-jwt middleware
var jwtMW = exjwt({secret: config.secret});

var router = express.Router();


app.get('/api/hello', (req, res) => {
   res.send("Hello World!");
});

// Registration Route:
app.post("/api/register", (req, res) => {
  console.log('Attempting to Register',req.body.user_name);
  connection.query(
    "SELECT * FROM users WHERE user_name = ?", req.body.user_name,
    function(err, rows, fields)
    {
      if(err)
      {
        console.log("An error occured while querying database for existing user.");
        console.log(err);
      }
      else
      {
        if (rows.length > 0)
        {
            console.log('User already registered');
            res.status(401).json({
            sucess:false,
            token:null,
            err:'Username already registered'
          });
        }
        else
        {
            console.log('Successfully picked unique username');
            var today = new Date();
            var passwordData = pwlib.saltHashPassword(req.body.password);
            var user = {
              'user_name': req.body.user_name,
              'first_name': req.body.first_name,
              'last_name': req.body.last_name,
              'passwordSalt': passwordData.salt,
              'passwordHash': passwordData.hash,
              'created': today
            };
            connection.query(
              "INSERT INTO users SET ?", user,
              function(err, rows, fields)
              {
                if(err)
                {
                  console.log("An error occured while trying to add user to database");
                  console.log(err);
                }
                else
                {
                  console.log("No errors occured while inserting user onto table");
                  let payload = {
                    user_name: user.user_name,
                    first_name: user.first_name,
                    last_name: user.last_name
                  }
                  let token = jwt.sign(payload, config.secret, {expiresIn: 129600});
                  res.json({success:true, err:null, token});
                }
              });
        }
      }
    }
  );
});


// Login Route:
app.post('/api/login', (req,res) => {
    console.log('Attempting to log in');
    var user_name = req.body.user_name;
    var password = req.body.password;
    console.log('Searching db for ',user_name);
    connection.query('SELECT * FROM users WHERE user_name = ?', [user_name],
    (error, results, fields) => {
        if (error)
        {
            console.log('error occured',error);
            res.status(401).json({success: false, err: 'Login Failure', token: null});
        }
        else
        {
            if(results.length > 0)
            {
                console.log('Found user ',user_name,'...checking password');
                if(pwlib.checkUserPassword(results[0].passwordSalt, results[0].passwordHash, password))
                {
                    console.log('Login Success!');
                    let payload = {
                                     user_name: results[0].user_name,
                                     first_name: results[0].first_name,
                                     last_name: results[0].last_name
                                  };
                    // Signing the token
                    let token = jwt.sign(payload, config.secret, { expiresIn: 129600 }); 
                    res.json({success: true, err: null, token});
                }
                else
                {
                    console.log('Login Fail! Username and Pass do not match');
                    res.status(401).json({success: false, err: 'Username and password do not match', token: null});
                }
            }
            else
            {
                console.log('Login Fail! Username not registered');
                res.status(401).json({success: false, err: 'Username not registered', token: null});
            }
        }
    });
});


// test authenticated route
app.get('/api/', jwtMW, (req,res) => {res.send('you are authenticated')});


// Use the jwt middleware instance on the /coffee route 
// If user does not send a valid token, response function 
// won't hit
app.get('/api/coffee', jwtMW, (req, res) => {
    // jwt token fields (user_name in this case) are found in 
    // the req.user structure ...
    console.log('Coffee authorized for ',req.user.user_name);
    res.json({response: req.user.user_name+' is authorized for coffee'});
    });



app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') 
    { 
        console.log('Unauthorized Error');
        res.status(401).send(err);
    }
    else 
    {
        next(err);
    }
});


app.listen(4000);
console.log('listening on port 4000');
