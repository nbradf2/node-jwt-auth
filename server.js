require('dotenv').config();
const bodyParser = require('body-parser');
const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const passport = require('passport');

// Here we use destructuring assignment with renaming so the two variables
// called router (from ./users and ./auth) have different names
// For example:
// const actorSurnames = { james: "Stewart", robert: "De Niro" };
// const { james: jimmy, robert: bobby } = actorSurnames;
// console.log(jimmy); // Stewart - the variable name is jimmy, not james
// console.log(bobby); // De Niro - the variable name is bobby, not robert
const {router: usersRouter} = require('./users');
const {router: authRouter, basicStrategy, jwtStrategy} = require('./auth');

mongoose.Promise = global.Promise;

const {PORT, DATABASE_URL} = require('./config');

const app = express();

// Logging
app.use(morgan('common'));

// CORS
app.use(function(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE');
    if (req.method === 'OPTIONS') {
        return res.send(204);
    }
    next();
});

// To use the BASIC auth strategy, register here in server.js
app.use(passport.initialize());
// To use the basic auth strategy in a route, we initialize Passport, 
// and register the strategy in server.js:
passport.use(basicStrategy);
// To register our JWT strategy with Passport, use the passport.use method:
passport.use(jwtStrategy);

app.use('/api/users/', usersRouter);
app.use('/api/auth/', authRouter);
// Then, we can use this to protect the /api/auth/login endpoint defined 
// in /auth/router.js

// A protected endpoint which needs a valid JWT to access it
// This uses the JWT strategy to protect endpoints:
app.get(
    '/api/protected',
    // use passport.authenticate middleware to protect the endpoint,
    // this time passing JWT as the argument so it uses the JWT strategy
    // instead of the basic AUTH strategy.  If an authenticated user
    // access the endpoint, we respond with our protected message.
    passport.authenticate('jwt', {session: false}),
    (req, res) => {
        return res.json({
            data: 'rosebud'
        });
    }
);

app.use('*', (req, res) => {
    return res.status(404).json({message: 'Not Found'});
});

// Referenced by both runServer and closeServer. closeServer
// assumes runServer has run and set `server` to a server object
let server;

function runServer() {
    return new Promise((resolve, reject) => {
        mongoose.connect(DATABASE_URL, {useMongoClient: true}, err => {
            if (err) {
                return reject(err);
            }
            server = app
                .listen(PORT, () => {
                    console.log(`Your app is listening on port ${PORT}`);
                    resolve();
                })
                .on('error', err => {
                    mongoose.disconnect();
                    reject(err);
                });
        });
    });
}

function closeServer() {
    return mongoose.disconnect().then(() => {
        return new Promise((resolve, reject) => {
            console.log('Closing server');
            server.close(err => {
                if (err) {
                    return reject(err);
                }
                resolve();
            });
        });
    });
}

if (require.main === module) {
    runServer().catch(err => console.error(err));
}

module.exports = {app, runServer, closeServer};
