const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');

const config = require('../config');

// This function is used to create our JWTs, including info about
// the user in the payload:
const createAuthToken = user => {
    // we use the jwt.sign function to create a JWT.  The first argument
    // is a payload: in this case, and object containing the information
    // about our user.  The second argument is the JWT_SECRET, or the secret
    // key that we use to sign the JWT with.  If this becomes public, then 
    // anyone would be able to create a valid token, which would allow them
    // to authenticate as any user.  This means that it is vital that this 
    // piece of information isn't leaked, and REMAINS ON THE SERVER-SIDE.
    return jwt.sign({user}, config.JWT_SECRET, {
        // the Third argument contains additional options and claims.  We set
        // up the SUB and EXP claims using the subject and expiresIn properties,
        // and specify that we want to use the HS256 algorithm to sign the token.
        // we default to the token expiring in one week (see config.js)
        subject: user.username,
        expiresIn: config.JWT_EXPIRY,
        algorithm: 'HS256'
    });
};

const router = express.Router();

// Protects the /api/auth/login endpoint
router.post(
    '/login',
    // The user provides a username and password to login
    // to use our basic auth strategy in the route, the below line is used.
    // we set session to FALSE to stop Passport adding SESSION COOKIES which
    // identify the user to the response.  Instead of using these cookies
    // to authenticate, the user supplies their JWT in a request header.
    // This helps prevent against Cross-Site Request Forgery (CSRF) Attacs, which
    // can allow attackers to gain access to a user's details.
    passport.authenticate('basic', {session: false}),
    (req, res) => {
        // This createAuthToken functino is used in the /api/auth/login route:
        const authToken = createAuthToken(req.user.apiRepr());
        res.json({authToken});
        // When the user provides a valid username and password, we create a JWT 
        // using the API-safe representation of the user information as the payload.
        // The token is sent back to the user, who can store it and use it to 
        // authenticate for subsequent API requests.
    }
);

// The final part of the login system allows users to refresh their tokens,
// receiving a token with a later expiry date when they supply a valid
// token to /api/auth/refresh:
router.post(
    '/refresh',
    // The user exchanges an existing valid JWT for a new one with a later
    // expiration
    passport.authenticate('jwt', {session: false}),
    (req, res) => {
        const authToken = createAuthToken(req.user);
        res.json({authToken});
    }
);

module.exports = {router};
