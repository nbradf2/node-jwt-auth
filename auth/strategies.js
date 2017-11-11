// Now that we are able to generate and store relatively secure passwords,
// we can require users to provide their credentials in order to access
// endpoints.
// To do this, we use passport.js to set up a basic authentication strategy.
// The strategy will retrieve the username and pass from the request's
// Authorization header and check whether they are valid.  We use the strategy
// to protect the /api/auth/login endpoint, so users have to provide valid
// credentials in order to obtain access.

const passport = require('passport');
const {BasicStrategy} = require('passport-http');
const {
    // Assigns the Strategy export to the name JwtStrategy using object
    // destructuring
    // https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment#Assigning_to_new_variable_names
    Strategy: JwtStrategy,
    ExtractJwt
} = require('passport-jwt');

const {User} = require('../users/models');
const {JWT_SECRET} = require('../config');

// BASIC authentication strategy (to use, register in server.js):
const basicStrategy = new BasicStrategy((username, password, callback) => {
    let user;
    // We look for a user with the supplied username.
    User.findOne({username: username})
        .then(_user => {
            user = _user;
            if (!user) {
                // Return a rejected promise so we break out of the chain of .thens.
                // Any errors like this will be handled in the catch block.
                return Promise.reject({
                    reason: 'LoginError',
                    message: 'Incorrect username or password'
                });
            }
            // If the user is found, we then call the validatePassword method
            // with the (password) from the request header, which returns a promise,
            // which resolves with a Boolean value indicating whether or not the 
            // password is valid.  If the password is valid, the user object will be
            // be added to the request object at req.user.  If not, we'll throw
            // an error message.
            return user.validatePassword(password);
        })
        .then(isValid => {
            if (!isValid) {
                return Promise.reject({
                    reason: 'LoginError',
                    message: 'Incorrect username or password'
                });
            }
            return callback(null, user);
        })
        .catch(err => {
            if (err.reason === 'LoginError') {
                return callback(null, false, err);
            }
            return callback(err, false);
        });
});

// After our user has their JWT, it needs to access an endpoint.  In order
// to make this work, we'll set up a second Passport strategy below:
const jwtStrategy = new JwtStrategy(
    {
        // We pass the same secret key that was used to sign the tokens,
        // and specify that we will only allow tokens signed with the
        // HS256 algorithm.
        secretOrKey: JWT_SECRET,
        // Look for the JWT as a Bearer auth header
        // jwtFromRequest property tels the strategy where it should
        // find the JWT in requests to our API.  In this case we say that
        // it should look in the request's Authorization header, and
        // that this will be using the "Bearer" scheme.
        jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('Bearer'),
        // Only allow HS256 tokens - the same as the ones we issue
        algorithms: ['HS256']
    },

    // If a valid JWT is supplied to the strategy above, the this callback will
    // be run.  In the callback, we indicate that we have authenticated 
    // successfully, assigning the USER property decoded from PAYLOAD to
    // req.user in the request object.
    (payload, done) => {
        done(null, payload.user);

        // To register this JWT strategy with Passport, use the passport.use
        // method in server.js
    }
);

module.exports = {basicStrategy, jwtStrategy};
