// This file is useful - CAN BE REPEATED THROUGHOUT MANY DIFFERENT PROJECTS!!
const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');

const {User} = require('./models');

const router = express.Router();

const jsonParser = bodyParser.json();

// Post to register a new user
router.post('/', jsonParser, (req, res) => {
    // Ensure that the username and password are defined
    const requiredFields = ['username', 'password'];
    const missingField = requiredFields.find(field => !(field in req.body));

    if (missingField) {
        return res.status(422).json({
            code: 422,
            reason: 'ValidationError',
            message: 'Missing field',
            location: missingField
        });
    }

    //Check to make sure that all of the fields are strings:
    const stringFields = ['username', 'password', 'firstName', 'lastName'];
    const nonStringField = stringFields.find(
        field => field in req.body && typeof req.body[field] !== 'string'
    );

    if (nonStringField) {
        return res.status(422).json({
            code: 422,
            reason: 'ValidationError',
            message: 'Incorrect field type: expected string',
            location: nonStringField
        });
    }

    // If the username and password aren't trimmed we give an error.  Users might
    // expect that these will work without trimming (i.e. they want the password
    // "foobar ", including the space at the end).  We need to reject such values
    // explicitly so the users know what's happening, rather than silently
    // trimming them and expecting the user to understand.
    // We'll silently trim the other fields, because they aren't credentials used
    // to log in, so it's less of a problem.

    // Check that the UN and Pass neither start or end with whitespace.
    // We explicitly reject these values rather than authomatically 
    // stripping any whitespace from the beginning and end of strings.
    // This is to prevent users who deliberately use a space at the
    // start or end of their UN or Pass from being surprised when
    // they are registered with different values
    // NOTE:  We don't perform this check for firstName and lastName.
    // Instead, we automatically strip leading and trailing whitespace from these
    // values.  This will be less damaging to the user experience.
    const explicityTrimmedFields = ['username', 'password'];
    const nonTrimmedField = explicityTrimmedFields.find(
        field => req.body[field].trim() !== req.body[field]
    );

    if (nonTrimmedField) {
        return res.status(422).json({
            code: 422,
            reason: 'ValidationError',
            message: 'Cannot start or end with whitespace',
            location: nonTrimmedField
        });
    }

    // Check to make sure that the username and password are the correct length.
    // We set a MINIMUM password length to ensure that it's reasonably hard to 
    // gues a password using a BRUTE FORCE ATTACK.  Later, we'll save an encrypted version of the password.
    const sizedFields = {
        username: {
            min: 1
        },
        password: {
            min: 10,
            // bcrypt truncates after 72 characters, so let's not give the illusion
            // of security by storing extra (unused) info
            max: 72
        }
    };
    const tooSmallField = Object.keys(sizedFields).find(
        field =>
            'min' in sizedFields[field] &&
            req.body[field].trim().length < sizedFields[field].min
    );
    const tooLargeField = Object.keys(sizedFields).find(
        field =>
            'max' in sizedFields[field] &&
            req.body[field].trim().length > sizedFields[field].max
    );

    if (tooSmallField || tooLargeField) {
        return res.status(422).json({
            // If any of the checks fail, we return a JSON error object below:
            code: 422,
            reason: 'ValidationError',
            message: tooSmallField
                ? `Must be at least ${sizedFields[tooSmallField]
                      .min} characters long`
                : `Must be at most ${sizedFields[tooLargeField]
                      .max} characters long`,
            // the LOCATION prperty identifies which field failed the check.  
            // This info can be used on the front-end to display appropriate error
            // messages to users who enter incorrect information.
            location: tooSmallField || tooLargeField
        });
    }

    let {username, password, firstName = '', lastName = ''} = req.body;
    // Username and password come in pre-trimmed, otherwise we throw an error
    // before this
    firstName = firstName.trim();
    lastName = lastName.trim();

    // Because usernames are unique in our system, we check if there is an existing user with the requested name:
    return User.find({username})
        .count()
        .then(count => {
            if (count > 0) {
                // There is an existing user with the same username
                return Promise.reject({
                    code: 422,
                    reason: 'ValidationError',
                    message: 'Username already taken',
                    location: 'username'
                });
            }
            // If there is no existing user, hash the password
            return User.hashPassword(password);
        })

        // Once we've got our hash, we save a new user, setting the PASSWORD
        // to the hash value.
        .then(hash => {
            return User.create({
                username,
                password: hash,
                firstName,
                lastName
            });
        })
        .then(user => {
            return res.status(201).json(user.apiRepr());
        })
        .catch(err => {
            // Forward validation errors on to the client, otherwise give a 500
            // error because something unexpected has happened
            if (err.reason === 'ValidationError') {
                return res.status(err.code).json(err);
            }
            // we return a generic 500 Internal Server Error message when
            // there is an unexpected error, rather than providing details
            // of the error to the client.  This stops us from leaking
            // potentially sensitive details about our database and codebase,
            // which may be contained within any errors which are thrown.
            res.status(500).json({code: 500, message: 'Internal server error'});
        });
});

// Never expose all your users like below in a prod application
// we're just doing this so we have a quick way to see
// if we're creating users. keep in mind, you can also
// verify this in the Mongo shell.
router.get('/', (req, res) => {
    return User.find()
        .then(users => res.json(users.map(user => user.apiRepr())))
        .catch(err => res.status(500).json({message: 'Internal server error'}));
});

module.exports = {router};
