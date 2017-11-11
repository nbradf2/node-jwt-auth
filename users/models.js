const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

mongoose.Promise = global.Promise;

const UserSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    firstName: {type: String, default: ''},
    lastName: {type: String, default: ''}
});

UserSchema.methods.apiRepr = function() {
    return {
        username: this.username || '',
        firstName: this.firstName || '',
        lastName: this.lastName || ''
    };
};

// This is how the password validation function works:
// We use BCRYPT to compare the plain text value passed to the function (password)
// with the hashed value stored on the user object (this.password), ultimately
// resolving with a boolean value indicating if the password is valid.
UserSchema.methods.validatePassword = function(password) {
    return bcrypt.compare(password, this.password);
};

// Using the BCRYPTJS library to handle encrypting user passwords.
// we call the bcrypt HASH method with the raw password and an integer
// value indicating how many rounds of the salting algorithm should be used.
// The higher this number is, the more computationally difficult it is to
// compare two passwords.  A value between 10 and 12 provides good balance
// between taking long enough so brute-force cracking is difficult, and
// being quick enough so that your app is responsive to your users.
UserSchema.statics.hashPassword = function(password) {
    return bcrypt.hash(password, 10);
};

const User = mongoose.model('User', UserSchema);

module.exports = {User};
