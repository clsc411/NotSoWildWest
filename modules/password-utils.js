// modules/password-utils.js
const argon2 = require('argon2');

// Argon2 configuration options
// These values provide a good balance of security and performance
const ARGON2_OPTIONS = {
  type: argon2.argon2id,  // Uses a hybrid approach (best for most cases)
  memoryCost: 65536,      // 64 MB memory cost
  timeCost: 3,            // Number of iterations
  parallelism: 4          // Number of parallel threads
};

/*
validatePassword takes a password and checks to see if
it passes some standard requirements (like length, an uppercase, etc)
*/
function validatePassword(password) {
  const errors = [];
  
  if (!password) {
    errors.push('Password is required');
    return { valid: false, errors };
  }
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    valid: errors.length === 0,
    errors: errors
  };
}

// simple function that will hash a password.
async function hashPassword(password) {
  return await argon2.hash(password, ARGON2_OPTIONS);
}


// Compares a plain text password with a hashed password

async function comparePassword(password, hash) {
  return await argon2.verify(hash, password);
}

module.exports = {
  validatePassword,
  hashPassword,
  comparePassword
};
