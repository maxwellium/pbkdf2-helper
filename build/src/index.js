"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
exports.DEFAULTS = {
    /** in (bytes) */
    SALT_SIZE: 16,
    PBKDF2_ITERATIONS: 50000,
    /** in (bytes) */
    HASH_SIZE: 16
};
function calculateHash(secret, salt) {
    return new Promise(async (resolve, reject) => {
        const _salt = salt || await generateSalt();
        crypto_1.pbkdf2(secret, _salt, exports.DEFAULTS.PBKDF2_ITERATIONS, exports.DEFAULTS.HASH_SIZE, 'sha512', (err, hash) => err ? reject(err) : resolve(_salt.toString('hex') + '.' + hash.toString('hex')));
    });
}
exports.calculateHash = calculateHash;
async function verifyHash(oldSalt, oldHash, value) {
    const newHash = await calculateHash(value, Buffer.from(oldSalt, 'hex'));
    return newHash === oldSalt + '.' + oldHash;
}
exports.verifyHash = verifyHash;
async function comparePasswords(hashedPassword, unverifiedPassword) {
    const [salt, hash] = hashedPassword.split('.');
    return verifyHash(salt, hash, unverifiedPassword);
}
exports.comparePasswords = comparePasswords;
function generateSalt(size = exports.DEFAULTS.SALT_SIZE) {
    return new Promise((resolve, reject) => crypto_1.randomBytes(size, (err, salt) => err ? reject(err) : resolve(salt)));
}
exports.generateSalt = generateSalt;
//# sourceMappingURL=index.js.map