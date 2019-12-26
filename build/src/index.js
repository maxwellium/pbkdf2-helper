import { pbkdf2, randomBytes } from 'crypto';
export const DEFAULTS = {
    /** in (bytes) */
    SALT_SIZE: 16,
    PBKDF2_ITERATIONS: 50000,
    /** in (bytes) */
    HASH_SIZE: 16
};
export function calculateHash(secret, salt) {
    return new Promise(async (resolve, reject) => {
        const _salt = salt || await generateSalt();
        pbkdf2(secret, _salt, DEFAULTS.PBKDF2_ITERATIONS, DEFAULTS.HASH_SIZE, 'sha512', (err, hash) => err ? reject(err) : resolve(_salt.toString('hex') + '.' + hash.toString('hex')));
    });
}
export async function verifyHash(oldSalt, oldHash, value) {
    const newHash = await calculateHash(value, Buffer.from(oldSalt, 'hex'));
    return newHash === oldSalt + '.' + oldHash;
}
export async function comparePasswords(hashedPassword, unverifiedPassword) {
    const [salt, hash] = hashedPassword.split('.');
    return verifyHash(salt, hash, unverifiedPassword);
}
export function generateSalt(size = DEFAULTS.SALT_SIZE) {
    return new Promise((resolve, reject) => randomBytes(size, (err, salt) => err ? reject(err) : resolve(salt)));
}
//# sourceMappingURL=index.js.map