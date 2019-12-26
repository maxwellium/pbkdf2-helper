/// <reference types="node" />
export declare const DEFAULTS: {
    /** in (bytes) */
    SALT_SIZE: number;
    PBKDF2_ITERATIONS: number;
    /** in (bytes) */
    HASH_SIZE: number;
};
export declare function calculateHash(secret: string, salt?: Buffer): Promise<string>;
export declare function verifyHash(oldSalt: string, oldHash: string, value: string): Promise<boolean>;
export declare function comparePasswords(hashedPassword: string, unverifiedPassword: string): Promise<boolean>;
export declare function generateSalt(size?: number): Promise<Buffer>;
