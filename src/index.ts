import { pbkdf2, randomBytes } from 'crypto';

export const DEFAULTS = {
  /** in (bytes) */
  SALT_SIZE: 16,
  PBKDF2_ITERATIONS: 50000,
  /** in (bytes) */
  HASH_SIZE: 16
};



export function calculateHash( secret: string, salt?: Buffer ): Promise<string> {
  return new Promise( async ( resolve, reject ) => {

    const _salt = salt || await generateSalt();

    pbkdf2( secret, _salt, DEFAULTS.PBKDF2_ITERATIONS, DEFAULTS.HASH_SIZE, 'sha512',
      ( err, hash ) => err ? reject( err ) : resolve(
        _salt.toString( 'hex' ) + '.' + hash.toString( 'hex' )
      )
    );
  } );
}

export async function verifyHash(
  oldSalt: string, oldHash: string, value: string
): Promise<boolean> {
  const newHash = await calculateHash( value, Buffer.from( oldSalt, 'hex' ) );
  return newHash === oldSalt + '.' + oldHash;
}

export async function comparePasswords(
  hashedPassword: string, unverifiedPassword: string
): Promise<boolean> {
  const [ salt, hash ] = hashedPassword.split( '.' );
  return verifyHash( salt, hash, unverifiedPassword );
}

export function generateSalt( size: number = DEFAULTS.SALT_SIZE ): Promise<Buffer> {
  return new Promise( ( resolve, reject ) => randomBytes(
    size, ( err, salt ) => err ? reject( err ) : resolve( salt )
  ) );
}
