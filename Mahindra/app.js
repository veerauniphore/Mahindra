const crypto = require('crypto');

function encrypt(clearTextData, encryptionKey) {

    const algorithm = 'aes-256-cbc';
    const hashedKey = crypto.createHash('sha256').update(encryptionKey).digest();
    const key = hashedKey.slice(0, 32);
    const iv = Buffer.alloc(16, 0);

    const cipher = crypto.createCipheriv(algorithm, key, iv);

    let encryptedData = cipher.update(clearTextData, 'utf8', 'base64');
    encryptedData += cipher.final('base64');

    return encryptedData;

    
}    

function decrypt(cipherData, decryptionKey) {

    const algorithm = 'aes-256-cbc';
    const hashedKey = crypto.createHash('sha256').update(decryptionKey).digest();
    const key = hashedKey.slice(0, 32);

    const iv = Buffer.alloc(16, 0);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    let decryptedData = decipher.update(cipherData, 'base64', 'utf8');
    decryptedData += decipher.final('utf8');

    return decryptedData;


}    

const encryptionKey = 'Uniphore@Mahindra';
const clearTextData = 'Veerapandiyan';
const encryptedData = encrypt(clearTextData, encryptionKey);
console.log('Encrypted Data:', encryptedData);

const decryptionKey = 'Uniphore@Mahindra'; // Should match the key used for encryption
const cipherData = 'Y0SmkuPXeUQ46D2tMuVcYQ==';
const decryptedData = decrypt(cipherData, decryptionKey);
console.log('Decrypted Data:', decryptedData);
