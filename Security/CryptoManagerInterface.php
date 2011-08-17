<?php

namespace Epicoftimewasted\CryptoBundle\Security;

/**
 * This is NOT designed to be a general purpose cryptography interface.
 * Instead, this is designed to provide a set of best practices.
 */
interface CryptoManagerInterface
{
	/**
	 * Gets the current hashing algorithm.
	 *
	 * @return string The current hashing algorithm
	 */
	public function getHashAlgorithm();

	/**
	 * Gets the output size of the current hashing algorithm in bytes.
	 *
	 * @return integer The output size of the current hashing algorithm in bytes
	 */
	public function getHashAlgorithmSize();

	/**
	 * Change the current hashing algorithm.
	 *
	 * @param string $newAlgorithm The hashing algorithm that we want to use
	 */
	public function changeHashAlgorithm($newAlgorithm);

	/**
	 * Restores the previously used hashing algorithm.
	 */
	public function restoreHashAlgorithm();

	/**
	 * Generates random bytes of data (entropy).
	 *
	 * @param integer $amount The amount of entropy, in bytes, to generate
	 * @return string The generated entropy
	 */
	public function getEntropy($amount);

	/**
	 * Password-based key derivation function 2.
	 * See section 5.2 of http://www.ietf.org/rfc/rfc2898.txt
	 *
	 * @param string $password The password to be transformed into a key
	 * @param string $salt The salt to use
	 * @param integer $iterations The number of times to iterate the hash function
	 * @param integer $keySize The desired size of the key in bytes
	 * @return string The derived key
	 */
	public function pbkdf2($password, $salt, $iterations, $keySize);

	/**
	 * Hash a message (generally a password) with the bcrypt algorithm.
	 *
	 * Note that while bcrypt will support work factors as low as 4, this
	 * enforces a floor of 8.  There is usually no good reason to go any lower
	 * than this.
	 *
	 * @param string $message The message (password) to be hashed
	 * @param string $salt The salt to use
	 * @param integer $workFactor The work factor (strength) of the hash
	 * @return string The hashed message
	 */
	public function bcrypt($message, $salt = null, $workFactor = 11);

	/**
	 * Generate an RSA public/private key pair.
	 *
	 * @param integer $keySize The desired size in bits of the keys to generate
	 * @param string $passphrase The passphrase to use for the private key, or null if no passphrase
	 */
	public function generateKeyPair($keySize = 2048, $passphrase = null);

	/**
	 * Import a public encryption key for usage.
	 *
	 * @param string $key The key to import, which can be a string representation or a file:// URI to the key's location on disk
	 */
	public function importPublicKey($key);

	/**
	 * Export the stored public encryption key.
	 *
	 * @return string|null Returns the stored key on success, or null if there is no key
	 */
	public function exportPublicKey();

	/**
	 * Import a private encryption key for usage.
	 *
	 * @param string $key The key to import, which can be a string representation or a file:// URI to the key's location on disk
	 * @param string $passphrase The passphrase used to decrypt the private key, or null if no passphrase
	 */
	public function importPrivateKey($key, $passphrase = null);

	/**
	 * Export the stored private encryption key.
	 *
	 * @param string $passphrase The passphrase used to decrypt the private key, or null if no passphrase
	 * @return string|null Returns the stored key on success, or null if there is no key
	 */
	public function exportPrivateKey($passphrase = null);

	/**
	 * Encrypt a message using the stored public key.
	 * To decrypt, use decryptPrivate().
	 *
	 * NOTE: This function uses OAEP padding, which means that it uses the
	 * current hashing algorithm to pad the message.  This means that your
	 * choice of hashing algorithm and key size could severely limit the
	 * maximum length of the message that can be encrypted.  For example, using
	 * a key size of 1024 bits and a hashing algorithm of SHA-1 limits the
	 * maximum message length to 86 bytes.  However, if you were to use SHA-512,
	 * you would not be able to encrypt a message at all using a 1024 bit key.
	 *
	 * @param string $message The message to be encrypted
	 * @return string The encrypted message on success
	 */
	public function encryptPublic($message);

	/**
	 * Encrypt a message using the stored private key.
	 * To decrypt, use decryptPublic().
	 *
	 * NOTE: This function uses OAEP padding, which means that it uses the
	 * current hashing algorithm to pad the message.  This means that your
	 * choice of hashing algorithm and key size could severely limit the
	 * maximum length of the message that can be encrypted.  For example, using
	 * a key size of 1024 bits and a hashing algorithm of SHA-1 limits the
	 * maximum message length to 86 bytes.  However, if you were to use SHA-512,
	 * you would not be able to encrypt a message at all using a 1024 bit key.
	 *
	 * @param string $message The message to be encrypted
	 * @return string The encrypted message on success
	 */
	public function encryptPrivate($message);

	/**
	 * Decrypt a message using the stored public key.
	 * Used to decrypt for encryptPrivate().
	 *
	 * @param string $message The message to be decrypted
	 * @return string The decrypted message on success
	 */
	public function decryptPublic($message);

	/**
	 * Decrypt a message using the stored private key.
	 * Used to decrypt for encryptPublic().
	 *
	 * @param string $message The message to be decrypted
	 * @return string The decrypted message on success
	 */
	public function decryptPrivate($message);

	/**
	 * AES-256-CTR (symmetric) encryption.
	 *
	 * @param string $message The message to be encrypted
	 * @param string $passphrase The passphrase to use to derive the encryption key
	 * @return string The encrypted message
	 */
	public function encrypt($message, $passphrase);

	/**
	 * AES-256-CTR (symmetric) decryption.
	 *
	 * @param string $message The message to be decrypted
	 * @param string $passphrase The passphrase to use to derive the decryption key
	 * @return string The decrypted message
	 */
	public function decrypt($message, $passphrase);
}
