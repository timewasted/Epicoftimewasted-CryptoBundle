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
	 * @param int $amount The amount of entropy, in bytes, to generate
	 * @return string The generated entropy
	 */
	public function getEntropy($amount);

	/**
	 * Password-based key derivation function 2.
	 * See section 5.2 of http://www.ietf.org/rfc/rfc2898.txt
	 *
	 * @param string $password The password to be transformed into a key
	 * @param string $salt The salt to use
	 * @param int $iterations The number of times to iterate the hash function
	 * @param int $keySize The desired size of the key in bytes
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
	 * @param int $workFactor The work factor (strength) of the hash
	 * @return string The hashed message
	 */
	public function bcrypt($message, $salt = null, $workFactor = 11);

	/**
	 * Generate an RSA public/private key pair.
	 *
	 * @param integer $keySize The desired size in bits of the keys to generate
	 * @param string $passphrase The passphrase to use for the private key, or null if no passphrase
	 */
	public function generateKeyPair($keySize, $passphrase = null);

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
	 * @param string $message The message to be encrypted
	 * @return mixed The encrypted message on success, otherwise null on failure
	 */
	public function encryptPublic($message);

	/**
	 * Encrypt a message using the stored private key.
	 * To decrypt, use decryptPublic().
	 *
	 * @param string $message The message to be encrypted
	 * @return mixed The encrypted message on success, otherwise null on failure
	 */
	public function encryptPrivate($message);

	/**
	 * Decrypt a message using the stored public key.
	 * Used to decrypt for encryptPrivate().
	 *
	 * @param string $message The message to be decrypted
	 * @return mixed The decrypted message on success, otherwise null on failure
	 */
	public function decryptPublic($message);

	/**
	 * Decrypt a message using the stored private key.
	 * Used to decrypt for encryptPublic().
	 *
	 * @param string $message The message to be decrypted
	 * @return mixed The decrypted message on success, otherwise null on failure
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
