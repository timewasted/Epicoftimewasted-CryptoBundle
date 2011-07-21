<?php

namespace Epicoftimewasted\CryptoBundle\Security;

class CryptoManager
{
	/**
	 * @var string $hashAlgorithm The desired hash algorithm.
	 */
	private $hashAlgorithm;

	/**
	 * @var string $hashAlgorithmSize The output size (in bytes) of this hash algorithm.
	 */
	private $hashAlgorithmSize;

	/**
	 * @var string $publicKey The string representation of a public key.
	 */
	private $publicKey;

	/**
	 * @var integer $publicKeySize The size (in bits) of this public key.
	 */
	private $publicKeySize;

	/**
	 * @var integer $publicKeyEncryptMaxSize The maximum message size (in bytes) that can be encrypted using this public key and OAEP padding.
	 */
	private $publicKeyEncryptMaxSize;

	/**
	 * @var string $privateKey The string representation of a private key.
	 */
	private $privateKey;

	/**
	 * @var integer $privateKeySize The size (in bits) of this private key.
	 */
	private $privateKeySize;

	/**
	 * @var integer $privateKeyEncryptMaxSize The maximum message size (in bytes) that can be encrypted using this private key and OAEP padding.
	 */
	private $privateKeyEncryptMaxSize;

	/**
	 * Constructor
	 *
	 * @param string $hashAlgorithm The hash algorithm to use.
	 */
	public function __construct($hashAlgorithm = 'sha512')
	{
		$this->setHashAlgorithm($hashAlgorithm);
	}

	/**
	 * Returns the current hash algorithm.
	 *
	 * @return string The hash algorithm currently in use.
	 */
	public function getHashAlgorithm()
	{
		return $this->hashAlgorithm;
	}

	/**
	 * Get the output size (in bytes) of the current hash algorithm.
	 *
	 * @return integer The size (in bytes) of the current hash algorithm.
	 */
	public function getHashAlgorithmSize()
	{
		return $this->hashAlgorithmSize;
	}

	/**
	 * Sets a new hash algorithm to be used.
	 *
	 * @param string $algorithm The hash algorithm to use.
	 * @return void
	 */
	public function setHashAlgorithm($algorithm)
	{
		if( !in_array($algorithm, hash_algos()) ) {
			throw new \InvalidArgumentException(sprintf('Invalid hash algorithm "%s".  Must be one of "%s".', $algorithm, implode(', ', hash_algos())));
		}
		$this->hashAlgorithm = $algorithm;
		$this->hashAlgorithmSize = strlen(hash($this->hashAlgorithm, null, true));

		if( $this->publicKeySize !== null ) {
			$this->publicKeyEncryptMaxSize = (int)ceil($this->publicKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;
		}
		if( $this->privateKeySize !== null ) {
			$this->privateKeyEncryptMaxSize = (int)ceil($this->privateKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;
		}
	}

	/**
	 * Returns the stored public key.
	 *
	 * @return mixed NULL on failure, string on success.
	 */
	public function getPublicKey()
	{
		if( $this->publicKey === null ) {
			return null;
		}
		return $this->publicKey;
	}

	/**
	 * Import a public key.
	 *
	 * @param mixed $pubKey This can be either a string representation, or a file:// URI to the key stored on disk.
	 * @return mixed FALSE on failure, NULL on success.
	 */
	public function setPublicKey($pubKey)
	{
		$key = openssl_pkey_get_public($pubKey);
		if( $key === false ) {
			return false;
		}
		$keyDetails = openssl_pkey_get_details($key);
		$this->publicKey = $keyDetails['key'];
		$this->publicKeySize = $keyDetails['bits'];
		$this->publicKeyEncryptMaxSize = (int)ceil($this->publicKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;
	}

	/**
	 * Returns the stored private key.
	 *
	 * @param string $passphrase The passphrase for the key, or null if none.
	 * @return mixed NULL on failure, string on success.
	 */
	public function getPrivateKey($passphrase = null)
	{
		if( $this->privateKey === null ) {
			return null;
		}
		if( empty($passphrase) ) {
			openssl_pkey_export($this->privateKey, $output);
		} else {
			openssl_pkey_export($this->privateKey, $output, $passphrase);
		}
		return $output;
	}

	/**
	 * Import a private key.
	 *
	 * @param mixed $privKey This can be either a string representation, or a file:// URI to the key stored on disk.
	 * @param string $passphrase The passphrase for the key, or null if none.
	 * @return mixed FALSE on failure, NULL on success.
	 */
	public function setPrivateKey($privKey, $passphrase = null)
	{
		if( empty($passphrase) ) {
			$key = openssl_pkey_get_private($privKey);
		} else {
			$key = openssl_pkey_get_private($privKey, $passphrase);
		}
		if( $key === false ) {
			return false;
		}
		$this->privateKey = $key;
		$keyDetails = openssl_pkey_get_details($this->privateKey);
		$this->privateKeySize = $keyDetails['bits'];
		$this->privateKeyEncryptMaxSize = (int)ceil($this->privateKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;
	}

	/**
	 * Generate a public and private key pair.
	 *
	 * @param integer $keySize The size (in bits) of the key to generate.
	 * @param string $passphrase The passphrase to use for the private key, or null if none.
	 * @return mixed FALSE on failure, TRUE on success.
	 */
	public function createKeyPair($keySize, $passphrase = null)
	{
		$config = array(
			'digest_alg'		=> $this->hashAlgorithm,
			'private_key_bits'	=> $keySize,
			'private_key_type'	=> OPENSSL_KEYTYPE_RSA,
		);
		$keyResource = openssl_pkey_new($config);
		if( $keyResource === false ) {
			return false;
		}

		/**
		 * Output of openssl_pkey_get_details()['rsa'] is defined here: http://www.openssl.org/docs/crypto/rsa.html
		 * Output of openssl_pkey_get_details()['dsa'] is defined here: http://www.openssl.org/docs/crypto/dsa.html
		 * Output of openssl_pkey_get_details()['dh'] is defined here: http://www.openssl.org/docs/crypto/dh.html
		 */
		$keyDetails = openssl_pkey_get_details($keyResource);
		$this->publicKey = $keyDetails['key'];
		$this->publicKeySize = $keyDetails['bits'];
		$this->publicKeyEncryptMaxSize = (int)ceil($this->publicKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;

		if( empty($passphrase) ) {
			openssl_pkey_export($keyResource, $this->privateKey);
			$this->privateKey = openssl_pkey_get_private($this->privateKey);
		} else {
			openssl_pkey_export($keyResource, $this->privateKey, $passphrase);
			$this->privateKey = openssl_pkey_get_private($this->privateKey, $passphrase);
		}
		$keyDetails = openssl_pkey_get_details($this->privateKey);
		$this->privateKeySize = $keyDetails['bits'];
		$this->privateKeyEncryptMaxSize = (int)ceil($this->privateKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;

		return true;
	}

	/**
	 * Encrypt data using a public key.  To decrypt, use privateDecrypt()
	 *
	 * @param string $plainText The text to be encrypted.
	 * @return mixed FALSE on failure, TRUE on success.
	 */
	public function publicEncrypt($plainText)
	{
		if( $this->publicKey === null ) {
			return false;
		}
		if( !is_string($plainText) || empty($plainText) ) {
			return false;
		}
		if( strlen($plainText) > $this->publicKeyEncryptMaxSize ) {
			return false;
		}

		$cipherText = '';
		if( openssl_public_encrypt($plainText, $cipherText, $this->publicKey, OPENSSL_PKCS1_OAEP_PADDING) === false ) {
			return false;
		}
		return $cipherText;
	}

	/**
	 * Encrypt data using a private key.  To decrypt, use publicDecrypt()
	 *
	 * @param string $plainText The text to be encrypted.
	 * @return mixed FALSE on failure, TRUE on success.
	 */
	public function privateEncrypt($plainText)
	{
		if( $this->privateKey === null ) {
			return false;
		}
		if( !is_string($plainText) || empty($plainText) ) {
			return false;
		}
		if( strlen($plainText) > $this->privateKeyEncryptMaxSize ) {
			return false;
		}

		$cipherText = '';
		if( openssl_private_encrypt($plainText, $cipherText, $this->privateKey, OPENSSL_PKCS1_OAEP_PADDING) === false ) {
			return false;
		}
		return $cipherText;
	}

	/**
	 * Decrypt data that was encrypted using privateEncrypt()
	 *
	 * @param string $cipherText The text to be decrypted.
	 * @return mixed FALSE on failure, TRUE on success.
	 */
	public function publicDecrypt($cipherText)
	{
		if( $this->publicKey === null ) {
			return false;
		}
		if( !is_string($cipherText) || empty($cipherText) ) {
			return false;
		}

		$plainText = '';
		if( openssl_public_decrypt($cipherText, $plainText, $this->publicKey, OPENSSL_PKCS1_OAEP_PADDING) === false ) {
			return false;
		}
		return $plainText;
	}

	/**
	 * Decrypt data that was encrypted using publicEncrypt()
	 *
	 * @param string $cipherText The text to be decrypted.
	 * @return mixed FALSE on failure, TRUE on success.
	 */
	public function privateDecrypt($cipherText)
	{
		if( $this->privateKey === null ) {
			return false;
		}
		if( !is_string($cipherText) || empty($cipherText) ) {
			return false;
		}

		$plainText = '';
		if( openssl_private_decrypt($cipherText, $plainText, $this->privateKey, OPENSSL_PKCS1_OAEP_PADDING) === false ) {
			return false;
		}
		return $plainText;
	}

	/**
	 * Generates entropy.
	 *
	 * Rough performance characteristics for each method of randomness are as follows:
	 *
	 * mt_rand(): Best suited for short 1-8 byte strings.  Reasonable performance up to 32 byte strings,
	 *   but still slower than openssl_random_pseudo_bytes.
	 *
	 * openssl_random_pseudo_bytes(): Best suited for 9-1536 byte strings.  Reasonable performance up to
	 *   2560 byte strings, but still slower than using /dev/urandom.
	 *
	 * /dev/urandom: By far the slowest until strings get larger than 1536 bytes.  Once the strings are
	 *   this large, though, nothing else can match it.
	 *
	 * @param integer $length The number of bytes of entropy to be generated.
	 * @return string The entropy that was generated.
	 */
	public function getEntropy($length)
	{
		if( $length <= 0 )
			return '';

		$entropy = '';
		if( $length > 1536 && file_exists('/dev/urandom') && is_readable('/dev/urandom') ) {
			if( ($file = fopen('/dev/urandom', 'r')) !== false ) {
				do {
					$entropy .= fread($file, $length - strlen($entropy));
				} while( strlen($entropy) < $length );
				fclose($file);
				return $entropy;
			}
		}

		if( function_exists('openssl_random_pseudo_bytes') ) {
			return openssl_random_pseudo_bytes($length);
		}

		do {
			$entropy .= pack('N', mt_rand(0, 0xffffffff));
		} while( strlen($entropy) < $length );
		return substr($entropy, 0, $length);
	}

	/**
	 * Password-based key derivation function 2, as defined in section 5.2:
	 * http://www.ietf.org/rfc/rfc2898.txt
	 *
	 * @param string $data The message to be transformed.
	 * @param string $salt The salt.
	 * @param integer $iterations The number of times to iterate the hash function.
	 * @param integer $keyLength The desired output size of the key.
	 * @return string The derived key.
	 */
	final public function pbkdf2($data, $salt, $iterations, $keyLength)
	{
		$blockCount = ceil($keyLength / $this->hashAlgorithmSize);
		$output = '';
		for( $i = 1; $i <= $blockCount; $i++ ) {
			$block = hash_hmac($this->hashAlgorithm, $salt . pack('N', $i), $data, true);
			$ib = $block;
			for( $loop = 1; $loop < $iterations; $loop++ ) {
				$block = hash_hmac($this->hashAlgorithm, $block, $data, true);
				$ib ^= $block;
			}
			$output .= $ib;
		}
		return substr($output, 0, $keyLength);
	}

	/**
	 * bcrypt a plain text password.
	 *
	 * Notes about work factor:
	 *
	 * While bcrypt will support work factors as low as 4, I'm opting to only
	 * support down to 8.  However, I would not recommend using 8 for anything
	 * except for throwaway data (bcrypt(getEntropy()) type situations).
	 *
	 * I would recommend using a work factor of at least 11 for moderately
	 * important data.  Bumping it up to 12 might give a better balance of
	 * strength and speed, depending on the hardware.
	 *
	 * For "high value" data, anything less than 14 is probably unacceptable.
	 *
	 * @param string $password The password to be hashed
	 * @param string $salt The salt to user for the password
	 * @param integer $workFactor The work factor
	 * @return string The secure password
	 */
	public function bcrypt($password, $salt = null, $workFactor = 11)
	{
		if( CRYPT_BLOWFISH !== 1 )
			throw new \RuntimeException('bcrypt is not supported on this system.');

		if( $workFactor < 8 )
			$workFactor = 8;
		if( $workFactor > 31 )
			$workFactor = 31;

		// Valid characters in the salt are '0-9', 'A-Z', 'a-z', '$', '.', and '/'.
		if( $salt !== null ) {
			if( is_string($salt) )
				$salt = str_replace('+', '', base64_encode($salt));
			if( !is_string($salt) || strlen($salt) < 22 )
				throw new \InvalidArgumentException('Salt must be a string of at least 22 characters in length.');
		} else {
			// We only need 22 bytes, but get more just to be sure.
			$salt = $this->getEntropy(32);
			$salt = substr(str_replace('+', '', base64_encode($salt)), 0, 22);
		}
		$salt = sprintf('$2a$%02d$%s', $workFactor, $salt);

		$output = crypt($password, $salt);
		if( strlen($output) < 13 ) {
			// Failure
		}
		return $output;
	}

	/**
	 * AES-256-CTR encryption.
	 *
	 * @param string $plainText The text to be encrypted.
	 * @param string $password The password to use to derive the encryption key.
	 * @return mixed FALSE on failure, string on success.
	 */
	public function encrypt($plainText, $password)
	{
		$module = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', 'ctr', '');
		if( $module === false ) {
			return false;
		}

		$salt = $this->getEntropy(32);
		$keyIV = $this->pbkdf2($password, $salt, 10000, mcrypt_enc_get_key_size($module) + mcrypt_enc_get_iv_size($module));
		$key = substr($keyIV, 0, mcrypt_enc_get_key_size($module));
		$IV = substr($keyIV, mcrypt_enc_get_key_size($module), mcrypt_enc_get_iv_size($module));

		$retVal = mcrypt_generic_init($module, $key, $IV);
		if( $retVal === false || $retVal < 0 ) {
			mcrypt_module_close($module);
			return false;
		}
//		$cipherText = mcrypt_generic($module, $this->oaep_pad($plainText, $salt));
		$cipherText = mcrypt_generic($module, $plainText);
		$cipherText = 'Salted__' . $salt . $cipherText . hash_hmac($this->hashAlgorithm, $cipherText, $key, true);

		mcrypt_generic_deinit($module);
		mcrypt_module_close($module);
		return $cipherText;
	}

	/**
	 * AES-256-CTR decryption.
	 *
	 * @param string $cipherText The text to be decrypted.
	 * @param string $password The password to use to derive the decryption key.
	 * @return mixed FALSE on failure, string on success.
	 */
	public function decrypt($cipherText, $password)
	{
		// 8 for 'Salted__', 32 for the size of the salt we're using.
		if( strlen($cipherText) <= 8 + 32 + $this->hashAlgorithmSize || substr($cipherText, 0, 8) !== 'Salted__' ) {
			return false;
		}

		$module = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', 'ctr', '');
		if( $module === false ) {
			return false;
		}

		$salt = substr($cipherText, 8, 32);
		$hmac = substr($cipherText, -$this->hashAlgorithmSize);
		$cipherText = substr($cipherText, 8 + 32, strlen($cipherText) - (8 + 32)  - $this->hashAlgorithmSize);

		$keyIV = $this->pbkdf2($password, $salt, 10000, mcrypt_enc_get_key_size($module) + mcrypt_enc_get_iv_size($module));
		$key = substr($keyIV, 0, mcrypt_enc_get_key_size($module));
		$IV = substr($keyIV, mcrypt_enc_get_key_size($module), mcrypt_enc_get_iv_size($module));
		if( hash_hmac($this->hashAlgorithm, $cipherText, $key, true) !== $hmac ) {
			return false;
		}

		$retVal = mcrypt_generic_init($module, $key, $IV);
		if( $retVal === false || $retVal < 0 ) {
			mcrypt_module_close($module);
			return false;
		}
		$plainText = mdecrypt_generic($module, $cipherText);
		mcrypt_generic_deinit($module);
		mcrypt_module_close($module);
/*
		$plainText = $this->oaep_unpad($plainText, $salt);
		if( $plainText === false ) {
			return false;
		}
*/
		return $plainText;
	}

	/**
	 * Mask Generation Function, as defined in section B.2.1:
	 * http://www.ietf.org/rfc/rfc3447.txt
	 */
	final protected function mgf($seed, $maskLength)
	{
		$output = '';
		for( $i = 0; $i < ceil($maskLength / $this->hashAlgorithmSize); $i++ ) {
			$c = pack('N', $i);
			if( strlen($c) < 4 ) {
				$c = str_repeat("\0", 4 - strlen($c)) . $c;
			}
			$output .= hash($this->hashAlgorithm, $seed . $c, true);
		}
		return substr($output, 0, $maskLength);
	}

	/**
	 * EME-OAEP encoding, as defined in section 7.1.1, step 2:
	 * http://www.ietf.org/rfc/rfc3447.txt
	 */
	final protected function oaep_pad($data, $label = '')
	{
		if( $this->privateKeySize === null ) {
			return false;
		}
		$keySize = ceil($this->privateKeySize / 8);

		$DB = hash($this->hashAlgorithm, $label, true) . str_repeat("\0", $keySize - strlen($data) - ($this->hashAlgorithmSize * 2) - 2) . "\1" . $data;
		$seed = $this->getEntropy($this->hashAlgorithmSize);
		$DB ^= $this->mgf($seed, $keySize - $this->hashAlgorithmSize - 1);
		$seed ^= $this->mgf($DB, $this->hashAlgorithmSize);
		return "\0" . $seed . $DB;
	}

	/**
	 * EME-OAEP decoding, as defined in section 7.1.2, step 3:
	 * http://www.ietf.org/rfc/rfc3447.txt
	 */
	final protected function oaep_unpad($data, $label = '')
	{
		if( $data[0] !== "\0" ) {
			return false;
		}

		if( $this->privateKeySize === null ) {
			return false;
		}
		$keySize = ceil($this->privateKeySize / 8);

		$DB = substr($data, $this->hashAlgorithmSize + 1, $keySize - $this->hashAlgorithmSize - 1);
		$seed = substr($data, 1, $this->hashAlgorithmSize) ^ $this->mgf($DB, $this->hashAlgorithmSize);
		$DB ^= $this->mgf($seed, $keySize - $this->hashAlgorithmSize - 1);

		if( substr($DB, 0, $this->hashAlgorithmSize) !== hash($this->hashAlgorithm, $label, true) ) {
			return false;
		}
		$DB = substr($DB, $this->hashAlgorithmSize);
		$PS = substr($DB, 0, strlen($DB) - strlen(ltrim($DB)));
		if( $DB[strlen($PS)] !== "\1" || strlen($PS) != $keySize - (strlen($DB) - strlen($PS) - 1) - ($this->hashAlgorithmSize * 2) - 2 ) {
			return false;
		}

		return substr($DB, strlen($PS) + 1);
	}
}
