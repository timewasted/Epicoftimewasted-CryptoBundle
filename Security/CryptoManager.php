<?php

namespace Epicoftimewasted\CryptoBundle\Security;

class CryptoManager implements CryptoManagerInterface
{
	/**
	 * @var string $hashAlgorithm The current hashing algorithm
	 */
	private $hashAlgorithm;

	/**
	 * @var string $prevHashAlgorithm The previously set hashing algorithm
	 */
	private $prevHashAlgorithm;

	/**
	 * @var integer $hashAlgorithmSize The output size in bytes of the current hashing algorithm
	 */
	private $hashAlgorithmSize;

	/**
	 * @var string $publicKey The stored public encryption key
	 */
	private $publicKey;

	/**
	 * @var integer $publicKeySize The size in bits of the stored public key
	 */
	private $publicKeySize;

	/**
	 * @var string $privateKey The stored private encryption key
	 */
	private $privateKey;

	/**
	 * @var integer $privateKeySize The size in bits of the stored private key
	 */
	private $privateKeySize;

	/**
	 * Constructor.
	 *
	 * @param string $hashAlgorithm The default hashing algorithm
	 */
	public function __construct($hashAlgorithm = 'sha512')
	{
		if( !in_array($hashAlgorithm, hash_algos()) )
			throw new \InvalidArgumentException(sprintf('Invalid hash algorithm "%s" specified.  Must be one one "%s".', $hashAlgorithm, implode(', ', hash_algos())));

		$this->hashAlgorithm = $hashAlgorithm;
		$this->hashAlgorithmSize = strlen(hash($this->hashAlgorithm, null, true));
	}

	/**
	 * {@inheritDoc}
	 */
	public function getHashAlgorithm()
	{
		return $this->hashAlgorithm;
	}

	/**
	 * {@inheritDoc}
	 */
	public function getHashAlgorithmSize()
	{
		return $this->hashAlgorithmSize;
	}

	/**
	 * {@inheritDoc}
	 */
	public function changeHashAlgorithm($newAlgorithm)
	{
		/**
		 * First, verify that the new algorithm is supported by hash().
		 */
		if( !in_array($newAlgorithm, hash_algos()) )
			throw new \InvalidArgumentException(sprintf('Invalid hash algorithm "%s" specified.  Must be one one "%s".', $newAlgorithm, implode(', ', hash_algos())));

		/**
		 * Save the current algorithm, then set the new algorithm
		 */
		$this->prevHashAlgorithm = $this->hashAlgorithm;
		$this->hashAlgorithm = $newAlgorithm;
		$this->hashAlgorithmSize = strlen(hash($this->hashAlgorithm, null, true));
	}

	/**
	 * {@inheritDoc}
	 */
	public function restoreHashAlgorithm()
	{
		if( $this->prevHashAlgorithm !== null ) {
			$curHashAlgorithm = $this->hashAlgorithm;
			$this->hashAlgorithm = $this->prevHashAlgorithm;
			$this->hashAlgorithmSize = strlen(hash($this->hashAlgorithm, null, true));
			$this->prevHashAlgorithm = $curHashAlgorithm;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public function getEntropy($amount)
	{
		/**
		 * Generating zero or less bytes of entropy doesn't make sense.
		 */
		if( !is_numeric($amount) || $amount <= 0 )
			throw new \InvalidArgumentException(sprintf('Unable to generate %d bytes of entropy.  Amount must be a number greater than zero.', $amount));

		/**
		 * Try to use openssl_random_pseudo_bytes() first.
		 */
		if( function_exists('openssl_random_pseudo_bytes') ) {
			$entropy = openssl_random_pseudo_bytes($amount, $isCryptoStrong);
			if( $entropy !== false && $isCryptoStrong )
				return $entropy;
		}

		/**
		 * Since openssl_random_pseudo_bytes isn't available, try /dev/urandom.
		 */
		if( is_readable('/dev/urandom') ) {
			if( ($urandom = fopen('/dev/urandom', 'r', false)) !== false ) {
				$entropy = '';
				do {
					$entropy .= fread($urandom, $amount - strlen($entropy));
				} while( strlen($entropy) < $amount );
				fclose($urandom);

				return substr($entropy, 0, $amount);
			}
		}

		/**
		 * All else has failed, so fall back to mt_rand().
		 */
		$entropy = '';
		do {
			$entropy .= pack('N', mt_rand(0, 0xffffffff));
		} while( strlen($entropy) < $amount );
		return substr($entropy, 0, $amount);
	}

	/**
	 * {@inheritDoc}
	 */
	final public function pbkdf2($password, $salt, $iterations, $keySize)
	{
		$blockCount = ceil($keySize / $this->hashAlgorithmSize);
		$output = '';
		for( $i = 1; $i <= $blockCount; $i++ ) {
			$block = hash_hmac($this->hashAlgorithm, $salt . pack('N', $i), $password, true);
			$ib = $block;
			for( $loop = 1; $loop < $iterations; $loop++ ) {
				$block = hash_hmac($this->hashAlgorithm, $block, $password, true);
				$ib ^= $block;
			}
			$output .= $ib;
		}
		return substr($output, 0, $keySize);
	}

	/**
	 * {@inheritDoc}
	 */
	public function bcrypt($message, $salt = null, $workFactor = 11)
	{
		/**
		 * Verify that bcrypt is available for usage.
		 */
		if( CRYPT_BLOWFISH !== 1 )
			throw new \RuntimeException('bcrypt is not supported on this system.');

		/**
		 * Range check the work factor.
		 */
		if( $workFactor < 8 )
			$workFactor = 8;
		if( $workFactor > 31 )
			$workFactor = 31;

		/**
		 * Note: valid characters for a salt are '0-9', 'A-Za-z', '$', '.', and '/'.
		 */
		if( $salt !== null ) {
			/**
			 * We only do basic checks on user-supplied salts, since crypt()
			 * is much better equipped to do comprehensive checks.
			 *
			 * FIXME: I can't help but think the salt should be run through
			 *   pbkdf2() or something to ensure it's a good salt.
			 */
			$salt = str_replace('+', '', base64_encode($salt));
			if( strlen($salt) < 22 )
				throw new \InvalidArgumentException('Salt must be a string of at least 22 characters in length.');
		} else {
			/**
			 * Since we're str_replacing() away bad characters, we should get
			 * more entropy than we need to ensure that we have enough.
			 */
			$salt = $this->getEntropy(32);
			$salt = substr(str_replace('+', '', base64_encode($salt)), 0, 22);
		}
		$salt = sprintf('$2a$%02d$%s', $workFactor, $salt);

		/**
		 * Hash the message and make sure that it's valid.
		 */
		$output = crypt($message, $salt);
		if( strlen($output) < 13 )
			throw new \RuntimeException('crypt() failed.');

		return $output;
	}

	/**
	 * {@inheritDoc}
	 */
	public function generateKeyPair($keySize = 2048, $passphrase = null)
	{
		if( !is_numeric($keySize) || $keySize <= 0 )
			throw new \InvalidArgumentException('Unable to generate a key of the specified size.  Must be greater than zero bits in size.');

		$config = array(
			'digest_alg'		=> $this->hashAlgorithm,
			'private_key_bits'	=> $keySize,
			'private_key_type'	=> OPENSSL_KEYTYPE_RSA,
		);
		if( ($keyResource = openssl_pkey_new($config)) === false )
			throw new \RuntimeException('Unable to generate new key pair.');

		/**
		 * Output of openssl_pkey_get_details()['rsa'] is defined here: http://www.openssl.org/docs/crypto/rsa.html
		 * Output of openssl_pkey_get_details()['dsa'] is defined here: http://www.openssl.org/docs/crypto/dsa.html
		 * Output of openssl_pkey_get_details()['dh'] is defined here: http://www.openssl.org/docs/crypto/dh.html
		 */
		$keyDetails = openssl_pkey_get_details($keyResource);
		$this->publicKey = $keyDetails['key'];
		$this->publicKeySize = $keyDetails['bits'];

		if( empty($passphrase) ) {
			openssl_pkey_export($keyResource, $this->privateKey);
			$this->privateKey = openssl_pkey_get_private($this->privateKey);
		} else {
			openssl_pkey_export($keyResource, $this->privateKey, $passphrase);
			$this->privateKey = openssl_pkey_get_private($this->privateKey, $passphrase);
		}
		$keyDetails = openssl_pkey_get_details($this->privateKey);
		$this->privateKeySize = $keyDetails['bits'];
	}

	/**
	 * {@inheritDoc}
	 */
	public function importPublicKey($key)
	{
		if( ($keyResource = openssl_pkey_get_public($key)) === false )
			throw new \RuntimeException('Unable to import the supplied public key.');

		$keyDetails = openssl_pkey_get_details($keyResource);
		$this->publicKey = $keyDetails['key'];
		$this->publicKeySize = $keyDetails['bits'];
	}

	/**
	 * {@inheritDoc}
	 */
	public function exportPublicKey()
	{
		return $this->publicKey === null ? null : $this->publicKey;
	}

	/**
	 * {@inheritDoc}
	 */
	public function importPrivateKey($key, $passphrase = null)
	{
		if( empty($passphrase) )
			$keyResource = openssl_pkey_get_private($key);
		else
			$keyResource = openssl_pkey_get_private($key, $passphrase);
		if( $keyResource === false )
			throw new \RuntimeException('Unable to import the supplied public key.');

		$keyDetails = openssl_pkey_get_details($keyResource);
		$this->privateKey = $keyResource;
		$this->privateKeySize = $keyDetails['bits'];
	}

	/**
	 * {@inheritDoc}
	 */
	public function exportPrivateKey($passphrase = null)
	{
		if( $this->privateKey === null )
			return null;

		if( empty($passphrase) )
			openssl_pkey_export($this->privateKey, $export);
		else
			openssl_pkey_export($this->privateKey, $export, $passphrase);
		return $export;
	}

	/**
	 * {@inheritDoc}
	 */
	public function encryptPublic($message)
	{
		if( $this->publicKey === null )
			throw new \RuntimeException('Unable to encrypt message with public key: no public key found.');

		if( !is_string($message) || empty($message) )
			throw new \InvalidArgumentException('Unable to encrypt message with public key: message must be a non-empty string.');

		$maxMessageLength = (int)ceil($this->publicKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;
		if( strlen($message) > $maxMessageLength )
			throw new \RuntimeException(sprintf('Unable to encrypt message with public key: message has a length of %d but the maximum message length is %d.', strlen($message), $maxMessageLength));

		if( openssl_public_encrypt($message, $encrypted, $this->publicKey, OPENSSL_PKCS1_OAEP_PADDING) === false )
			throw new \RuntimeException('Unable to encrypt message with public key: encryption failed.');

		return $encrypted;
	}

	/**
	 * {@inheritDoc}
	 */
	public function encryptPrivate($message)
	{
		if( $this->privateKey === null )
			throw new \RuntimeException('Unable to encrypt message with private key: no private key found.');

		if( !is_string($message) || empty($message) )
			throw new \InvalidArgumentException('Unable to encrypt message with private key: message must be a non-empty string.');

		$maxMessageLength = (int)ceil($this->privateKeySize / 8) - ($this->hashAlgorithmSize * 2) - 2;
		if( strlen($message) > $maxMessageLength )
			throw new \RuntimeException(sprintf('Unable to encrypt message with private key: message has a length of %d but the maximum message length is %d.', strlen($message), $maxMessageLength));

		if( openssl_private_encrypt($this->oaep_pad($message), $encrypted, $this->privateKey, OPENSSL_NO_PADDING) === false )
			throw new \RuntimeException('Unable to encrypt message with private key: encryption failed.');

		return $encrypted;
	}

	/**
	 * {@inheritDoc}
	 */
	public function decryptPublic($message)
	{
		if( $this->publicKey === null )
			throw new \RuntimeException('Unable to decrypt message with public key: no public key found.');

		if( !is_string($message) || empty($message) )
			throw new \InvalidArgumentException('Unable to decrypt message with public key: message must be a non-empty string.');

		if( openssl_public_decrypt($message, $decrypted, $this->publicKey, OPENSSL_NO_PADDING) === false )
			throw new \RuntimeException('Unable to decrypt message with public key: decryption failed.');

		return $this->oaep_unpad($decrypted);
	}

	/**
	 * {@inheritDoc}
	 */
	public function decryptPrivate($message)
	{
		if( $this->privateKey === null )
			throw new \RuntimeException('Unable to decrypt message with private key: no private key found.');

		if( !is_string($message) || empty($message) )
			throw new \InvalidArgumentException('Unable to decrypt message with private key: message must be a non-empty string.');

		if( openssl_private_decrypt($message, $decrypted, $this->privateKey, OPENSSL_PKCS1_OAEP_PADDING) === false )
			throw new \RuntimeException('Unable to decrypt message with private key: decryption failed.');

		return $decrypted;
	}

	/**
	 * {@inheritDoc}
	 */
	public function encrypt($message, $passphrase, $oaepPadding = false)
	{
		/**
		 * Open the desired module.
		 */
		if( ($module = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', 'ctr', '')) === false )
			throw new \RuntimeException('Unable to open the Rijndael 256 CTR mcrypt module.');

		/**
		 * Generate the salt, key, and IV.
		 */
		$salt = $this->getEntropy(32);
		$keyIV = $this->pbkdf2($passphrase, $salt, 10000, mcrypt_enc_get_key_size($module) + mcrypt_enc_get_iv_size($module));
		$key = substr($keyIV, 0, mcrypt_enc_get_key_size($module));
		$IV = substr($keyIV, mcrypt_enc_get_key_size($module), mcrypt_enc_get_iv_size($module));

		/**
		 * Initialize the module with the generated key and IV.
		 */
		$initValue = mcrypt_generic_init($module, $key, $IV);
		if( $initValue === false || $initValue < 0 ) {
			mcrypt_module_close($module);
			throw new \RuntimeException('Unable to initialize the mcrypt module.');
		}

		/**
		 * Encrypt the message and add the salt and HMAC.
		 */
		$encrypted = mcrypt_generic($module, $oaepPadding === true ? $this->oaep_pad($message, $salt) : $message);
		$encrypted = 'Salted__' . $salt . $encrypted . hash_hmac($this->hashAlgorithm, $encrypted, $key, true);

		/**
		 * Clean up mcrypt then return.
		 */
		mcrypt_generic_deinit($module);
		mcrypt_module_close($module);
		return $encrypted;
	}

	/**
	 * {@inheritDoc}
	 */
	public function decrypt($message, $passphrase, $oaepPadding = false)
	{
		/**
		 * Check that the message appears to have a valid format.  The length
		 * must be 8 ("Salted__") + 32 (length of the salt) + size of the
		 * output from our hashing algorithm.  The message must also start with
		 * the string "Salted__".
		 */
		if( strlen($message) <= 8 + 32 + $this->hashAlgorithmSize || substr($message, 0, 8) !== 'Salted__' )
			throw new \RuntimeException('Unable to decrypt message: invalid format.');

		/**
		 * Open the desired module.
		 */
		if( ($module = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', 'ctr', '')) === false )
			throw new \RuntimeException('Unable to open the Rijndael 256 CTR mcrypt module.');

		/**
		 * Extract the salt and HMAC from the message.
		 */
		$salt = substr($message, 8, 32);
		$hmac = substr($message, -$this->hashAlgorithmSize);
		$message = substr($message, 8 + 32, strlen($message) - (8 + 32) - $this->hashAlgorithmSize);

		/**
		 * Generate the key and IV, and verify that the HMAC is valid.
		 */
		$keyIV = $this->pbkdf2($passphrase, $salt, 10000, mcrypt_enc_get_key_size($module) + mcrypt_enc_get_iv_size($module));
		$key = substr($keyIV, 0, mcrypt_enc_get_key_size($module));
		$IV = substr($keyIV, mcrypt_enc_get_key_size($module), mcrypt_enc_get_iv_size($module));
		if( hash_hmac($this->hashAlgorithm, $message, $key, true) !== $hmac )
			throw new \RuntimeException('Possible corruption/tampering: HMAC does not match the message.');

		/**
		 * Initialize the module with the generated key and IV.
		 */
		$initValue = mcrypt_generic_init($module, $key, $IV);
		if( $initValue === false || $initValue < 0 ) {
			mcrypt_module_close($module);
			throw new \RuntimeException('Unable to initialize the mcrypt module.');
		}

		/**
		 * Decrypt the message and clean up mcrypt.
		 */
		$decrypted = mdecrypt_generic($module, $message);
		mcrypt_generic_deinit($module);
		mcrypt_module_close($module);
		if( $oaepPadding === true ) {
			if( ($decrypted = $this->oaep_unpad($decrypted, $salt)) === false )
				throw new \RuntimeException('Unable to unpad decrypted message.');
		}

		return $decrypted;
	}

	/**
	 * Mask Generation Function.
	 * See section B.2.1 of http://www.ietf.org/rfc/rfc3447.txt
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
	 * EME-OAEP encoding.
	 * See section 7.1.1, step 2 of http://www.ietf.org/rfc/rfc3447.txt
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
	 * EME-OAEP decoding.
	 * See section 7.1.2, step 3 of http://www.ietf.org/rfc/rfc3447.txt
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
