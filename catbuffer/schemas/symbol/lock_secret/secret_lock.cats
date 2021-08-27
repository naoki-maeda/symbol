import "lock_secret/lock_secret_types.cats"
import "transaction.cats"

# binary layout for a secret lock transaction
struct SecretLockTransactionBody
	# locked mosaic recipient address
	recipientAddress = UnresolvedAddress

	# secret
	secret = Hash256

	# locked mosaic
	mosaic = UnresolvedMosaic

	# number of blocks for which a lock should be valid
	duration = BlockDuration

	# hash algorithm
	hashAlgorithm = LockHashAlgorithm

# binary layout for a non-embedded secret lock transaction
struct SecretLockTransaction
	const uint8 transaction_version = 1
	const TransactionType transaction_type = secret_lock

	inline Transaction
	inline SecretLockTransactionBody

# binary layout for an embedded secret lock transaction
struct EmbeddedSecretLockTransaction
	const uint8 transaction_version = 1
	const TransactionType transaction_type = secret_lock

	inline EmbeddedTransaction
	inline SecretLockTransactionBody