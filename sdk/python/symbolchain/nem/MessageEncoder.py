import cryptography
import secrets
from symbolchain.Cipher import AesCbcCipher, AesGcmCipher

from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.nc import Message, MessageType
from symbolchain.nem.SharedKey import SharedKey
from symbolchain.nem.KeyPair import KeyPair

class MessageEncoder:
	"""Encrypts and encodes messages between two parties."""

	def __init__(self, key_pair: KeyPair):
		"""Creates message encoder around key pair."""
		self.key_pair = key_pair

	def _decode_aes_gcm(self, recipient_public_key, encoded_message):
		GCM_IV_SIZE = 12

		tag = encoded_message[:AesGcmCipher.TAG_SIZE]
		initialization_vector = encoded_message[AesGcmCipher.TAG_SIZE:AesGcmCipher.TAG_SIZE + GCM_IV_SIZE]
		encoded_message_data = encoded_message[AesGcmCipher.TAG_SIZE + GCM_IV_SIZE:]

		shared_key = SharedKey.derive_shared_key(self.key_pair, recipient_public_key)
		cipher = AesGcmCipher(shared_key)
		return cipher.decrypt(encoded_message_data + tag, initialization_vector)

	def _decode_aes_cbc(self, recipient_public_key, encoded_message):
		CBC_IV_SIZE = 16

		salt = encoded_message[:32]
		initialization_vector = encoded_message[32:32 + CBC_IV_SIZE]
		encoded_message_data = encoded_message[32 + CBC_IV_SIZE:]
		shared_key = SharedKey.derive_shared_key_deprecated(self.key_pair, recipient_public_key, salt)
		cipher = AesCbcCipher(shared_key)
		return cipher.decrypt(encoded_message_data, initialization_vector)

	def try_decode(self, recipient_public_key, encoded_message: Message):
		"""Tries to decode encoded message, returns tuple:
		* True, message - if message has been decoded and decrypted
		* False, encoded_message - otherwise
		"""

		if MessageType.ENCRYPTED != encoded_message.message_type:
			raise RuntimeError('invalid message format')

		try:
			message = self._decode_aes_gcm(recipient_public_key, encoded_message.message)
			return True, message
		except cryptography.exceptions.InvalidTag:
			pass

		try:
			message = self._decode_aes_cbc(recipient_public_key, encoded_message.message)
			return True, message
		except ValueError as e:
			if 'Invalid padding bytes' not in str(e):
				raise

		return False, encoded_message

	def encode_deprecated(self, recipient_public_key: PublicKey, message: bytes):
		"""Encode message to recipient using deprecated encryption and key derivation."""

		salt = secrets.token_bytes(32)
		shared_key = SharedKey.derive_shared_key_deprecated(self.key_pair, recipient_public_key, salt)
		cipher = AesCbcCipher(shared_key)

		initialization_vector = secrets.token_bytes(16)
		cipher_text = cipher.encrypt(message, initialization_vector)

		encoded_messsage = Message()
		encoded_messsage.message_type = MessageType.ENCRYPTED
		encoded_messsage.message = salt + initialization_vector + cipher_text
		return encoded_messsage

	def encode(self, recipient_public_key: PublicKey, message: bytes):
		"""Encode message to recipient using recommended format."""

		shared_key = SharedKey.derive_shared_key(self.key_pair, recipient_public_key)
		cipher = AesGcmCipher(shared_key)

		initialization_vector = secrets.token_bytes(12)
		cipher_text = cipher.encrypt(message, initialization_vector)

		tag_start_offset = len(cipher_text) - AesGcmCipher.TAG_SIZE
		tag = cipher_text[tag_start_offset:]

		return Message(MessageType.ENCRYPTED, tag + initialization_vector + cipher_text[:tag_start_offset])

