from binascii import hexlify, unhexlify
import cryptography
import secrets
from symbolchain.Cipher import AesGcmCipher

from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.symbol.SharedKey import SharedKey
from symbolchain.symbol.KeyPair import KeyPair


DELEGATION_MARKER = unhexlify('FE2A8061577301E2')

class MessageEncoder:
	"""Encrypts and encodes messages between two parties."""

	IV_SIZE = 12

	def __init__(self, key_pair: KeyPair):
		"""Creates message encoder around key pair."""
		self.key_pair = key_pair

	def _decode_aes_gcm(self, recipient_public_key, encoded_message):
		tag = encoded_message[:AesGcmCipher.TAG_SIZE]
		initialization_vector = encoded_message[AesGcmCipher.TAG_SIZE:AesGcmCipher.TAG_SIZE + self.IV_SIZE]
		encoded_message_data = encoded_message[AesGcmCipher.TAG_SIZE + self.IV_SIZE:]

		shared_key = SharedKey.derive_shared_key(self.key_pair, recipient_public_key)
		cipher = AesGcmCipher(shared_key)
		return cipher.decrypt(encoded_message_data + tag, initialization_vector)

	def try_decode(self, recipient_public_key, encoded_message):
		if 1 == encoded_message[0]:
			try:
				message = self._decode_aes_gcm(recipient_public_key, encoded_message[1:])
				return True, message
			except cryptography.exceptions.InvalidTag:
				pass
		elif 0xFE == encoded_message[0] and DELEGATION_MARKER == encoded_message[:8]:
			try:
				ephemeral_public_key = PublicKey(encoded_message[8:8 + PublicKey.SIZE])
				message = self._decode_aes_gcm(ephemeral_public_key, encoded_message[8 + PublicKey.SIZE:])
				return True, message
			except cryptography.exceptions.InvalidTag:
				pass

		return False, encoded_message

	def encode_persistent_harvesting_delegation(self, node_public_key, remote_key_pair, vrf_root_key_pair):
		ephemeral_key_pair = KeyPair(PrivateKey.random())

		shared_key = SharedKey.derive_shared_key(ephemeral_key_pair, node_public_key)
		cipher = AesGcmCipher(shared_key)

		initialization_vector = secrets.token_bytes(12)
		cipher_text = cipher.encrypt(remote_key_pair.private_key.bytes + vrf_root_key_pair.private_key.bytes, initialization_vector)

		tag_start_offset = len(cipher_text) - AesGcmCipher.TAG_SIZE
		tag = cipher_text[tag_start_offset:]



	def encode(self, recipient_public_key: PublicKey, message: bytes):
		"""Encode message to recipient using recommended format."""

		shared_key = SharedKey.derive_shared_key(self.key_pair, recipient_public_key)
		cipher = AesGcmCipher(shared_key)

		initialization_vector = secrets.token_bytes(12)
		cipher_text = cipher.encrypt(message, initialization_vector)

		tag_start_offset = len(cipher_text) - AesGcmCipher.TAG_SIZE
		tag = cipher_text[tag_start_offset:]

		return b'\1' + tag + initialization_vector + cipher_text[:tag_start_offset]
