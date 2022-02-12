import boto3
client = boto3.client('kms')


def main(event, context):
    """
    key_id : key_id used to encrypt/decrypt
    plaintext: plaintext for encryption
    :return: None
    """

    alias_name = event.get('key_id')
    plaintext = event.get('plaintext')

    # Encryption
    response = client.encrypt(
        KeyId=alias_name,
        Plaintext=plaintext.encode('utf-8')
    )
    ciphertext = response['CiphertextBlob']
    algo = response['EncryptionAlgorithm']
    print(f"Encrypted '{plaintext}' using {algo} with {alias_name}")

    # Decryption
    response = client.decrypt(
        CiphertextBlob=ciphertext
    )
    print(f"Decrypted ciphertext to get '{response['Plaintext'].decode('utf-8')}'")

    return None