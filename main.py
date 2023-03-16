from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome import Random
import xml.etree.ElementTree as ET
import os

# Функция для генерации случайных открытого и закрытого ключей
def generate_keys():
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    return key

# Функция для экспорта ключей в файлы формата XML
def export_key(key, filename):
    directory = os.path.dirname(filename)
    if directory != '' and not os.path.exists(directory):
        os.makedirs(directory)
    with open(filename, 'wb') as f:
        f.write(key.exportKey(format='PEM'))

# Функция для импорта ключей из файлов формата XML
def import_key(filename):
    with open(filename, 'rb') as f:
        key = RSA.importKey(f.read())
    return key

# Функция для шифрования данных с помощью открытого ключа
def encrypt_data(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(data)
    return ciphertext

# Функция для дешифрования данных с помощью закрытого ключа
def decrypt_data(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    data = cipher.decrypt(ciphertext)
    return data


if __name__ == '__main__':
    # Генерация ключей
    key = generate_keys()

    # Экспорт ключей в файлы формата XML
    export_key(key.publickey(), 'public_key.xml')
    export_key(key, 'private_key.xml')

    # Импорт ключей из файлов формата XML
    public_key = import_key('public_key.xml')
    private_key = import_key('private_key.xml')

    # Шифрование и дешифрование данных
    message = b'This is a test message'
    ciphertext = encrypt_data(message, public_key)
    plaintext = decrypt_data(ciphertext, private_key)
    print('Original message:', message)
    print('Decrypted message:', plaintext)
