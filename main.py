from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome import Random
from Cryptodome.PublicKey import DSA
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256
import os
# import rsa

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

def var2file(text, filename):
    directory = os.path.dirname(filename)
    if directory != '' and not os.path.exists(directory):
        os.makedirs(directory)
    with open(filename, 'wb') as f:
        f.write(text)

def file2var(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

if __name__ == '__main__':
    # Генерация ключей
    key = generate_keys()

    # Экспорт ключей в файлы формата XML
    export_key(key.publickey(), 'public_key.pem')
    export_key(key, 'private_key.pem')

    # Импорт ключей из файлов формата XML
    public_key = import_key('public_key.pem')
    private_key = import_key('private_key.pem')
    # Шифрование и дешифрование данных
    message = b'This is a test message i can choose whatever i want to'
    ciphertext = encrypt_data(message, public_key)

    var2file(ciphertext, 'crypted_test_file.pem')

    loaded_text = file2var('crypted_test_file.pem')


    plaintext = decrypt_data(loaded_text, private_key)
    print('Original message:', message)
    print('Decrypted message:', plaintext)

    print('----------------------------')

    # Генерация ключей DSA
    key = DSA.generate(2048)

    # Создание объекта для вычисления хеша
    hash_object = SHA256.new(message)

    # Создание объекта для вычисления ЭЦП
    signer = DSS.new(key, 'fips-186-3')

    # Подпись данных
    signature = signer.sign(hash_object)

    # Сохранение подписи в файл
    directory = os.path.dirname('signature.pem')
    if directory != '' and not os.path.exists(directory):
        os.makedirs(directory)
    with open('signature.pem', 'wb') as f:
        f.write(signature)

    # Загрузка подписи из файла
    with open('signature.pem', 'rb') as f:
        signature = f.read()

    # Создание объекта для вычисления хеша
    hash_object = SHA256.new(message)

    # Создание объекта для проверки подписи
    verifier = DSS.new(key, 'fips-186-3')

    # Проверка подписи
    try:
        verifier.verify(hash_object, signature)
        print('Signature is valid.')
    except ValueError:
        print('Signature is not valid.')