import random
from Cryptodome.Util.number import getPrime


def generate_parameters(bit_length):
    """
    Генерация параметров криптосистемы: простое число p и образующую g
    """
    p = getPrime(bit_length)
    # Находим образующую для группы Fp*
    def is_generator(g, p):
        if pow(g, p - 1, p) != 1: # Порядок g делит p−1 по малой теореме Ферма?
            return False
        for factor in prime_factors(p - 1):
            if pow(g, (p - 1) // factor, p) == 1:
                return False # Порядок g меньше p-1, g - не образующая
        return True

    # Разложение на простые множители
    def prime_factors(n):
        factors = set()
        while n % 2 == 0:
            factors.add(2)
            n = n // 2
        i = 3
        while i * i <= n:
            while n % i == 0:
                factors.add(i)
                n = n // i
            i += 2
        if n > 2:
            factors.add(n)
        return factors

    # Ищем образующую
    for g in range(2, p):
        if is_generator(g, p):
            return {'prime': p, 'generator': g}

    raise ValueError("Не удалось найти образующую")


def generate_keypair(params):
    """
    Генерация пары ключей (открытый и закрытый)
    """
    p = params['prime']
    g = params['generator']

    x = random.randint(2, p - 2)  # закрытый ключ
    b = pow(g, x, p)  # открытый ключ

    return {'public_key': b, 'private_key': x}


def int_to_asn1_integer(num):
    """Преобразование целого числа в ASN.1 INTEGER"""

    bytes_data = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')

    # Удаляем ведущие нули
    if bytes_data[0] & 0x80:
        bytes_data = b'\x00' + bytes_data

    # Определяем длину
    length = len(bytes_data)
    if length < 0x80:
        length_bytes = bytes([length])
    else:
        length_bytes = bytes([0x80 | (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8,'big')

    return b'\x02' + length_bytes + bytes_data


def sequence_to_asn1(elements):
    """Преобразование последовательности в ASN.1 SEQUENCE"""
    content = b''.join(elements)
    length = len(content)

    if length < 0x80:
        length_bytes = bytes([length])
    else:
        length_bytes = bytes([0x80 | (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8,
                                                                                        'big')

    return b'\x30' + length_bytes + content


def decrypt_message(asn1_data, private_key, params):
    """Дешифрование ASN.1 структуры"""
    p = params['prime']
    x = private_key

    # Разбираем ASN.1 структуру шифртекста
    ptr = 0
    if asn1_data[ptr] != 0x30:
        raise ValueError("Invalid ASN.1 sequence")
    ptr += 1

    # Читаем длину последовательности
    length_byte = asn1_data[ptr]
    ptr += 1
    if length_byte & 0x80:
        length_len = length_byte & 0x7F
        ptr += length_len

    # Читаем a
    if asn1_data[ptr] != 0x02:
        raise ValueError("Expected INTEGER (a)")
    ptr += 1

    a_len_byte = asn1_data[ptr]
    ptr += 1
    if a_len_byte & 0x80:
        a_len_len = a_len_byte & 0x7F
        a_len = int.from_bytes(asn1_data[ptr:ptr + a_len_len], 'big')
        ptr += a_len_len
    else:
        a_len = a_len_byte

    a = int.from_bytes(asn1_data[ptr:ptr + a_len], 'big')
    ptr += a_len

    # Читаем c
    if asn1_data[ptr] != 0x02:
        raise ValueError("Expected INTEGER (c)")
    ptr += 1

    c_len_byte = asn1_data[ptr]
    ptr += 1
    if c_len_byte & 0x80:
        c_len_len = c_len_byte & 0x7F
        c_len = int.from_bytes(asn1_data[ptr:ptr + c_len_len], 'big')
        ptr += c_len_len
    else:
        c_len = c_len_byte

    c = int.from_bytes(asn1_data[ptr:ptr + c_len], 'big')

    # Дешифруем сообщение
    s = pow(a, x, p)
    m = (c - s) % p

    return m


def encrypt_file(input_file, output_file, public_key, params):
    """
    Шифрование файла с сохранением в ASN.1 формате
    """
    p = params['prime']
    g = params['generator']
    b = public_key

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    m = int.from_bytes(plaintext, byteorder='big')
    if m >= p:
        raise ValueError("Сообщение слишком большое для выбранного простого числа")

    # Шифруем сообщение
    y = random.randint(2, p - 2)
    a = pow(g, y, p)
    s = pow(b, y, p)
    c = (m + s) % p

    a_asn1 = int_to_asn1_integer(a)
    c_asn1 = int_to_asn1_integer(c)
    ciphertext_asn1 = sequence_to_asn1([a_asn1, c_asn1])

    prime_asn1 = int_to_asn1_integer(p)
    generator_asn1 = int_to_asn1_integer(g)
    params_asn1 = sequence_to_asn1([prime_asn1, generator_asn1])

    public_key_asn1 = int_to_asn1_integer(b)

    # Полная структура файла
    file_content = sequence_to_asn1([
        int_to_asn1_integer(0x80010202),
        public_key_asn1,
        params_asn1,
        ciphertext_asn1
    ])

    with open(output_file, 'wb') as f:
        f.write(file_content)


def decrypt_file(input_file, output_file, private_key, params):
    """
    Дешифрование файла в ASN.1 формате (финальная версия)
    """
    with open(input_file, 'rb') as f:
        data = f.read()

    ptr = 0
    if data[ptr] != 0x30:
        raise ValueError("Invalid ASN.1 file format")
    ptr += 1

    # Читаем длину файла
    length_byte = data[ptr]
    ptr += 1
    if length_byte & 0x80:
        length_len = length_byte & 0x7F
        ptr += length_len

    # Пропускаем идентификатор алгоритма
    if data[ptr] != 0x02:
        raise ValueError("Expected INTEGER (algorithm id)")
    ptr += 1
    alg_len_byte = data[ptr]
    ptr += 1
    if alg_len_byte & 0x80:
        alg_len_len = alg_len_byte & 0x7F
        alg_len = int.from_bytes(data[ptr:ptr + alg_len_len], 'big')
        ptr += alg_len_len
    else:
        alg_len = alg_len_byte
    ptr += alg_len

    # Читаем открытый ключ
    if data[ptr] != 0x02:
        raise ValueError("Expected INTEGER (public key)")
    ptr += 1
    pub_len_byte = data[ptr]
    ptr += 1
    if pub_len_byte & 0x80:
        pub_len_len = pub_len_byte & 0x7F
        pub_len = int.from_bytes(data[ptr:ptr + pub_len_len], 'big')
        ptr += pub_len_len
    else:
        pub_len = pub_len_byte
    public_key = int.from_bytes(data[ptr:ptr + pub_len], 'big')
    ptr += pub_len

    # Пропускаем параметры
    if data[ptr] != 0x30:
        raise ValueError("Expected SEQUENCE (parameters)")
    ptr += 1
    params_len_byte = data[ptr]
    ptr += 1
    if params_len_byte & 0x80:
        params_len_len = params_len_byte & 0x7F
        params_len = int.from_bytes(data[ptr:ptr + params_len_len], 'big')
        ptr += params_len_len
    else:
        params_len = params_len_byte
    ptr += params_len

    # Читаем шифртекст
    if data[ptr] != 0x30:
        raise ValueError("Expected SEQUENCE (ciphertext)")

    cipher_data = data[ptr:]
    m = decrypt_message(cipher_data, private_key, params)

    plaintext = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

    with open(output_file, 'wb') as f:
        f.write(plaintext)


def save_asn1_params(params, filename):
    """Сохранение параметров в ASN.1 формате"""
    prime_asn1 = int_to_asn1_integer(params['prime'])
    generator_asn1 = int_to_asn1_integer(params['generator'])
    params_asn1 = sequence_to_asn1([prime_asn1, generator_asn1])

    with open(filename, 'wb') as f:
        f.write(params_asn1)


def load_asn1_params(filename):
    """Загрузка параметров из ASN.1 формата"""
    with open(filename, 'rb') as f:
        data = f.read()

    ptr = 0
    if data[ptr] != 0x30:
        raise ValueError("Invalid ASN.1 parameters format")
    ptr += 1

    # Читаем длину
    length_byte = data[ptr]
    ptr += 1
    if length_byte & 0x80:
        length_len = length_byte & 0x7F
        length = int.from_bytes(data[ptr:ptr + length_len], 'big')
        ptr += length_len
    else:
        length = length_byte

    # Читаем простое число
    if data[ptr] != 0x02:
        raise ValueError("Expected INTEGER (prime)")
    ptr += 1

    prime_len_byte = data[ptr]
    ptr += 1
    if prime_len_byte & 0x80:
        prime_len_len = prime_len_byte & 0x7F
        prime_len = int.from_bytes(data[ptr:ptr + prime_len_len], 'big')
        ptr += prime_len_len
    else:
        prime_len = prime_len_byte

    prime = int.from_bytes(data[ptr:ptr + prime_len], 'big')
    ptr += prime_len

    # Читаем образующую
    if data[ptr] != 0x02:
        raise ValueError("Expected INTEGER (generator)")
    ptr += 1

    gen_len_byte = data[ptr]
    ptr += 1
    if gen_len_byte & 0x80:
        gen_len_len = gen_len_byte & 0x7F
        gen_len = int.from_bytes(data[ptr:ptr + gen_len_len], 'big')
        ptr += gen_len_len
    else:
        gen_len = gen_len_byte

    generator = int.from_bytes(data[ptr:ptr + gen_len], 'big')

    return {'prime': prime, 'generator': generator}


def save_asn1_key(key, filename, is_public=True):
    """Сохранение ключа в ASN.1 формате"""
    key_asn1 = int_to_asn1_integer(key)
    with open(filename, 'wb') as f:
        f.write(key_asn1)


def load_asn1_key(filename, is_public=True):
    """Загрузка ключа из ASN.1 формата"""
    with open(filename, 'rb') as f:
        data = f.read()

    ptr = 0
    if data[ptr] != 0x02:
        raise ValueError("Expected INTEGER (key)")
    ptr += 1

    key_len_byte = data[ptr]
    ptr += 1
    if key_len_byte & 0x80:
        key_len_len = key_len_byte & 0x7F
        key_len = int.from_bytes(data[ptr:ptr + key_len_len], 'big')
        ptr += key_len_len
    else:
        key_len = key_len_byte

    key = int.from_bytes(data[ptr:ptr + key_len], 'big')
    return key


def interactive_menu():
    """Интерактивное меню для работы с программой"""
    print("Программа реализации протокола Эль-Гамаля")
    print("Выберите действие:")
    print("1. Генерация параметров криптосистемы")
    print("2. Генерация пары ключей")
    print("3. Шифрование файла")
    print("4. Дешифрование файла")
    print("0. Выход")

    while True:
        choice = input("> ")

        if choice == "1":
            bit_length = int(input("Введите длину простого числа в битах: "))
            params = generate_parameters(bit_length)
            filename = input("Введите имя файла для сохранения параметров: ")
            save_asn1_params(params, filename)
            print(f"Параметры сохранены в файл {filename}")
            print(f"Простое число p: {params['prime']}")
            print(f"Образующая g: {params['generator']}")

        elif choice == "2":
            params_file = input("Введите имя файла с параметрами: ")
            params = load_asn1_params(params_file)
            keypair = generate_keypair(params)

            pub_filename = input("Введите имя файла для сохранения открытого ключа: ")
            save_asn1_key(keypair['public_key'], pub_filename, is_public=True)

            priv_filename = input("Введите имя файла для сохранения закрытого ключа: ")
            save_asn1_key(keypair['private_key'], priv_filename, is_public=False)

            print(f"Открытый ключ сохранен в {pub_filename}")
            print(f"Закрытый ключ сохранен в {priv_filename}")

        elif choice == "3":
            input_file = input("Введите имя файла для шифрования: ")
            output_file = input("Введите имя файла для сохранения шифртекста: ")
            pub_key_file = input("Введите имя файла с открытым ключом: ")
            params_file = input("Введите имя файла с параметрами: ")

            public_key = load_asn1_key(pub_key_file, is_public=True)
            params = load_asn1_params(params_file)

            encrypt_file(input_file, output_file, public_key, params)
            print(f"Файл {input_file} успешно зашифрован в {output_file}")

        elif choice == "4":
            input_file = input("Введите имя файла для дешифрования: ")
            output_file = input("Введите имя файла для сохранения расшифрованного текста: ")
            priv_key_file = input("Введите имя файла с закрытым ключом: ")
            params_file = input("Введите имя файла с параметрами: ")

            private_key = load_asn1_key(priv_key_file, is_public=False)
            params = load_asn1_params(params_file)

            decrypt_file(input_file, output_file, private_key, params)
            print(f"Файл {input_file} успешно расшифрован в {output_file}")

        elif choice == "0":
            print("Выход из программы")
            break

        else:
            print("Неверный выбор. Попробуйте снова.")


if __name__ == '__main__':
    interactive_menu()