from flask import Flask, render_template, request
import copy

app = Flask(__name__)

# Polinomio irreducible propietario: x^8 + x^6 + x^4 + x^3 + x^2 + x + 1
# Representación correcta: 0x5F (95)
GF_MOD = 0x5F


def gf_mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= GF_MOD
        b >>= 1
    return res


def gf_inv(a):
    if a == 0:
        return 0
    for i in range(1, 256):
        if gf_mul(a, i) == 1:
            return i
    return 0


def generate_sbox():
    sbox = []
    for i in range(256):
        inv = gf_inv(i)
        # Transformación afín estándar de AES
        x = inv
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            inv ^= x
        sbox.append((inv ^ 0x63) & 0xFF)
    sbox = [b & 0xFF for b in sbox[:256]]
    return sbox


def generate_inv_sbox(sbox):
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv


SBOX = generate_sbox()
INV_SBOX = generate_inv_sbox(SBOX)


def bytes2matrix(text):
    print(text)
    if len(text) < 16:
        # Añadir padding PKCS7 si es necesario
        pad_len = 16 - len(text)
        text += bytes([pad_len] * pad_len)
    elif len(text) > 16:
        raise ValueError(f"{text} El bloque debe tener exactamente 16 bytes")
    return [list(text[i::4]) for i in range(4)]


def matrix2bytes(matrix):
    # return bytes([matrix[row][col] for col in range(4) for row in range(4)])
    bytes_data = bytes([matrix[row][col] for col in range(4) for row in range(4)])
    # Verificar y remover padding PKCS7
    pad_len = bytes_data[-1]
    if pad_len <= 16 and all(b == pad_len for b in bytes_data[-pad_len:]):
        return bytes_data[:-pad_len]
    return bytes_data

def sub_bytes(state):
    return [[SBOX[b & 0xFF] for b in row] for row in state]


def inv_sub_bytes(state):
    return [[INV_SBOX[b & 0xFF] for b in row] for row in state]


def shift_rows(state):
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][1], state[1][2], state[1][3], state[1][0]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][3], state[3][0], state[3][1], state[3][2]],
    ]


def inv_shift_rows(state):
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][3], state[1][0], state[1][1], state[1][2]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][1], state[3][2], state[3][3], state[3][0]],
    ]


def mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3)
        state[3][c] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2)
    return state


def inv_mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gf_mul(a[0], 14) ^ gf_mul(a[1], 11) ^ gf_mul(a[2], 13) ^ gf_mul(a[3], 9)
        state[1][c] = gf_mul(a[0], 9) ^ gf_mul(a[1], 14) ^ gf_mul(a[2], 11) ^ gf_mul(a[3], 13)
        state[2][c] = gf_mul(a[0], 13) ^ gf_mul(a[1], 9) ^ gf_mul(a[2], 14) ^ gf_mul(a[3], 11)
        state[3][c] = gf_mul(a[0], 11) ^ gf_mul(a[1], 13) ^ gf_mul(a[2], 9) ^ gf_mul(a[3], 14)
    return state


def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def expand_key(master_key):
    print(master_key)
    key_columns = bytes2matrix(master_key)
    columns = [list(col) for col in zip(*key_columns)]
    i = 4
    while len(columns) < 44:
        word = columns[-1][:]
        if len(columns) % 4 == 0:
            word = word[1:] + word[:1]
            word = [SBOX[b] for b in word]
            word[0] ^= RCON[len(columns) // 4]
        word = [a ^ b for a, b in zip(word, columns[-4])]
        columns.append(word)
        i += 1
    round_keys = []
    for i in range(11):
        block = columns[4 * i:4 * (i + 1)]
        round_keys.append([list(col) for col in zip(*block)])
    return round_keys


def pad(plaintext):
    pad_len = 16 - (len(plaintext) % 16)
    # Siempre añade padding (incluso si pad_len == 0, añade 16 bytes de 16)
    return plaintext + bytes([pad_len] * pad_len)


def unpad(plaintext):
    if not plaintext or len(plaintext) == 0:
        raise ValueError("Texto vacío, no se puede quitar el relleno")
    pad_len = plaintext[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Relleno inválido")
    if len(plaintext) < pad_len:
        raise ValueError("El tamaño del relleno es mayor que el texto")
    if plaintext[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Relleno inválido")
    return plaintext[:-pad_len]

def format_matrix(matrix):
    return "\n".join(["\t".join(f"{byte:02x}" for byte in row) for row in matrix])

def format_round_keys(round_keys):
    return "\n\n".join(
        f"Round {i}:\n{format_matrix(key)}"
        for i, key in enumerate(round_keys)
    )

def aes_encrypt_ecb(plaintext, key):
    round_keys = expand_key(key)
    ciphertext = b''

    # Aplicar padding al texto completo primero
    padded_plaintext = pad(plaintext)

    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i + 16]
        ciphertext += encrypt_block(block, round_keys)
    return ciphertext


def aes_decrypt_ecb(ciphertext, key):
    if len(ciphertext) % 16 != 0:
        raise ValueError("El texto cifrado debe ser múltiplo de 16 bytes")

    round_keys = expand_key(key)
    plaintext = b''

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext += decrypt_block(block, round_keys)

    # Remover padding al final
    return unpad(plaintext)


def encrypt_block(plaintext, round_keys):
    state = bytes2matrix(plaintext)
    state = add_round_key(state, round_keys[0])
    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return matrix2bytes(state)

def decrypt_block(ciphertext, round_keys):
    state = bytes2matrix(ciphertext)
    state = add_round_key(state, round_keys[10])
    for i in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[i])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return matrix2bytes(state)

def decrypt_block_verbose(ciphertext, round_keys):
    steps = []
    state = bytes2matrix(ciphertext)
    steps.append(("Estado inicial", copy.deepcopy(state)))

    # Ronda inicial
    state = add_round_key(state, round_keys[10])
    steps.append(("Añadir Clave de Ronda 10", copy.deepcopy(state), round_keys[10]))

    # 9 rondas principales
    for i in range(9, 0, -1):
        state = inv_shift_rows(state)
        steps.append((f"Desplazamiento Inverso Filas (Ronda {10 - i})", copy.deepcopy(state)))

        state = inv_sub_bytes(state)
        steps.append((f"Sustitución Inversa Bytes (Ronda {10 - i})", copy.deepcopy(state)))

        state = add_round_key(state, round_keys[i])
        steps.append((f"Añadir Clave (Ronda {i})", copy.deepcopy(state), round_keys[i]))

        state = inv_mix_columns(state)
        steps.append((f"Mezcla Inversa Columnas (Ronda {10 - i})", copy.deepcopy(state)))

    # Ronda final
    state = inv_shift_rows(state)
    steps.append(("Desplazamiento Inverso Filas (Final)", copy.deepcopy(state)))

    state = inv_sub_bytes(state)
    steps.append(("Sustitución Inversa Bytes (Final)", copy.deepcopy(state)))

    state = add_round_key(state, round_keys[0])
    steps.append(("Añadir Clave Inicial", copy.deepcopy(state), round_keys[0]))

    return matrix2bytes(state), steps

def encrypt_block_verbose(plaintext, round_keys):
    steps = []
    # pone el padding
    padded_text = pad(plaintext) if len(plaintext) < 16 else plaintext
    state = bytes2matrix(padded_text)

    steps.append({
        'name': 'Estado inicial (con padding si es necesario)',
        'state': copy.deepcopy(state),
        'round_key': None,
        'input': plaintext.hex()
    })

    # Ronda inicial
    state = add_round_key(state, round_keys[0])
    steps.append({
        'name': 'Añadir Clave de Ronda (Ronda 0)',
        'state': copy.deepcopy(state),
        'round_key': copy.deepcopy(round_keys[0])
    })

    # 9 rondas principales
    for i in range(1, 10):
        state = sub_bytes(state)
        steps.append({
            'name': f'Sustitución de Bytes (Ronda {i})',
            'state': copy.deepcopy(state),
            'round_key': None
        })

        state = shift_rows(state)
        steps.append({
            'name': f'Desplazamiento de Filas (Ronda {i})',
            'state': copy.deepcopy(state),
            'round_key': None
        })

        state = mix_columns(state)
        steps.append({
            'name': f'Mezcla de Columnas (Ronda {i})',
            'state': copy.deepcopy(state),
            'round_key': None
        })

        state = add_round_key(state, round_keys[i])
        steps.append({
            'name': f'Añadir Clave de Ronda (Ronda {i})',
            'state': copy.deepcopy(state),
            'round_key': copy.deepcopy(round_keys[i])
        })

    # Ronda final
    state = sub_bytes(state)
    steps.append({
        'name': 'Sustitución de Bytes (Ronda 10)',
        'state': copy.deepcopy(state),
        'round_key': None
    })

    state = shift_rows(state)
    steps.append({
        'name': 'Desplazamiento de Filas (Ronda 10)',
        'state': copy.deepcopy(state),
        'round_key': None
    })

    state = add_round_key(state, round_keys[10])
    steps.append({
        'name': 'Añadir Clave de Ronda (Ronda 10)',
        'state': copy.deepcopy(state),
        'round_key': copy.deepcopy(round_keys[10])
    })

    return matrix2bytes(state), steps


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        key_type = request.form['key_type']
        message_type = request.form['message_type']
        key = request.form['key']
        message = request.form['message']

        try:
            # Procesar clave
            if key_type == 'hex':
                if len(key) != 32 or not all(c in '0123456789abcdefABCDEF' for c in key):
                    raise ValueError("La clave debe tener 32 dígitos hexadecimales (sin 0x)")
                key_bytes = bytes.fromhex(key)
            else:
                if len(key) != 16:
                    raise ValueError("La clave en texto plano debe tener exactamente 16 caracteres")
                key_bytes = key.encode('utf-8')

            # Procesar mensaje
            if message_type == 'hex':
                if not all(c in '0123456789abcdefABCDEF' for c in message):
                    raise ValueError("El mensaje contiene caracteres hexadecimales inválidos")
                if len(message) % 2 != 0:
                    message = '0' + message
                message_bytes = bytes.fromhex(message)
            else:
                message_bytes = message.encode('utf-8')

            # Cifrar
            round_keys = expand_key(key_bytes)
            ciphertext = b''
            steps = []
            for i in range(0, len(message_bytes), 16):
                block = message_bytes[i:i + 16]
                sub_ciphertext, sub_steps = encrypt_block_verbose(block, round_keys)
                ciphertext += sub_ciphertext
                steps.extend(sub_steps)

            return render_template('result.html',
                                   operation='Cifrado',
                                   original=message,
                                   result_hex=ciphertext.hex(),
                                   result_text=ciphertext.decode('utf-8', errors='replace'),
                                   steps=steps,
                                   round_keys=format_round_keys(round_keys),
                                   format_matrix=format_matrix)

        except Exception as e:
            error = str(e)
            return render_template(
                'encrypt.html',
                error=error,
                key=request.form.get('key', ''),
                message=request.form.get('message', ''),
                key_type=request.form.get('key_type', 'hex'),
                message_type=request.form.get('message_type', 'text')
            )

    return render_template('encrypt.html')


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        key_type = request.form['key_type']
        message_type = request.form['message_type']
        key = request.form['key']
        message = request.form['message']

        try:
            # Procesar clave
            if key_type == 'hex':
                if len(key) != 32 or not all(c in '0123456789abcdefABCDEF' for c in key):
                    raise ValueError("La clave debe tener 32 dígitos hexadecimales (sin 0x)")
                key_bytes = bytes.fromhex(key)
            else:
                if len(key) != 16:
                    raise ValueError("La clave en texto plano debe tener exactamente 16 caracteres")
                key_bytes = key.encode('utf-8')

            # Procesar mensaje
            if message_type == 'hex':
                if not all(c in '0123456789abcdefABCDEF' for c in message):
                    raise ValueError("El mensaje contiene caracteres hexadecimales inválidos")
                if len(message) % 2 != 0:
                    message = '0' + message
                message_bytes = bytes.fromhex(message)
            else:
                message_bytes = message.encode('utf-8')

            # Descifrar
            round_keys = expand_key(key_bytes)
            plaintext = b''
            steps = []
            for i in range(0, len(message_bytes), 16):
                block = message_bytes[i:i + 16]
                sub_plaintext, sub_steps = decrypt_block_verbose(block, round_keys)
                plaintext += sub_plaintext
                steps.extend(sub_steps)

            return render_template('result.html',
                                   operation='Descifrado',
                                   original=message,
                                   result_hex=plaintext.hex(),
                                   result_text=plaintext.decode('utf-8', errors='replace'),
                                   steps=steps,
                                   round_keys=format_round_keys(round_keys),
                                   format_matrix=format_matrix
                                 )

        except Exception as e:
            error = str(e)
            return render_template('decrypt.html', error=error)

    return render_template('decrypt.html')


if __name__ == '__main__':
    app.run(debug=True)