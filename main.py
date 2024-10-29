import ssl
import bencodepy
import aiohttp
import asyncio
import socket
import hashlib
import struct
import random
import os
from urllib.parse import quote  # Импортируем для кодирования


# Парсинг торрент-файла
def parse_torrent_file(torrent_file):
    with open(torrent_file, 'rb') as f:
        torrent_data = bencodepy.decode(f.read())

    # Проверка на наличие ключа 'length'
    if b'length' in torrent_data[b'info']:
        file_size = torrent_data[b'info'][b'length']
        file_name = torrent_data[b'info'][b'name']
    elif b'files' in torrent_data[b'info']:
        # Мульти-файловый торрент
        total_size = 0
        for file in torrent_data[b'info'][b'files']:
            total_size += file[b'length']
        file_name = [file[b'path'] for file in torrent_data[b'info'][b'files']]
        file_size = total_size
    else:
        raise ValueError("Не удалось найти размер файла в торренте.")

    tracker_url = torrent_data[b'announce'].decode('utf-8')
    info_hash = hashlib.sha1(bencodepy.encode(torrent_data[b'info'])).hexdigest()

    return file_name, file_size, tracker_url, info_hash


# Генерация уникального идентификатора пира
def generate_peer_id():
    return '-PC0001-' + ''.join(
        [random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz') for _ in range(12)])


# Асинхронное соединение с трекером
async def get_peers(tracker_url, info_hash, file_size):
    params = {
        'info_hash': quote(info_hash),
        'peer_id': generate_peer_id(),
        'port': 6881,
        'uploaded': 0,
        'downloaded': 0,
        'left': file_size,
        'event': 'started'
    }

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession() as session:
        async with session.get(tracker_url, params=params, ssl=ssl_context) as response:
            if response.status == 200:
                data = await response.read()
                return parse_tracker_response(data)  # Обработка ответа от трекера


def parse_tracker_response(data):
    response = bencodepy.decode(data)
    print(response)
    peers = response[b'peers']

    if isinstance(peers, bytes):
        return [f"{socket.inet_ntoa(peers[i:i + 4])}:{struct.unpack('>H', peers[i + 4:i + 6])[0]}"
                for i in range(0, len(peers), 6)]
    else:
        return [f"{peer[b'ip'].decode()}:{peer[b'port']}" for peer in peers]


# Создание рукопожатия
async def handshake(peer_ip, peer_port, info_hash, peer_id):
    reader, writer = await asyncio.open_connection(peer_ip, peer_port)
    try:
        handshake_message = create_handshake_message(info_hash, peer_id)
        writer.write(handshake_message)
        await writer.drain()

        response = await reader.read(68)
        return response
    finally:
        writer.close()
        await writer.wait_closed()


def create_handshake_message(info_hash, peer_id):
    pstr = b'BitTorrent protocol'
    pstrlen = len(pstr)
    reserved = b'x00' * 8
    return struct.pack('B', pstrlen) + pstr + reserved + info_hash + peer_id.encode('utf-8')


# Функция для скачивания фрагмента

async def download_piece(peer_ip, peer_port, piece_index, info_hash, peer_id, file_name):
    # Создаем TCP-соединение с пиром
    reader, writer = await asyncio.open_connection(peer_ip, peer_port)

    # Формируем запрос на скачивание кусочка
    request = struct.pack('>B', 6)  # 6 - это код для запроса на скачивание кусочка
    request += info_hash + peer_id + struct.pack('>I', piece_index)  # Добавьте необходимые данные

    # Отправляем запрос
    writer.write(request)
    await writer.drain()

    # Получаем ответ от пира
    response = await reader.read(16384)  # Читаем данные (размер буфера можно изменить)

    # Сохраняем данные в файл
    with open(file_name, 'r+b') as f:
        f.seek(piece_index * piece_size)  # Устанавливаем указатель на нужный кусочек
        f.write(response)  # Записываем загруженные данные

    print(f"Received data for piece {piece_index} from {peer_ip}:{peer_port}")

    # Закрываем соединение
    writer.close()
    await writer.wait_closed()


# Сборка файла из скачанных фрагментов
def assemble_file(pieces, output_file):
    with open(output_file, 'wb') as f:
        for piece in pieces:
            f.write(piece)


# Проверка целостности файла
def check_file_integrity(file_path, expected_hash):
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha1.update(chunk)
    return sha1.hexdigest() == expected_hash


# Генерация уникального peer_id
def generate_peer_id():
    return '-PC0001-' + os.urandom(8).hex()  # Пример peer_id длиной 20 символов


async def main(torrent_file):
    file_names, file_size, tracker_url, info_hash = parse_torrent_file(torrent_file)

    if isinstance(file_names, list):
        file_name = file_names[0]
    else:
        file_name = file_names

    file_name = file_name[0]
    print(file_name)

    global piece_size
    piece_size = 256 * 1024
    num_pieces = (file_size + piece_size - 1) // piece_size

    with open(file_name, 'wb') as f:
        f.write(b'0' * file_size)

    peers = await get_peers(tracker_url, info_hash, file_size)

    print(f"Found peers: {peers}")

    # Генерация peer_id
    peer_id = generate_peer_id()

    tasks = []
    for peer in peers:
        try:
            peer_ip, peer_port = peer.split(':')
            peer_port = int(peer_port)
            for piece_index in range(num_pieces):
                tasks.append(download_piece(peer_ip, peer_port, piece_index, info_hash, peer_id, file_name))
        except ValueError:
            print(f"Unexpected peer format: {peer}")

    await asyncio.gather(*tasks)


# Запуск основного кода
if __name__ == "__main__":
    asyncio.run(main('Noita_1.0..torrent'))
