import bencodepy
import requests
import hashlib
import aiohttp
import asyncio
import socket


# 1. Модуль парсинга торрент файла
# Торрент файл хранит информацию в формате Bencode.
# Это включает в себя метаданные о файле, такие как имя, размер и трекеры.
def parse_torrent_file(file_path):
    with open(file_path, 'rb') as f:
        torrent_data = bencodepy.decode(f.read())

    # Извлечение информации
    file_name = torrent_data[b'info'][b'name'].decode('utf-8')
    file_size = torrent_data[b'info'][b'length']
    tracker_url = torrent_data[b'announce'].decode('utf-8')

    # Если это многослойный торрент (с несколькими файлами)
    if b'files' in torrent_data[b'info']:
        files = torrent_data[b'info'][b'files']
        file_info = []
        for file in files:
            name = file[b'path'][0].decode('utf-8')
            size = file[b'length']
            file_info.append((name, size))
        return file_info, tracker_url
    else:
        return [(file_name, file_size)], tracker_url


# Пример использования
file_info, tracker_url = parse_torrent_file('example.torrent')  ##################################
print(f"Files: {file_info}, Tracker URL: {tracker_url}")


# 2. Механизм HTTP соединений с трекером
# Трекеры помогают клиентам находить друг друга.
# Мы отправляем запросы к трекерам, чтобы получить список пиров.
def get_peers(tracker_url, info_hash, peer_id, port, file_size):
    params = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': file_size,
        'event': 'started'
    }

    response = requests.get(tracker_url, params=params)

    if response.status_code == 200:
        return response.content  # Обработка ответа зависит от формата (обычно это bencode)
    else:
        raise Exception("Failed to contact tracker")


# Пример использования
file_size = file_info[0][1]
info_hash = hashlib.sha1(b'some_info_data').digest()  # Замените на реальный info_hash
peer_id = '-AZ2060-123456789012'  # Уникальный идентификатор вашего клиента
port = 6881
peers_data = get_peers(tracker_url, info_hash, peer_id, port, file_size)


# 3. Асинхронные HTTP соединения
# Асинхронные запросы позволяют вашему клиенту не блокировать выполнение программы во время ожидания ответа от трекера.
async def fetch_peers(tracker_url, info_hash, peer_id, port, file_size):
    params = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': file_size,
        'event': 'started'
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(tracker_url, params=params) as response:
            return await response.read()  # Получаем данные о пирах


# Пример вызова
async def main():
    peers_data = await fetch_peers(tracker_url, info_hash, peer_id, port, file_size)
    print(peers_data)


# Запуск асинхронной функции
asyncio.run(main())


# 4. Протокол пиров
# Рукопожатие между пирами — это важный шаг для установления соединения и начала обмена данными.
def handshake(peer_id, info_hash):
    pstr = "BitTorrent protocol"
    pstrlen = len(pstr)
    reserved = b'x00' * 8
    handshake_message = (
            bytes([pstrlen]) + pstr.encode() + reserved + info_hash + peer_id.encode()
    )
    # Создание сокета и отправка рукопожатия
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip, peer_port))  # peer_ip и peer_port должны быть определены заранее
    s.send(handshake_message)

    response = s.recv(68)  # Ожидаем ответ рукопожатия
    return response


# Пример использования
response = handshake(peer_id, info_hash)
print(response)


# 5. Сбор файла из скачанных фрагментов
# Когда файл разбивается на фрагменты (чанки), их нужно собрать в единое целое.
def assemble_file(chunks, output_file):
    with open(output_file, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)


# Пример использования
chunks = [b'chunk1_data', b'chunk2_data']  # Список загруженных фрагментов
assemble_file(chunks, 'output_file.dat')


def check_file_integrity(file_path, expected_hash):
    sha1 = hashlib.sha1()

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha1.update(chunk)

    return sha1.hexdigest() == expected_hash


# Пример использования
expected_hash = 'expected_sha1_hash_here'  # Замените на реальный хеш
if check_file_integrity('output_file.dat', expected_hash):
    print("File is valid.")
else:
    print("File is corrupted.")
