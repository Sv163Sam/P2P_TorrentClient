import random

import bencodepy
import hashlib
import socket
import struct
import aiohttp
import asyncio
import requests
import os
import urllib.parse


# 1. Парсинг торрент-файла с использованием Bencode
def parse_torrent_file(torrent_file_path):
    with open(torrent_file_path, 'rb') as f:
        torrent_data = bencodepy.decode(f.read())
    return torrent_data


# 2. Механизм установления HTTP-соединений с трекером для получения списка пиров
def get_peers_from_tracker(tracker_url, torrent_info_hash, peer_id, port=6881):
    params = {
        'info_hash': torrent_info_hash,
        'peer_id': peer_id,
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': 1000000,  # Размер оставшегося файла
        'compact': 1,  # Ответ в компактном формате
        'event': 'started'  # Событие - начало скачивания
    }

    tracker_url = urllib.parse.urljoin(tracker_url, '/announce')
    response = requests.get(tracker_url, params=params)

    if response.status_code == 200:
        return response.content
    else:
        raise Exception(f"Не удалось получить данные с трекера: {response.status_code}")


# 3. Асинхронные HTTP-соединения для получения пиров
async def get_peers_async(tracker_url, torrent_info_hash, peer_id):
    params = {
        'info_hash': torrent_info_hash,
        'peer_id': peer_id,
        'port': 6881,
        'uploaded': 0,
        'downloaded': 0,
        'left': 1000000,
        'compact': 1,
        'event': 'started'
    }

    # Отключаем валидацию SSL-сертификатов
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get(tracker_url, params=params) as response:
            if response.status == 200:
                return await response.read()
            else:
                raise Exception(f"Не удалось получить данные с трекера: {response.status}")


# 4. Протокол пиров - рукопожатие и скачивание фрагмента
def handshake(info_hash, peer_id):
    # Преобразуем в байты, если это не байтовая строка
    if isinstance(info_hash, str):
        info_hash = bytes.fromhex(info_hash)  # если info_hash представлен в hex-строке

    pstrlen = 19
    pstr = b'BitTorrent protocol'
    reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'  # 8 байт зарезервированного пространства

    print(len(peer_id))
    handshake1 = struct.pack(
        '>B19s8s20s16s',  # Формат упаковки: байт, 19 байт, 8 байт, 20 байт, 20 байт
        pstrlen,
        pstr,
        reserved,
        info_hash,
        peer_id.encode('utf-8')
    )
    return handshake1


async def connect_to_peer(peer_ip, peer_port, info_hash, peer_id):
    try:
        # Подключение к пиру
        reader, writer = await asyncio.open_connection(peer_ip, peer_port)
        print(f"Подключаемся к пиру {peer_ip}:{peer_port}")
        # Отправка сообщения рукопожатия
        handshake_msg = handshake(info_hash, peer_id)
        print(f"Отправка рукопожатия: {handshake_msg}")
        writer.write(handshake_msg)
        await writer.drain()

        # Ожидание ответа
        response = await reader.read(68)  # Ожидаем ответа от пира (обычно 68 байт)
        print(f"Получен ответ: {response.hex()}")

        print("Respone:", len(response))

        # Проверка правильности рукопожатия
        print("Check handshake: ", response[0:19])

        # Вывод информации о соединении
        # print("Рукопожатие успешно!")

        writer.close()
        await writer.wait_closed()

        # Возвращаем соединение
        return response

    except Exception as e:
        print(f"Ошибка при подключении к пиру {peer_ip}:{peer_port}: {e}")
        raise


def assemble_file(total_pieces, piece_size, file_path, downloaded_pieces):
    try:
        # Убедитесь, что скачанных частей достаточно
        if len(downloaded_pieces) < total_pieces:
            raise ValueError(
                f"Недостаточно скачанных частей: ожидается {total_pieces}, получено {len(downloaded_pieces)}.")

        # Пример сборки файла
        with open(file_path, 'wb') as file:
            for i in range(total_pieces):
                piece_offset = i * piece_size
                # Проверка на доступность части перед сохранением
                if i < len(downloaded_pieces):
                    save_piece(downloaded_pieces[i], file_path, piece_offset)
                else:
                    print(f"Предупреждение: часть {i} не была скачана.")

    except ValueError as e:
        print(f"Ошибка при сборке файла: {e}")
    except IndexError as e:
        print(f"Ошибка индексации при сборке файла: {e}")


# 5. Сбор файла из скачанных фрагментов
def save_piece(piece_data, file_path, offset):
    if piece_data:  # Проверка на пустоту данных
        with open(file_path, 'r+b') as file:
            file.seek(offset)
            file.write(piece_data)
    else:
        print(f"Пустая часть данных на смещении {offset}, пропуск.")


# 6. Проверка целостности файла
def check_file_integrity(file_path, torrent_data):
    for pice in torrent_data[b'info'][b'pieces']:
        print(pice)

    expected_hash = torrent_data[b'info'][b'pieces']
    with open(file_path, 'rb') as f:
        file_data = f.read()
        file_hash = hashlib.sha1(file_data).digest()

    if file_hash == expected_hash:
        print("Файл соответствует ожидаемому")
    else:
        print("Ошибка целостности файла")


def get_info_hash(torrent_data):
    info = torrent_data[b'info']
    # Получаем хэш по содержимому информации (первоначальный torrent_info)
    info_bytes = bencodepy.encode(info)  # Сериализуем данные под ключом 'info'
    info_hash = hashlib.sha1(info_bytes).digest()  # Вычисляем хэш SHA1
    return info_hash


def parse_peers(peers_data):
    peers = []

    # Пропускаем первые 8 байтов, так как они содержат информацию о трекере
    peer_count = struct.unpack('>Q', peers_data[:8])[0]  # Получаем количество пиров
    peers_data = peers_data[8:]  # Оставляем только данные пиров

    # Для каждого пира проверяем, что данные достаточно большие
    for i in range(peer_count):
        if len(peers_data) < (i + 1) * 6:  # Проверяем, что осталось достаточно данных
            break  # Прерываем цикл, если данных не хватает

        peer = peers_data[i * 6:(i + 1) * 6]  # Извлекаем данные о пире
        ip = '.'.join(map(str, peer[:4]))  # Преобразуем первые 4 байта в строку IP
        port = struct.unpack('>H', peer[4:6])[0]  # Извлекаем порт (2 байта)
        peers.append((ip, port))  # Добавляем IP и порт в список пиров

    return peers


def choose_random_peer(peers):
    return random.choice(peers)  # Выбираем случайного пира из списка


# Пример асинхронного запроса пиров
def is_port_open(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, port))
        sock.close()
        return True
    except socket.error:
        return False


# Пример асинхронного запроса пиров
async def main():
    torrent_file_path = 'summer-dance-hits-2024.torrent'
    torrent_data = parse_torrent_file(torrent_file_path)

    # Получаем информацию о торренте
    info_hash = get_info_hash(torrent_data).hex()
    peer_id = '-TR1234-abcdefgh'  # Пример peer_id, обычно генерируется
    tracker_url = torrent_data[b'announce'].decode('utf-8')
    print(tracker_url)

    # Получаем пиров
    peers = await get_peers_async(tracker_url, info_hash, peer_id)
    downloaded_pieces = []
    prs = parse_peers(peers)

    for peer_ip, peer_port in prs:
        print(f"Peer IP: {peer_ip}, Peer Port: {peer_port}")
        if is_port_open(peer_ip, peer_port):
            piece_part = await connect_to_peer(peer_ip, peer_port, info_hash, peer_id)
            downloaded_pieces.append(piece_part)

    total_pieces = len(downloaded_pieces)

    piece_size = 1024 * 256  # Размер фрагмента (256 KB)

    # Сборка файла
    file_path = 'assembled_file.mp3'
    assemble_file(total_pieces, piece_size, file_path, downloaded_pieces)

    # Проверка целостности файла
    check_file_integrity(file_path, torrent_data)


# Запуск асинхронной программы
if __name__ == "__main__":
    asyncio.run(main())
