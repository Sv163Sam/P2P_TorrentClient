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

    downloaded_pieces = []
    prs = [('69.32.72.84', 19788), ('32.80.85.66', 19529), ('67.32.34.45', 12079), ('87.51.67.47', 12100),
           ('84.68.32.72', 21581), ('76.32.52.46', 12337), ('32.84.114.97', 28275), ('105.116.105.111', 28257),
           ('108.47.47.69', 20002), ('32.34.104.116', 29808), ('58.47.47.119', 30583), ('46.119.51.46', 28530),
           ('103.47.84.82', 12136), ('116.109.108.52', 12140), ('111.111.115.101', 11876), ('116.100.34.62', 2620),
           ('104.116.109.108', 8304), ('114.101.102.105', 30781), ('34.121.97.58', 8296), ('116.116.112.58', 12079),
           ('119.101.98.109', 24947), ('116.101.114.46', 31073), ('110.100.101.120', 11890), ('117.47.118.111', 25441),
           ('98.117.108.97', 29289), ('101.115.47.34', 15932), ('104.101.97.100', 15882), ('60.109.101.116', 24864),
           ('104.116.116.112', 11621), ('113.117.105.118', 15650), ('67.111.110.116', 25966), ('116.45.84.121', 28773),
           ('34.32.99.111', 28276), ('101.110.116.61', 8820), ('101.120.116.47', 26740), ('109.108.59.32', 25448),
           ('97.114.115.101', 29757), ('119.105.110.100', 28535), ('115.45.49.50', 13617), ('34.62.10.60', 28005),
           ('116.97.32.110', 24941), ('101.61.34.121', 24942), ('100.101.120.45', 30309), ('114.105.102.105', 25441),
           ('116.105.111.110', 8736), ('99.111.110.116', 25966), ('116.61.34.49', 13158), ('51.52.101.49', 25137),
           ('98.97.57.51', 14131), ('102.34.32.47', 15882), ('60.109.101.116', 24864), ('104.116.116.112', 11621),
           ('113.117.105.118', 15650), ('67.111.110.116', 25966), ('116.45.83.116', 31084), ('101.45.84.121', 28773),
           ('34.32.99.111', 28276), ('101.110.116.61', 8820), ('101.120.116.47', 25459), ('115.34.62.10', 15469),
           ('101.116.97.32', 26740), ('116.112.45.101', 29045), ('105.118.61.34', 22573), ('85.65.45.67', 28525),
           ('112.97.116.105', 25196), ('101.34.32.99', 28526), ('116.101.110.116', 15650), ('99.104.114.111', 28005),
           ('61.49.34.62', 2620), ('109.101.116.97', 8304), ('114.111.112.101', 29300), ('121.61.34.121', 24890),
           ('105.110.116.101', 29281), ('99.116.105.111', 28194), ('32.99.111.110', 29797), ('110.116.61.34', 22605),
           ('76.95.70.79', 21069), ('34.32.47.62', 2620), ('109.101.116.97', 8304), ('114.111.112.101', 29300),
           ('121.61.34.121', 24890), ('105.110.116.101', 29281), ('99.116.105.111', 28218), ('117.114.108.34', 8291),
           ('111.110.116.101', 28276), ('61.34.104.116', 29808), ('58.47.47.110', 28269), ('45.99.108.117', 25134),
           ('109.101.47.102', 28530), ('117.109.47.121', 24942), ('100.101.120.46', 30829), ('108.34.32.47', 15882),
           ('60.108.105.110', 27424), ('114.101.108.61', 8825), ('97.110.100.101', 30765), ('116.97.98.108', 25953),
           ('117.45.119.105', 25703), ('101.116.34.32', 26738), ('101.102.61.34', 26740), ('116.112.115.58', 12079),
           ('110.110.109.45', 25452), ('117.98.46.109', 25903), ('116.97.98.108', 25953), ('117.47.116.97', 25196),
           ('101.97.117.46', 27251), ('111.110.34.32', 12094), ('10.60.109.101', 29793), ('32.110.97.109', 25917),
           ('34.118.105.101', 30576), ('111.114.116.34', 8291), ('111.110.116.101', 28276), ('61.34.119.105', 25716),
           ('104.61.100.101', 30313), ('99.101.45.119', 26980), ('116.104.44.32', 26990), ('105.116.105.97', 27693),
           ('115.99.97.108', 25917), ('49.46.48.34', 8239)]
    print(prs)
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
