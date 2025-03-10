import threading
import binascii
import hashlib
import socket
import random
import json
import time
import struct

address = 'bc1qwqkywltefk5g6vh59dzeq9etfp0lq86sl900xx'
workername = "bee"
server_address = ('pool.nerdminers.de', 3333)
response = b''
target = ''
job_id = ''
prevhash = ''
prevhash_1 = ''
coinb1 = ''
coinb2 = ''
merkle_branch = ''
version = ''
nbits = ''
ntime = ''
clean_jobs = ''
merkle_root = ''
sub_details = ''
extranonce1 = ''
extranonce2 = ''
extranonce2_size = 0
difficulty = 0.0001
difficulty_ok = 0
target_max =   "0000003e8b300000000000000000000000000000000000000000000000000000"
target_miner = "00003e8b30000000000000000000000000000000000000000000000000000000"
id_max = 1
partial_header = ""
test = 0
if test > 0:
    print("################## Debug True ##################")
    difficulty = 0.1
    difficulty_global = 0.1
def target_to_difficulty(target):
    # hedef (target) değerini zorluk (difficulty) değerine dönüştürme
    #print("Function target:", target)
    max_target = 0xFFFF * 2 ** (8 * (0x1D - 3))
    return max_target / int(target, 16)

def difficulty_to_target(difficulty):
    # hedef (target) değerini zorluk (difficulty) değerine dönüştürme
    max_target = 0xFFFF * 2 ** (8 * (0x1D - 3))
    return max_target / difficulty

def rev(item):
    item = item[::-1]
    item = ''.join([item[i:i + 2][::-1] for i in range(0, len(item), 2)])
    return item
def rev8(item):
    item = item[::-1]
    item = ''.join([item[i:i + 8][::-1] for i in range(0, len(item), 8)])
    return item

def worker(sock):
    global id_max, partial_header, job_id, extranonce2, ntime, address, target
    hash_count = 0
    star_time = time.time()
    nonce = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(8)  # nnonve   #hex(int(nonce,16)+1)[2:]
    nonce_int = int(nonce, 16)
    while True:

        nonce_int = nonce_int + 1

        header = partial_header + struct.pack("<L", nonce_int)

        hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        hash = binascii.hexlify(hash[::-1])

        #hash_count += 1
        #if int(hash_count % 3000000) == 0:
        #    m_time = time.time() - star_time
        #    hash_rate = hash_count / (m_time + 1) / 1000
        #    # print("Hash_count(k):", hash_count/1000, "Last nonce:", int(nonce,16))
        #    print("Last nonce:", str(nonce), "Hash rate:", int(hash_rate), "k per second")
        if target_to_difficulty(hash) > difficulty:
            id_max = id_max + 1
            print("=============Submit============", nonce, hash[::-1])
            payload = bytes('{"params": ["' + address + '", "' + job_id + '", "' + extranonce2 \
                            + '", "' + ntime + '", "' + hex(nonce_int)[2:].zfill(8) + '"], "id": ' + str(id_max) + ', "method": "mining.submit"}\n', 'utf-8')
            sock.sendall(payload)
            print("Send:", payload)

def receive_all(socket):
    # Alınacak veriyi tutmak için boş bir tampon oluştur
    all_data = b""
    while True:
        # Veri al
        data = socket.recv(1024)
        if len(data) < 1024:
            all_data += data
            break
        # Alınan veriyi tampona ekle
        all_data += data
    return all_data

# İstemciye gelen cevapları dinleyen iş parçacığı
def receive_messages(sock):
    global response, client, target, merkle_root, difficulty, id_max, target_miner, difficulty_ok, partial_header
    global job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs, sub_details, extranonce1, extranonce2, extranonce2_size,prevhash_1,difficulty_global,test

    while True:
        try:
            response = receive_all(client)
            responses = response.decode().split('\n')
            if(len(responses[0]) > 0):
                print("responses", responses,difficulty)

                for line in responses:
                    if("mining.set_difficulty" in line):
                       print("set_difficulty Line:", line)
                       response = json.loads(line)
                       difficulty = float(response['params'][0])
                       target_miner = format(int(difficulty_to_target(difficulty)))
                       print("difficulty:", difficulty, "Target: ", int(difficulty_to_target(difficulty)), "target_hex_64bit", format(int(difficulty_to_target(difficulty)), '064x'))
                       if(difficulty_ok == 0):
                           message = b'{"id":  ' + str(
                            id_max).encode() + b', "method": "mining.suggest_difficulty", "params": [0.0001]}\n'
                           # {"id": 3, "method": "mining.suggest_difficulty", "params": [0.0001]}
                           id_max = id_max + 1
                           client.sendall(message)
                           print("Send:", message)
                           difficulty_ok = 1
                    elif("mining.notify" in line and "}" in line ):

                        lines = json.loads(line)
                        if test > 0:
                            lines = json.loads('{"id":null,"method":"mining.notify","params":["125d743","213b49e448ab61cf1ba9028eacd42b1fd612228c0002304c0000000000000000","02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1703fc7a0d5075626c69632d506f6f6c","ffffffff02116cd312000000001976a9144aec5a123e1fcac480ad4a1bf1ae3bd15d693e6d88ac0000000000000000266a24aa21a9edcd480f493aca7e9b458aef188b3b03397f8f0e21a90a9dcf2819e38243342ad800000000",["c13a2371799d8762211f0a49ddf884b2ac83d3d34401395322227640ec69c400","19324de1e56bb1518904974450b111a34a65c83b343816f9509c5416925f4b41","5764da73fa91cd7fd1d7bf0aa85ba0013250805c5f08aad0ba469eb7670eda32","3f50a30964b878e154701dc7e2683dbb6ba22ac1c67130e4fd050ad95f6c9447","e64ac53edf3d055d10643e99822a29f1cc008d11c1b65572ed746cb0c77af660","f4746df81090812acbe6a44d1b4da5583ea2a76ee5848a9e69e7ae459769a575","54ae7542c543590bd3a0a77b59b857648ca90f48476a08771613e40f10fe25ad","a6270a936b8d661e97c9d8f1f6736725f0a71e083efbdaf1d7e7005d06a32b71","40e93ab2aa4b63994d4e5abf75da9d1dc2d79605a4be8bba6ed2bc56c2c57991","a98df388c2069fb70bf717423205d20c649898e9ac656f34a7645de10c0f7565","39e761238bdf4360f99a098ae947ad00d3ff758ec5f1faa3f62ed393ea6907b9","bb420c00e288c9336c26e8621716bb71f19df44dff7cdc136d496616717ee72b"],"20000000","17027726","67acd1ba",true]}')
                        job_idnn, prevhashnn, coinb1nn, coinb2nn, merkle_branchnn, versionnn, nbitsnn, ntimenn, clean_jobsnn = lines['params']
                        if prevhash_1 != prevhashnn:
                            job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs = lines['params']
                            
                            print("notify Line:", line)
                            print("====================================New job==================================")
                            target = (nbits[2:] + '00' * (int(nbits[:2], 16) - 3)).zfill(64)
                            print("Hash:", prevhash)
                            print("Target:", target)
                            extranonce2 = hex(random.randint(0, 2 ** (8 * extranonce2_size) - 1))[2:].zfill(2 * extranonce2_size)  # create random
                            if test > 0:
                                extranonce2 = hex(0)[2:].zfill(2 * extranonce2_size)
                            coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
                            print("coinbase:", coinbase)
                            coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

                            merkle_root = coinbase_hash_bin
                            for h in merkle_branch:
                                merkle_root = hashlib.sha256(
                                    hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

                            merkle_root = binascii.hexlify(merkle_root).decode()

                            # little endian
                            merkle_root = ''.join(
                                [merkle_root[i] + merkle_root[i + 1] for i in range(0, len(merkle_root), 2)][::-1])
                            prevhash_1 = prevhash
                            prevhash = rev8(prevhash)
                            version_int = int(version, 16)
                            time = int(ntime, 16)
                            bits = int(nbits, 16)

                            partial_header = struct.pack("<L", version_int) \
                                             + bytes.fromhex(prevhash)[::-1] \
                                             + bytes.fromhex(merkle_root)[::-1] \
                                             + struct.pack("<LL", time, bits)
        except Exception as e:
            print(e)
            pass          



if __name__ == '__main__':
    # Sunucuya bağlan
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(server_address)

    message = b'{"id": 1, "method": "mining.subscribe", "params": ["NerdMinerV2"]}\n'
    client.sendall(message)
    print("Send:", message)

    lines = client.recv(1024).decode().split('\n')
    print(lines)
    response = json.loads(lines[0])
    if test >0:
        response = json.loads('{"id":1,"error":null,"result":[[["mining.notify","50bf5064"]],"50bf5064",4]}')
    sub_details, extranonce1, extranonce2_size = response['result']
    print("Response:", response)
    print("sub_details, extranonce1, extranonce2_size:", sub_details, extranonce1, extranonce2_size)

    message = f'{{"params": ["{address}.{workername}", "x"], "id": 2, "method": "mining.authorize"}}\n'.encode()
    client.sendall(message)
    print("Send:", message)

    #response = receive_all(client)
    #print("Response:", response)
    #lines = response.decode().split('\n')
    #response = json.loads(lines[0])


    #message = b'{"id": 3, "method": "mining.suggest_difficulty"", "params": ["0.0001"]}\n\n'
    #client.sendall(message)
    #print("Send:", message)
    # İstemci tarafında cevapları dinlemek için yeni bir iş parçacığı başlat
    threading.Thread(target=receive_messages, args=(client,)).start()
    while True:
        try:
            hash_count = 0
            star_time = time.time()
            nonce = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(8)  # nnonve   #hex(int(nonce,16)+1)[2:]
            nonce_int = int(nonce, 16)
            while True:
                if partial_header != "":
                    nonce_int = nonce_int + 1
                    if test>0:
                        nonce_int = 0xfdfa0dc0
                    header = partial_header + struct.pack("<L", nonce_int)

                    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
                    hash = binascii.hexlify(hash[::-1])

                    #hash_count += 1
                    #if int(hash_count % 3000000) == 0:
                    #    m_time = time.time() - star_time
                    #    hash_rate = hash_count / (m_time + 1) / 1000
                    #    # print("Hash_count(k):", hash_count/1000, "Last nonce:", int(nonce,16))
                    #    print("Last nonce:", str(nonce), "Hash rate:", int(hash_rate), "k per second")
                    if target_to_difficulty(hash) > difficulty:
                        id_max = id_max + 1
                        print("=============Submit============", hex(nonce_int)[2:].zfill(8), hash,rev8(prevhash_1))
                        payload = bytes('{"params": ["' + address + '", "' + job_id + '", "' + extranonce2 \
                                        + '", "' + ntime + '", "' + hex(nonce_int)[2:].zfill(8) + '"], "id": ' + str(id_max) + ', "method": "mining.submit"}\n', 'utf-8')
                        if test == 0:
                            client.sendall(payload)
                        if test >0:
                            print("Test hash must be : 00000005eacad752637386c7c065b8b29a49b6c18695f662f4a2e3f72c9c0598")
                        print(payload)
        except Exception as e:
            print(e)
            pass 