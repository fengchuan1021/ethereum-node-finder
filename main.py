#pip install pysha3
#pip install eciespy
#pip install netifaces
#pip install rlp
#pip install aioredis
import asyncio
import socket
import os
import secrets
from boostrapnodes import BOOTNODES
import urllib.parse
import binascii
import sha3
import rlp
import struct
from ecies.utils import generate_eth_key
import time
from typing import Any,List
from typing import NewType
Hash32 = NewType('Hash32', bytes)
from eth_keys.datatypes import PrivateKey,PublicKey
from eth_keys import keys
import ipaddress
import netifaces

CMD_PING=1
CMD_PONG = 2
CMD_FIND_NODE = 3
CMD_NEIGHBOURS =4
CMD_ENR_REQUEST = 5
CMD_ENR_RESPONSE = 6
MAC_SIZE = 256 // 8
SIG_SIZE = 520 // 8  # 65
HEAD_SIZE = MAC_SIZE + SIG_SIZE
sem = asyncio.Semaphore(100) #一次最多同时连接查询100个节点



def get_external_ipaddress() -> ipaddress.IPv4Address:
    for iface in netifaces.interfaces():
        for family, addresses in netifaces.ifaddresses(iface).items():
            if family != netifaces.AF_INET:
                continue
            for item in addresses:
                iface_addr = ipaddress.ip_address(item['addr'])
                if iface_addr.is_global:
                    return iface_addr
    return ipaddress.ip_address('127.0.0.1')

def _get_msg_expiration() -> bytes:
    return rlp.sedes.big_endian_int.serialize(int(time.time() + 60))
def init():
    if os.path.exists('key'):
        try:

            with open('key','rb') as f:
                eth_k=PrivateKey(f.read())
                return eth_k
        except Exception as e:
            print('55',e)
            pass
    eth_k = generate_eth_key()
    with open('key','wb') as f:
       f.write(eth_k.to_bytes())
    return eth_k
eth_k=init()
def keccak256(s):
    k = sha3.keccak_256()
    k.update(s)
    return k.digest()
myid= keccak256(eth_k.public_key.to_bytes()).hex()




sequence_number=111
def get_local_enr_seq():
    global sequence_number
    sequence_number+=1
    return sequence_number
def int_to_big_endian4(integer: int) -> bytes:
    return struct.pack('>I', integer)
def int_to_big_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
def big_endian_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big")
def enc_port(p: int) -> bytes:
    return int_to_big_endian4(p)[-2:]
def _is_msg_expired(rlp_expiration: bytes) -> bool:
    expiration = rlp.sedes.big_endian_int.deserialize(rlp_expiration)
    if time.time() > expiration:
        return True
    return False

class Address():
    def __init__(self, ip: str, udp_port: int, tcp_port: int=0) -> None:
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self._ip = ipaddress.ip_address(ip)

    @property
    def is_loopback(self) -> bool:
        return self._ip.is_loopback

    @property
    def is_unspecified(self) -> bool:
        return self._ip.is_unspecified

    @property
    def is_reserved(self) -> bool:
        return self._ip.is_reserved

    @property
    def is_private(self) -> bool:
        return self._ip.is_private

    @property
    def ip(self) -> str:
        return str(self._ip)
    def ip_packed(self) -> str:
        """The binary representation of this IP address."""
        return self._ip.packed

    def __eq__(self, other: Any) -> bool:
        return (self.ip, self.udp_port) == (other.ip, other.udp_port)

    def __repr__(self) -> str:
        return 'Address(%s:udp:%s|tcp:%s)' % (self.ip, self.udp_port, self.tcp_port)

    def to_endpoint(self) -> List[bytes]:

        return [self._ip.packed, enc_port(self.udp_port), enc_port(self.tcp_port)]

def _pack_v4(cmd_id, payload, privkey) -> bytes:
    cmd_id_bytes = int(cmd_id).to_bytes(1,byteorder='big')
    encoded_data = cmd_id_bytes + rlp.encode(payload)
    signature = privkey.sign_msg(encoded_data)
    message_hash = keccak256(signature.to_bytes() + encoded_data)
    return message_hash + signature.to_bytes() + encoded_data

def _unpack_v4(message: bytes):
    message_hash = Hash32(message[:MAC_SIZE])
    if message_hash !=keccak256(message[MAC_SIZE:]):
        raise Exception("Wrong msg mac")
    signature = keys.Signature(message[MAC_SIZE:HEAD_SIZE])
    signed_data = message[HEAD_SIZE:]
    remote_pubkey = signature.recover_public_key_from_msg(signed_data)
    cmd_id = message[HEAD_SIZE]
    payload = tuple(rlp.decode(message[HEAD_SIZE + 1:], strict=False))
    return remote_pubkey, cmd_id, payload, message_hash

async def sendlookuptonode(remote_publickey,remote_address):
    target_key = int_to_big_endian(
        secrets.randbits(512)
    ).rjust(512 // 8, b'\x00')
    nodeid=keccak256(target_key)
    expiration = _get_msg_expiration()
    await send(remote_address, CMD_FIND_NODE, (target_key, expiration))

async def recv_pong_v4(remote_publickey,remote_address, payload, _: Hash32,db) -> None:
    # The pong payload should have at least 3 elements: to, token, expiration
    await sendlookuptonode(remote_publickey,remote_address)



async def addtodb(db,arr):
    if arr:
        sql = "insert ignore into ethereum (nodeid,ip,port,publickey) values (%s,%s,%s,%s)"
        await db.executemany(sql,arr)

import datetime
async def recv_neighbours_v4(remote_publickey,remote_address, payload, _: Hash32,db) -> None:

    # The neighbours payload should have 2 elements: nodes, expiration
    if len(payload) < 2:
        print('neighbors wrong')
        return
    nodes, expiration = payload[:2]
    arr=[]
    update_arr=[]
    nodeid1=keccak256(remote_publickey.to_bytes()).hex()
    tm = datetime.datetime.now()
    for item in nodes:
        try:
            ip, udp_port, tcp_port, publickey = item
            ip=ipaddress.ip_address(ip)
            udp_port=big_endian_to_int(udp_port)
            node_id=keccak256(publickey).hex()
            update_arr.append([nodeid1,node_id,tm])
            arr.append([node_id,str(ip),udp_port,publickey.hex()])
        except Exception as e:
            print(e)
            continue
    if arr:
        await addtodb(db,arr)
    if update_arr:

        sql="insert into ethereum_neighbours (nodeid1,nodeid2,update_time) values (%s,%s,%s) ON DUPLICATE KEY UPDATE update_time=VALUES(update_time)"
        await db.executemany(sql,update_arr)


async def recv_ping_v4(
        remotepk,remote_address, payload, message_hash: Hash32,db) -> None:

    targetnodeid = keccak256(remotepk.to_bytes())
    if targetnodeid.hex()  == myid:
        return
    print('ping insert',[targetnodeid.hex(),remote_address[0],remote_address[1],remotepk.to_bytes().hex()])
    await addtodb(db,[[targetnodeid.hex(),remote_address[0],remote_address[1],remotepk.to_bytes().hex()]])

    if len(payload) < 4:
        print('error ping')
        return
    elif len(payload) == 4:
        _, _, _, expiration = payload[:4]
        enr_seq = None
    else:
        _, _, _, expiration, enr_seq = payload[:5]
        enr_seq = big_endian_to_int(enr_seq)
    if _is_msg_expired(expiration):
        print('msg ping timeout')
        return
    expiration = _get_msg_expiration()
    local_enr_seq = get_local_enr_seq()
    payload = (Address(remote_address[0],remote_address[1],remote_address[1]).to_endpoint(),message_hash, expiration, int_to_big_endian(local_enr_seq))
    await send(remote_address, CMD_PONG, payload)



def _get_handler(cmd):
    if cmd == CMD_PING:
        return recv_ping_v4
    elif cmd == CMD_PONG:
        return recv_pong_v4
    elif cmd == CMD_FIND_NODE:
        return None
    elif cmd == CMD_NEIGHBOURS:
        return recv_neighbours_v4
    elif cmd == CMD_ENR_REQUEST:
        return None
    elif cmd == CMD_ENR_RESPONSE:
        return None

def _onrecv(sock,db):
    try:
        data,remoteaddr=sock.recvfrom(1280*2)
    except Exception as e:
        return
    try:
        remote_pubkey, cmd_id, payload, message_hash = _unpack_v4(data)



    except Exception as e:
        print(e)
        return
    if cmd_id not in [CMD_PING,CMD_PONG,CMD_NEIGHBOURS]:
        return
    handler = _get_handler(cmd_id)
    asyncio.create_task(handler(remote_pubkey,remoteaddr,payload, message_hash,db))
    #await handler(remote_pubkey,remoteaddr,payload, message_hash)

async def send_ping_v4(hostname,port):

    version = rlp.sedes.big_endian_int.serialize(4)
    expiration = rlp.sedes.big_endian_int.serialize(int(time.time() + 180))
    local_enr_seq = get_local_enr_seq()
    payload = (version, Address('127.0.0.1',30303,30303).to_endpoint(), Address(hostname,port,port).to_endpoint(),
               expiration, int_to_big_endian(local_enr_seq))
    await send((hostname,port),1,payload)


async def inibootstrapnode(redis):
    ids=[]
    arr=[]
    for nodeurl in BOOTNODES:
        node_parsed = urllib.parse.urlparse(nodeurl)
        raw_pubkey = binascii.unhexlify(node_parsed.username)
        hostname=node_parsed.hostname
        strid=keccak256(raw_pubkey).hex()
        hid='hid:'+strid
        arr.append([strid,raw_pubkey.hex(),hostname,node_parsed.port,int(time.time())])
    if arr:
        sql="insert ignore into ethereum (nodeid,publickey,ip,port,pingtime) values (%s,%s,%s,%s,%s)"

        await redis.executemany(sql,arr)
async def find_node_to_ping(redis):
    nowtime=int(time.time())
    sql=f"select id,nodeid,ip,port from ethereum where pingtime<{nowtime}"
    result=await redis.execute(sql,1)
    tmpid=[str(row[0]) for row in result]
    if tmpid:
        sql=f"update ethereum set pingtime={nowtime+300} where id in ({','.join(tmpid)})"
        await redis.execute(sql)
    tasks = []
    for row in result:
        nodeid = row[1]
        ip= row[2]
        port=row[3]
        if myid != nodeid:
            tasks.append(send_ping_v4(ip, int(port)))
    if tasks:
        await asyncio.wait(tasks)

async def main(db):
    await inibootstrapnode(redis)
    while 1:
        await find_node_to_ping(redis)
        await asyncio.sleep(120)
from db import Db
async def getredis():
    dbconfig = {'sourcetable': 'ethereum', 'database': 'topo_p2p', 'databaseip': '192.168.1.36',
                'databaseport': 3306, 'databaseuser': 'fengchuan', 'databasepassword': 'bOelm#Fb2aX', 'condition': '',
                'conditionarr': []}
    db=await Db(dbconfig)

    return db
async def send(ipport, cmd_id, payload) -> bytes:
    global eth_k,sock,sem
    async with sem:
        message = _pack_v4(cmd_id, payload, eth_k)
        try:
            sock.sendto(message, ipport)
        except Exception as e:
            print(ipport)
    return message
if __name__=='__main__':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0',30303))
    loop = asyncio.get_event_loop()
    redis=loop.run_until_complete(getredis())
    loop.add_reader(sock, _onrecv,sock,redis)
    loop.create_task(main(redis))
    #loop.create_task(sendmsg(redis,sock))
    loop.run_forever()
