#pip install pysha3
#pip install eciespy
#pip install netifaces
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

from p2p.discv5.enr import ENR, UnsignedENR, IDENTITY_SCHEME_ENR_KEY
from p2p.discv5.identity_schemes import V4IdentityScheme
from p2p.discv5.constants import (
    IP_V4_ADDRESS_ENR_KEY,
    TCP_PORT_ENR_KEY,
    UDP_PORT_ENR_KEY,
)
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
myid=eth_k.public_key.to_bytes()
def keccak256(s):
    k = sha3.keccak_256()
    k.update(s)
    return k.digest()
def _generate_local_enr(
         sequence_number: int, ip_address = None) -> ENR:
    global eth_k
    if ip_address is None:
        ip_address = ipaddress.ip_address('127.0.0.1')
    kv_pairs = {
        IDENTITY_SCHEME_ENR_KEY: V4IdentityScheme.id,
        V4IdentityScheme.public_key_enr_key: eth_k.public_key.to_compressed_bytes(),
        IP_V4_ADDRESS_ENR_KEY: ip_address.packed,
        UDP_PORT_ENR_KEY: 30303,
        TCP_PORT_ENR_KEY: 30303,
    }

    unsigned_enr = UnsignedENR(sequence_number, kv_pairs)
    return unsigned_enr.to_signed_enr(eth_k.to_bytes())
enr=_generate_local_enr(111, get_external_ipaddress())

def get_local_enr_seq():
    return enr.sequence_number
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


CMD_PING=1
CMD_PONG = 2
CMD_FIND_NODE = 3
CMD_NEIGHBOURS =4
CMD_ENR_REQUEST = 5
CMD_ENR_RESPONSE = 6
MAC_SIZE = 256 // 8
SIG_SIZE = 520 // 8  # 65
HEAD_SIZE = MAC_SIZE + SIG_SIZE

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

async def recv_pong_v4(remote_publickey,remote_address, payload, _: Hash32) -> None:
    # The pong payload should have at least 3 elements: to, token, expiration
    await sendlookuptonode(remote_publickey,remote_address)
    if len(payload) < 3:
        return
    elif len(payload) == 3:
        _, token, expiration = payload[:3]
        enr_seq = None
    else:
        _, token, expiration, enr_seq = payload[:4]
        enr_seq = big_endian_to_int(enr_seq)
    if _is_msg_expired(expiration):
        return

async def addtodb(arr):
    global redis
    pipe = redis.pipeline()
    for node_id,ip,udp_port,pk in arr:
        pipe.hmset(f'hid:{node_id}', 'hostname', ip, 'port', udp_port,'pubkey',pk)
        pipe.sadd('ids', node_id)
    await pipe.execute()
    #await addtodb([targetnodeid.hex(),remote_address[0],remote_address[1],remotepk.to_bytes()])
async def recv_neighbours_v4(remote_publickey,remote_address, payload, _: Hash32) -> None:

    # The neighbours payload should have 2 elements: nodes, expiration
    if len(payload) < 2:
        print('neighbors wrong')
        return
    nodes, expiration = payload[:2]
    arr=[]
    for item in nodes:
        try:
            ip, udp_port, tcp_port, node_id = item
            ip=ipaddress.ip_address(ip)
            udp_port=big_endian_to_int(udp_port)
            node_id=node_id.hex()
            arr.append([node_id,str(ip),udp_port,''])
        except Exception as e:
            continue
    if arr:
        await addtodb(arr)


async def recv_ping_v4(
        remotepk,remote_address, payload, message_hash: Hash32) -> None:
    """Process a received ping packet.

    A ping packet may come any time, unrequested, or may be prompted by us bond()ing with a
    new node. In the former case we'll just reply with a pong, whereas in the latter we'll
    also send an empty msg on the appropriate channel from ping_channels, to notify any
    coroutine waiting for that ping.

    Also, if we have no valid bond with the given remote, we'll trigger one in the background.
    """
    targetnodeid = keccak256(remotepk.to_bytes())
    if targetnodeid  == myid:
        return
    await addtodb([[targetnodeid.hex(),remote_address[0],remote_address[1],remotepk.to_bytes()]])
    # The ping payload should have at least 4 elements: [version, from, to, expiration], with
    # an optional 5th element for the node's ENR sequence number.

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




async def recv_find_node_v4(remote_publickey,remote_address, payload, _: Hash32) -> None:
    # The find_node payload should have 2 elements: node_id, expiration
    if len(payload) < 2:
        return
    target, expiration = payload[:2]
    if _is_msg_expired(expiration):
        return
    target_id =keccak256(target)
    #found = self.routing.neighbours(target_id)
    #self.send_neighbours_v4(node, found)

async def recv_enr_request(
        remote_publickey, addr,payload, msg_hash: Hash32) -> None:
    # The enr_request payload should have at least one element: expiration.
    if len(payload) < 1:
        return
    expiration = payload[0]
    if _is_msg_expired(expiration):
        return
    payload = (msg_hash, ENR.serialize(enr))
    await send(addr, CMD_ENR_RESPONSE, payload)

async def recv_enr_response(
        remote_publickey, payload, msg_hash: Hash32) -> None:
    # The enr_response payload should have at least two elements: request_hash, enr.
    print('recv a req')
    if len(payload) < 2:
        return
    token, serialized_enr = payload[:2]
    try:
        tmpenr = ENR.deserialize(serialized_enr)
    except Exception as error:
        print(276,error)
        return
    tmpenr.validate_signature()

def send_enr_request(remote_publickey) -> Hash32:
    return
    message = self.send(node, CMD_ENR_REQUEST, [_get_msg_expiration()])
    token = Hash32(message[:MAC_SIZE])
    self.logger.debug("Sending ENR request with token: %s", encode_hex(token))
    return token
def _get_handler(cmd):
    if cmd == CMD_PING:
        return recv_ping_v4
    elif cmd == CMD_PONG:
        return recv_pong_v4
    elif cmd == CMD_FIND_NODE:
        return recv_find_node_v4
    elif cmd == CMD_NEIGHBOURS:
        return recv_neighbours_v4
    elif cmd == CMD_ENR_REQUEST:
        return recv_enr_request
    elif cmd == CMD_ENR_RESPONSE:
        return recv_enr_response

def _onrecv(sock):
    data,remoteaddr=sock.recvfrom(1280*2)
    try:
        remote_pubkey, cmd_id, payload, message_hash = _unpack_v4(data)

        print('cmdid:',cmd_id)

    except Exception as e:
        print(e)
        return
    if cmd_id<=0 and cmd_id>6:
        return
    handler = _get_handler(cmd_id)
    asyncio.create_task(handler(remote_pubkey,remoteaddr,payload, message_hash))
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
    for nodeurl in BOOTNODES:
        node_parsed = urllib.parse.urlparse(nodeurl)
        raw_pubkey = binascii.unhexlify(node_parsed.username)
        hostname=node_parsed.hostname
        strid=keccak256(raw_pubkey).hex()
        hid='hid:'+strid
        if not await redis.exists(hid):
            await redis.hmset(hid,'pingtime',0,'hostname',hostname,'port',node_parsed.port,'pubkey',raw_pubkey)
        ids.append(strid)
    await redis.sadd('ids',*ids)
async def find_node_to_ping(redis):
    total = await redis.scard('ids')
    pagesize = 200
    for i in range(0, total, pagesize):
        result = await redis.sort('ids', '#', 'hid:*->pingtime', 'hid:*->hostname', 'hid:*->port', by='hid:*->pingtime',offset=i, count=pagesize)
        tasks = []
        tmpids=[]
        for i in range(len(result) // 4):
            nodeid = result[i * 4]
            pingtime = result[i * 4 + 1]
            pingtime=0 if not pingtime else int(pingtime)
            hostname = result[i * 4 + 2]
            port = result[i * 4 + 3]
            if int(time.time()) - pingtime > 3 * 60:
                tmpids.append(b'hid:'+nodeid)
                if myid != nodeid:
                    tasks.append(send_ping_v4(hostname.decode(), int(port)))
            else:
                break

        if tasks:
            pipe=redis.pipeline()
            tm=int(time.time())
            for id in tmpids:
                pipe.hset(id,'pingtime',tm)
            await pipe.execute()
            await asyncio.wait(tasks)
        else:
            return
async def main(redis):
    await inibootstrapnode(redis)
    sem = asyncio.Semaphore(100) #一次最多同时连接查询100个节点
    while 1:
        await find_node_to_ping(redis)
        await asyncio.sleep(120)

async def getredis():
    from redis import Redis
    redis=await Redis()
    return redis
async def send(ipport, cmd_id, payload) -> bytes:
    global eth_k,sock
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
    loop.add_reader(sock, _onrecv,sock)
    loop.create_task(main(redis))
    #loop.create_task(sendmsg(redis,sock))
    loop.run_forever()
