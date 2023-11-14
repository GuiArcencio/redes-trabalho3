from __future__ import annotations
from ipaddress import ip_address

from grader.iputils import *

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        ip = self._ipaddr_para_bitstring(dest_addr)
        return self._tabela_encaminhamento.find(ip)

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self._tabela_encaminhamento = TRIE()
        for cidr, next_hop in tabela:
            self._tabela_encaminhamento.insert(
                self._cidr_para_bitstring(cidr),
                next_hop
            )

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(datagrama, next_hop)

    def _cidr_para_bitstring(self, cidr: str):
        ip, bits = cidr.split('/')
        bits = int(bits)
        ip = int.from_bytes(ip_address(ip).packed, 'big')
        ip = f'{ip:032b}'[:bits]

        return ip 
    
    def _ipaddr_para_bitstring(self, ipaddr: str):
        ip = int.from_bytes(ip_address(ipaddr).packed, 'big')
        return f'{ip:032b}'


# Implementação de TRIE para a tabela de encaminhamento
class TRIE:
    _content: str | None
    _one_child: TRIE
    _zero_child: TRIE

    def __init__(self, content: str | None = None) -> None:
        self._content = content
        self._one_child = None
        self._zero_child = None

    def find(self, key: str):
        found = self._content
        found_child = None

        if len(key) > 0:
            if key[0] == '0' and self._zero_child is not None:
                found_child = self._zero_child.find(key[1:])
            elif key[0] == '1' and self._one_child is not None:
                found_child = self._one_child.find(key[1:])

        if found_child is not None:
            return found_child
        return found

    def insert(self, key: str, content: str):
        if len(key) == 0:
            self._content = content
            return
        
        if key[0] == '0':
            if self._zero_child is None:
                self._zero_child = TRIE()

            self._zero_child.insert(key[1:], content)
        elif key[0] == '1':
            if self._one_child is None:
                self._one_child = TRIE()

            self._one_child.insert(key[1:], content)