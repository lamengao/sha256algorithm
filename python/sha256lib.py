#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import Self
from functools import cached_property, cache

# https://github.com/in3rsha/sha256-animation

# Initialize variables
# (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# Initialize table of round constants
# (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


# word is 32 bit bytes

class Word():
    mask = 2**32 - 1

    def __init__(self, word: bytes) -> None:
        assert len(word) == 4
        self.word = word

    @staticmethod
    def from_int(num: int) -> "Word":
        b = num.to_bytes(4, "big")
        return Word(b)

    @staticmethod
    def from_bin(bin_str: str) -> "Word":
        bin_str = bin_str.replace(" ", "")
        i = int(bin_str, 2)
        assert i <= 2**32 - 1
        return Word(i.to_bytes(4, "big"))

    def copy(self) -> Self:
        return Word(self.word)

    def __str__(self) -> str:
        return self.hex()

    def __eq__(self, o: Self) -> bool:
        return self.word == o.word

    def __add__(self, o: Self) -> Self:
        return self.add(o)

    def hex(self) -> str:
        return "0x" + self.word.hex()

    def bin(self) -> str:
        i = int.from_bytes(self.word, "big")
        return '0b' + bin(i)[2:].zfill(32)

    @property
    def int_(self) -> int:
        return int.from_bytes(self.word, "big")

    # Right Shift
    # SHRn(x) = x >> n
    def shr(self, n: int) -> Self:
        assert n <= 32
        j = self.int_ >> n
        return Word.from_int(j)

    # Rotate Right
    # ROTRn(x) = (x >> n) | (x << 32-n)
    def rotr(self, n: int) -> Self:
        assert n <= 32
        i = (self.int_ >> n | (self.int_ << (32 - n))) & Word.mask
        return Word.from_int(i)

    # Exclusive Or
    # x ^ y ^ z
    def xor(self, *args: Self) -> Self:
        i = self.int_
        for w in args:
            i = i ^ w.int_
        return Word.from_int(i)

    def add(self, *args: Self) -> Self:
        i = self.int_
        for w in args:
            i = i + w.int_
        i = i % 2**32
        return Word.from_int(i)

    # σ0(x) = ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x)
    def sigma0(self) -> Self:
        return self.rotr(7).xor(self.rotr(18), self.shr(3))

    # σ1(x) = ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x)
    def sigma1(self) -> Self:
        return self.rotr(17).xor(self.rotr(19), self.shr(10))

    # Σ0(x) = ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x)
    def usigma0(self) -> Self:
        return self.rotr(2).xor(self.rotr(13), self.rotr(22))

    # Σ1(x) = ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x)
    def usigma1(self) -> Self:
        return self.rotr(6).xor(self.rotr(11), self.rotr(25))

    # Ch(x, y, z) = (x & y) ^ (~x & z)
    # self is x
    def ch(self, y: Self, z: Self) -> Self:
        left = self.int_ & y.int_
        right = (~self.int_) & z.int_
        return Word.from_int(left ^ right)

    # Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
    def maj(self, y: Self, z: Self) -> Self:
        a = self.int_ & y.int_
        b = self.int_ & z.int_
        c = y.int_ & z.int_
        return Word.from_int(a ^ b ^ c)


class Message():

    def __init__(self, data: bytes) -> None:
        self.msg = data

    @staticmethod
    def from_str(data: str) -> "Message":
        return Message(bytes(data, 'utf-8'))

    # https://en.wikipedia.org/wiki/SHA-2
    # begin with the original message of length L bits
    # append a single '1' bit
    # append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    # append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    # such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> ,
    # (the number of bits will be a multiple of 512)
    @cached_property
    def padded_msg(self) -> bytes:
        msg_len = len(self.msg) * 8
        k = 512 - ((msg_len + 65) % 512)
        # can not handle msg that bits length not eq 8n
        assert (k - 7) % 8 == 0
        _padding_msg: bytearray = bytearray(self.msg)
        _padding_msg.append(0b10000000)
        _padding_msg.extend(bytearray((k - 7)//8))
        msg_len_bytes = msg_len.to_bytes(64 // 8, "big")
        _padding_msg.extend(bytearray(msg_len_bytes))
        return _padding_msg

    def padded_msg_bin(self) -> str:
        length = len(self.padded_msg) * 8  # padding msg bits length
        b = bytes(self.padded_msg)
        i = int.from_bytes(b, "big")
        return '0b' + bin(i)[2:].zfill(length)

    @cached_property
    def blocks(self) -> list[bytes]:
        _blocks: list[bytes] = []
        count = len(self.padded_msg) * 8 // 512
        for i in range(count):
            start = i * 512 // 8
            end = start + 512 // 8
            _blocks.append(bytes(self.padded_msg[start:end]))
        return _blocks

    @cache
    def get_schedule(self, block_index: int) -> list["Word"]:
        if block_index >= len(self.blocks):
            raise IndexError
        block = self.blocks[block_index]
        schedule: list["Word"] = [Word(block[i*4:i*4+4]) for i in range(16)]
        for t in range(16, 64):
            # Wt = σ1(Wt-2) + Wt-7 + σ0(Wt-15) + Wt-16
            # (for 16 ≤ t ≤ 63)
            w = schedule[t-2].sigma1() + schedule[t-7] + \
                schedule[t-15].sigma0() + schedule[t-16]
            schedule.append(w)
        return schedule


def compression(initial: list["Word"], schedule: list["Word"]):
    a, b, c, d, e, f, g, h = initial
    for (i, w) in enumerate(schedule):
        # T1 = Σ1(e) + Ch(e, f, g) + h + Kt + Wt
        # T2 = Σ0(a) + Maj(a, b, c)
        t1 = e.usigma1() + e.ch(f, g) + h + Word.from_int(K[i]) + w
        t2 = a.usigma0() + a.maj(b, c)
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    a += initial[0]
    b += initial[1]
    c += initial[2]
    d += initial[3]
    e += initial[4]
    f += initial[5]
    g += initial[6]
    h += initial[7]
    return [a, b, c, d, e, f, g, h]


def sha256(msg: Message):
    initial = [Word.from_int(i) for i in H]
    for i in range(len(msg.blocks)):
        schedule = msg.get_schedule(i)
        initial = compression(initial, schedule)
    digest = ''
    for w in initial:
        digest += w.hex()[2:]
    return digest
