#!/usr/bin/env python
# -*- coding: utf-8 -*-
import fire
from sha256lib import Message, sha256


def sha256str(string: str) -> str:
    msg = Message.from_str(string)
    return sha256(msg)


if __name__ == '__main__':
    fire.Fire()
