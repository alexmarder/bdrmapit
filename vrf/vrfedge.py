from enum import IntEnum


class VType(IntEnum):
    toforward = 1
    forwarding = 2
    both = 3


class VRFEdge:
    def __init__(self, node, vtype: VType):
        self.node = node
        self.vtype = vtype

    def update(self, vtype: VType):
        if vtype != self.vtype:
            self.vtype = VType.both
