from enum import Enum, IntEnum

from algorithm.edge import Edge


class VType(IntEnum):
    toforward = 1
    forwarding = 2
    both = 3


class VRFEdge(Edge):
    def __init__(self, node, vtype: VType):
        super().__init__(node)
        self.vtype = vtype

    def update(self, vtype: VType):
        if vtype != self.vtype:
            self.vtype = VType.both
