from dataclasses import dataclass


@dataclass
class ControlState:
    kill_switch: bool = False
    deny_prod: bool = False


STATE = ControlState()
