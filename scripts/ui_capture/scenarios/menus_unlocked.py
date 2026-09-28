from common import *

STATUS = unlock_all
STEPS = [*boot(), *nav("play_in", MAIN["play"]), ("wait", 30)]
