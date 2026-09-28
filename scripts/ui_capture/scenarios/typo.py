from common import *

STATUS = unlock_all
STEPS = [*boot(), ("click", *MAIN["play"]), ("wait", 120), ("click", 232, 424), ("wait", 180), ("shot", "typo_hud"),
         ("text", "abc"), ("wait", 10), ("shot", "typo_typed"), ("wait", 300), ("shot", "typo_5s")]
