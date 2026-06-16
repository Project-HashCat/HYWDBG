$ErrorActionPreference = "Stop"
python .\tools\hywctl.py core.hello
python .\tools\hywctl.py core.startBackend '{"kind":"titan"}'
python .\tools\hywctl.py core.backendStatus
python .\tools\hywctl.py dbg.capabilities
python .\tools\hywctl.py dbg.attach '{"pid":1234}'
python .\tools\hywctl.py dbg.regs
python .\tools\hywctl.py dbg.disasm '{"addr":"0x140001000","count":4}'
python .\tools\hywctl.py core.stopBackend
