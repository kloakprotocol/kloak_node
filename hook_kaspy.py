# PyInstaller hook for kaspy
from PyInstaller.utils.hooks import collect_all, collect_submodules

# Collect all kaspy modules and data
datas, binaries, hiddenimports = collect_all('kaspy')

# Add google.protobuf.service explicitly - this is what kaspy needs
hiddenimports += [
    'google.protobuf.service',
    'google.protobuf.service_reflection', 
    'google.protobuf.symbol_database',
]

# Collect all grpc modules
hiddenimports += collect_submodules('grpc')
