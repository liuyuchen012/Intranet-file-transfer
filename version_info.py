# version_info.py
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringTable,
    StringStruct,
    VarFileInfo,
    VarStruct,
    VSVersionInfo
)

vs_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(2, 1, 0, 0),
        prodvers=(2, 1, 0, 0),
        mask=0x3F,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
    ),
    kids=[
        StringFileInfo([
            StringTable(
                '040904B0',
                [
                    StringStruct('CompanyName', '天津市东丽区创晨普通物理科技工作室'),
                    StringStruct('FileDescription', '文件传输系统'),
                    StringStruct('FileVersion', '2.1.0'),
                    StringStruct('InternalName', 'FileTransfer'),
                    StringStruct('LegalCopyright', '© 2024 天津市东丽区创晨普通物理科技工作室'),
                    StringStruct('OriginalFilename', 'FileTransferSystem.exe'),
                    StringStruct('ProductName', 'File Transfer System'),
                    StringStruct('ProductVersion', '2.1.0')
                ])
        ]),
        VarFileInfo([
            VarStruct('Translation', [0x0409, 1200])
        ])
    ]
)