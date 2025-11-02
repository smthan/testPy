# -*- coding: utf-8 -*-
"""
文件夹压缩加密工具 - GUI界面
包含完整的压缩、解压和加密解密功能
"""
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import re
import json
import gzip
import struct
import hashlib
import base64
import fnmatch
from typing import Tuple, List, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# ==================== 加密解密功能 ====================

def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    从密码派生加密密钥
    
    Args:
        password: 用户密码
        salt: 盐值，如果为None则生成新的盐值
    
    Returns:
        (key, salt) 元组
    """
    if salt is None:
        salt = hashlib.sha256(password.encode()).digest()[:16]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_data(data: bytes, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    加密数据
    
    Args:
        data: 要加密的数据
        password: 密码
        salt: 盐值
    
    Returns:
        (加密后的数据, salt) 元组
    """
    key, salt = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    return encrypted_data, salt


def decrypt_data(encrypted_data: bytes, password: str, salt: bytes) -> bytes:
    """
    解密数据
    
    Args:
        encrypted_data: 加密的数据
        password: 密码
        salt: 盐值
    
    Returns:
        解密后的数据
    """
    key, _ = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data


# ==================== 忽略规则处理 ====================

def parse_ignore_patterns(ignore_text: str) -> Tuple[List[str], List[str]]:
    """
    解析忽略规则文本，返回文件夹列表和文件模式列表
    
    Args:
        ignore_text: 忽略规则文本，用逗号或换行分隔，如 "logs,*.pdb,temp"
    
    Returns:
        (文件夹列表, 文件模式列表) 元组
    """
    if not ignore_text or not ignore_text.strip():
        return [], []
    
    patterns = []
    # 支持逗号、分号、换行符分隔
    for delimiter in [',', ';', '\n', '\r\n']:
        ignore_text = ignore_text.replace(delimiter, '|')
    
    patterns = [p.strip() for p in ignore_text.split('|') if p.strip()]
    
    folders = []
    file_patterns = []
    
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        
        # 如果包含通配符（*或?），认为是文件模式
        # 如果没有通配符，可能是文件夹名或文件名
        if '*' in pattern or '?' in pattern:
            file_patterns.append(pattern)
        else:
            # 检查是否是扩展名（以.开头且只有扩展名）
            if pattern.startswith('.') and '.' not in pattern[1:]:
                # 这是一个扩展名，转换为文件模式
                file_patterns.append(f'*{pattern}')
            else:
                # 可能是文件夹名或文件名
                folders.append(pattern)
    
    return folders, file_patterns


def should_ignore_path(path_str: str, folders: List[str], file_patterns: List[str], is_file: bool = True) -> bool:
    """
    判断路径是否应该被忽略
    
    Args:
        path_str: 相对路径字符串（使用/分隔符）
        folders: 要忽略的文件夹名列表
        file_patterns: 要忽略的文件模式列表（支持通配符）
        is_file: 是否为文件（True为文件，False为文件夹）
    
    Returns:
        如果应该忽略返回True，否则返回False
    """
    path_parts = path_str.split('/')
    
    # 检查文件夹匹配
    for folder_name in folders:
        if folder_name in path_parts:
            return True
    
    # 如果是文件，检查文件模式匹配
    if is_file:
        filename = path_parts[-1] if path_parts else path_str
        for pattern in file_patterns:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(filename.lower(), pattern.lower()):
                return True
    
    return False


# ==================== 压缩功能 ====================

def compress_folder(folder_path: str, output_file: str, password: str, 
                    progress_callback=None, cancel_flag=None, ignore_patterns: Optional[str] = None):
    """
    压缩文件夹为fz文件
    
    Args:
        folder_path: 要压缩的文件夹路径
        output_file: 输出的fz文件路径
        password: 加密密码
        progress_callback: 进度回调函数 (current, total, status) -> None
        cancel_flag: 取消标志对象，检查 cancel_flag.is_set() 来判断是否取消
        ignore_patterns: 忽略规则文本，如 "logs,*.pdb"
    """
    folder_path = Path(folder_path).resolve()
    if not folder_path.exists() or not folder_path.is_dir():
        raise ValueError(f"文件夹不存在: {folder_path}")
    
    # 解析忽略规则
    ignore_folders, ignore_file_patterns = parse_ignore_patterns(ignore_patterns or "")
    if ignore_folders or ignore_file_patterns:
        print(f"忽略文件夹: {ignore_folders}")
        print(f"忽略文件模式: {ignore_file_patterns}")
    
    # 收集所有文件信息和文件夹信息
    files_data = []
    file_contents = []
    folders_set = set()  # 记录所有文件夹（包括空文件夹）
    
    print(f"正在遍历文件夹: {folder_path}")
    if progress_callback:
        progress_callback(0, 0, "正在扫描文件...")
    
    # 先统计文件总数（用于进度显示，同时过滤忽略的文件）
    total_files = 0
    for root, dirs, files in os.walk(folder_path):
        root_path = Path(root).resolve()
        # 检查当前路径是否在忽略的文件夹中
        try:
            relative_folder = root_path.relative_to(folder_path)
            relative_folder_str = str(relative_folder).replace('\\', '/')
            if should_ignore_path(relative_folder_str, ignore_folders, ignore_file_patterns, is_file=False):
                # 跳过这个文件夹及其子文件夹
                dirs[:] = []  # 清空dirs列表，os.walk不会再进入子目录
                continue
        except ValueError:
            pass
        
        # 统计非忽略文件
        for file in files:
            file_path = root_path / file
            try:
                relative_path = file_path.relative_to(folder_path)
                relative_path_str = str(relative_path).replace('\\', '/')
                if not should_ignore_path(relative_path_str, ignore_folders, ignore_file_patterns, is_file=True):
                    total_files += 1
            except ValueError:
                pass
    
    if cancel_flag and cancel_flag.is_set():
        raise InterruptedError("操作已取消")
    
    print(f"找到 {total_files} 个文件，开始处理...")
    processed_files = 0
    
    # 遍历文件夹和子文件夹
    for root, dirs, files in os.walk(folder_path):
        root_path = Path(root).resolve()
        
        # 检查当前路径是否在忽略的文件夹中
        try:
            relative_folder = root_path.relative_to(folder_path)
            relative_folder_str = str(relative_folder).replace('\\', '/')
            if should_ignore_path(relative_folder_str, ignore_folders, ignore_file_patterns, is_file=False):
                # 跳过这个文件夹及其子文件夹
                dirs[:] = []  # 清空dirs列表，os.walk不会再进入子目录
                print(f"  跳过忽略的文件夹: {relative_folder_str}")
                continue
        except ValueError:
            pass
        
        # 记录当前文件夹（包括根文件夹本身）
        try:
            relative_folder = root_path.relative_to(folder_path)
            # 将文件夹路径添加到集合中（包括所有父文件夹）
            folder_parts = []
            for part in relative_folder.parts:
                # 检查文件夹名是否在忽略列表中
                if part in ignore_folders:
                    # 如果当前文件夹被忽略，不再继续添加父路径
                    break
                folder_parts.append(part)
                folder_path_str = '/'.join(folder_parts)
                folders_set.add(folder_path_str)
        except ValueError:
            # 如果无法计算相对路径，跳过
            pass
        
        # 处理文件
        for file in files:
            if cancel_flag and cancel_flag.is_set():
                raise InterruptedError("操作已取消")
            
            file_path = root_path / file
            
            try:
                # 计算相对路径
                try:
                    relative_path = file_path.relative_to(folder_path)
                except ValueError:
                    # 如果无法计算相对路径，使用绝对路径
                    relative_path = file_path
                
                relative_path_str = str(relative_path).replace('\\', '/')
                
                # 检查是否应该忽略此文件
                if should_ignore_path(relative_path_str, ignore_folders, ignore_file_patterns, is_file=True):
                    print(f"  跳过忽略的文件: {relative_path_str}")
                    continue
                
                # 以二进制方式读取文件
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                files_data.append({
                    'path': relative_path_str,  # 统一使用/分隔符
                    'size': len(content)
                })
                file_contents.append(content)
                
                # 确保文件的父文件夹也被记录
                if '/' in relative_path_str:
                    parent_folder = '/'.join(relative_path_str.split('/')[:-1])
                    # 检查父文件夹是否包含被忽略的文件夹
                    if not should_ignore_path(parent_folder, ignore_folders, ignore_file_patterns, is_file=False):
                        folders_set.add(parent_folder)
                
                processed_files += 1
                if progress_callback:
                    progress_callback(processed_files, total_files, f"正在读取: {relative_path}")
                
                print(f"  [{processed_files}/{total_files}] 已读取: {relative_path} ({len(content)} 字节)")
                
            except Exception as e:
                print(f"  警告: 无法读取文件 {file_path}: {e}")
                continue
    
    # 将文件夹集合转换为排序的列表（排除空字符串，因为根目录不需要单独记录）
    folders_list = sorted([f for f in folders_set if f])
    
    if cancel_flag and cancel_flag.is_set():
        raise InterruptedError("操作已取消")
    
    print(f"\n共找到 {len(files_data)} 个文件")
    print(f"共找到 {len(folders_list)} 个文件夹")
    print("正在压缩...")
    
    if progress_callback:
        progress_callback(0, 100, "正在构建文件结构...")
    
    # 构建文件结构数据
    structure = {
        'files': files_data,
        'file_count': len(files_data),
        'folders': folders_list,  # 保存所有文件夹信息
        'folder_count': len(folders_list)
    }
    structure_json = json.dumps(structure, ensure_ascii=False).encode('utf-8')
    
    # 将所有文件内容连接起来，每个文件前添加4字节的长度信息
    # 格式: [文件1长度(4字节)][文件1内容][文件2长度(4字节)][文件2内容]...
    if progress_callback:
        progress_callback(30, 100, "正在组织文件数据...")
    
    file_data_parts = []
    for i, content in enumerate(file_contents):
        if cancel_flag and cancel_flag.is_set():
            raise InterruptedError("操作已取消")
        # 写入文件长度（大端序，4字节）
        file_data_parts.append(struct.pack('>I', len(content)))
        # 写入文件内容
        file_data_parts.append(content)
        
        if progress_callback and (i + 1) % max(1, len(file_contents) // 10) == 0:
            progress_callback(30 + int((i + 1) / len(file_contents) * 30), 100, "正在组织文件数据...")
    
    all_content = b''.join(file_data_parts)
    
    # 组合结构信息和文件内容
    # 格式: [JSON长度(4字节)][JSON数据][文件数据]
    combined_data = struct.pack('>I', len(structure_json)) + structure_json + all_content
    
    if progress_callback:
        progress_callback(65, 100, "正在压缩数据...")
    
    # 使用gzip压缩
    compressed_data = gzip.compress(combined_data, compresslevel=9)
    
    if cancel_flag and cancel_flag.is_set():
        raise InterruptedError("操作已取消")
    
    if progress_callback:
        progress_callback(80, 100, "正在加密数据...")
    
    print("正在加密...")
    # 加密压缩后的数据
    encrypted_data, salt = encrypt_data(compressed_data, password)
    
    if cancel_flag and cancel_flag.is_set():
        raise InterruptedError("操作已取消")
    
    if progress_callback:
        progress_callback(90, 100, "正在写入文件...")
    
    # 写入fz文件
    # 文件格式: [salt长度(4字节)][salt][加密数据]
    with open(output_file, 'wb') as f:
        # 写入salt长度
        f.write(struct.pack('>I', len(salt)))
        # 写入salt
        f.write(salt)
        # 写入加密数据
        f.write(encrypted_data)
    
    print(f"压缩完成！输出文件: {output_file}")
    print(f"原始大小: {len(combined_data)} 字节")
    print(f"压缩后大小: {len(compressed_data)} 字节")
    print(f"加密后大小: {len(encrypted_data)} 字节")


# ==================== 解压功能 ====================

def decompress_fz(input_file: str, output_folder: str, password: str,
                  progress_callback=None, cancel_flag=None):
    """
    解压fz文件到指定文件夹
    
    Args:
        input_file: 输入的fz文件路径
        output_folder: 输出的文件夹路径
        password: 解密密码
        progress_callback: 进度回调函数 (current, total, status) -> None
        cancel_flag: 取消标志对象，检查 cancel_flag.is_set() 来判断是否取消
    """
    input_file = Path(input_file).resolve()
    if not input_file.exists():
        raise ValueError(f"文件不存在: {input_file}")
    
    output_folder = Path(output_folder).resolve()
    
    print(f"正在读取文件: {input_file}")
    
    if progress_callback:
        progress_callback(0, 100, "正在读取文件...")
    
    if cancel_flag and cancel_flag.is_set():
        raise InterruptedError("操作已取消")
    
    # 读取fz文件
    with open(input_file, 'rb') as f:
        # 读取salt长度
        salt_length = struct.unpack('>I', f.read(4))[0]
        # 读取salt
        salt = f.read(salt_length)
        # 读取加密数据
        encrypted_data = f.read()
    
    if progress_callback:
        progress_callback(20, 100, "正在解密数据...")
    
    print("正在解密...")
    # 解密数据
    try:
        compressed_data = decrypt_data(encrypted_data, password, salt)
    except Exception as e:
        raise ValueError(f"解密失败，密码可能错误: {e}")
    
    if cancel_flag and cancel_flag.is_set():
        raise InterruptedError("操作已取消")
    
    if progress_callback:
        progress_callback(30, 100, "正在解压数据...")
    
    print("正在解压...")
    # 解压数据
    combined_data = gzip.decompress(compressed_data)
    
    if cancel_flag and cancel_flag.is_set():
        raise InterruptedError("操作已取消")
    
    # 解析文件格式: [JSON长度(4字节)][JSON数据][文件数据]
    if len(combined_data) < 4:
        raise ValueError("文件格式错误：数据太短")
    
    # 读取JSON长度
    json_length = struct.unpack('>I', combined_data[:4])[0]
    
    # 读取JSON数据
    if len(combined_data) < 4 + json_length:
        raise ValueError("文件格式错误：JSON数据不完整")
    
    structure_json = combined_data[4:4+json_length].decode('utf-8')
    structure = json.loads(structure_json)
    
    if progress_callback:
        progress_callback(40, 100, "正在解析文件结构...")
    
    # 获取文件内容部分
    file_contents_data = combined_data[4+json_length:]
    files_info = structure['files']
    total_files = len(files_info)
    
    # 按照文件大小逐个读取文件内容
    file_contents = []
    offset = 0
    for i, file_info in enumerate(files_info):
        if cancel_flag and cancel_flag.is_set():
            raise InterruptedError("操作已取消")
        if offset + 4 > len(file_contents_data):
            raise ValueError(f"文件格式错误：无法读取文件 {file_info['path']} 的长度")
        
        # 读取文件长度
        file_size = struct.unpack('>I', file_contents_data[offset:offset+4])[0]
        offset += 4
        
        if offset + file_size > len(file_contents_data):
            raise ValueError(f"文件格式错误：文件 {file_info['path']} 的数据不完整")
        
        # 读取文件内容
        file_content = file_contents_data[offset:offset+file_size]
        offset += file_size
        
        file_contents.append(file_content)
        
        if progress_callback:
            progress_val = 50 + int((i + 1) / total_files * 40)
            progress_callback(progress_val, 100, f"正在解析文件: {file_info['path']}")
    
    if offset != len(file_contents_data):
        raise ValueError(f"文件格式错误：数据长度不匹配，预期 {offset} 字节，实际 {len(file_contents_data)} 字节")
    
    if len(file_contents) != len(files_info):
        raise ValueError(f"文件数量不匹配: 结构中有{len(files_info)}个文件，但数据中有{len(file_contents)}个文件")
    
    # 获取文件夹信息（向后兼容，如果旧版本没有folders字段）
    folders_info = structure.get('folders', [])
    
    print(f"找到 {len(files_info)} 个文件")
    print(f"找到 {len(folders_info)} 个文件夹")
    print(f"正在解压到: {output_folder}")
    
    # 创建输出文件夹
    output_folder.mkdir(parents=True, exist_ok=True)
    
    # 先创建所有文件夹（包括空文件夹）
    for folder_path_str in folders_info:
        folder_path = output_folder / folder_path_str
        try:
            folder_path.mkdir(parents=True, exist_ok=True)
            print(f"  已创建文件夹: {folder_path_str}")
        except Exception as e:
            print(f"  警告: 无法创建文件夹 {folder_path_str}: {e}")
    
    # 解压所有文件
    for i, (file_info, content) in enumerate(zip(files_info, file_contents)):
        if cancel_flag and cancel_flag.is_set():
            raise InterruptedError("操作已取消")
        
        file_path = output_folder / file_info['path']
        
        # 创建父目录（双重保险，即使文件夹已创建也要确保）
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入文件
        with open(file_path, 'wb') as f:
            f.write(content)
        
        # 验证文件大小
        if len(content) != file_info['size']:
            print(f"  警告: 文件 {file_info['path']} 大小不匹配")
        
        if progress_callback:
            progress_val = 90 + int((i + 1) / len(files_info) * 10)
            progress_callback(progress_val, 100, f"正在解压: {file_info['path']}")
        
        print(f"  [{i+1}/{len(files_info)}] 已解压: {file_info['path']} ({len(content)} 字节)")
    
    print(f"\n解压完成！输出文件夹: {output_folder}")


# ==================== GUI界面 ====================

class FolderZipGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("文件夹压缩加密工具")
        self.root.geometry("650x260")
        
        # 创建主框架（减少内边距）
        self.main_frame = ttk.Frame(root, padding="5")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        
        # 取消标志
        self.cancel_flag = threading.Event()
        self.worker_thread = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """设置UI界面"""
        
        # 创建主内容框架
        content_frame = ttk.Frame(self.main_frame, padding="8")
        content_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.main_frame.rowconfigure(1, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        
        # 设置压缩和解压UI在同一界面
        self.setup_unified_ui(content_frame)
    
    def setup_unified_ui(self, parent):
        """设置合并的UI界面（根据模式切换）"""
        # 配置列权重
        parent.columnconfigure(1, weight=1)
        
        row = 0
        
        # 模式选择（单选框）
        
        ttk.Label(parent, text="模式:", font=("Arial", 9)).grid(row=row, column=0, sticky=tk.W, pady=(0, 5), padx=(0, 5))
        self.mode = tk.StringVar(value="compress")
        mode_frame = ttk.Frame(parent)
        mode_frame.grid(row=row, column=1, columnspan=3, sticky=tk.W, pady=(0, 5))
        ttk.Radiobutton(mode_frame, text="压缩加密", variable=self.mode, value="compress",
                        command=self.on_mode_change).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="解密解压", variable=self.mode, value="decompress",
                        command=self.on_mode_change).pack(side=tk.LEFT, padx=5)
        row += 1
        
        # === 输入路径（根据模式变化） ===
        self.input_label = ttk.Label(parent, text="选择文件夹:", font=("Arial", 9))
        self.input_label.grid(row=row, column=0, sticky=tk.W, pady=(0, 5), padx=(0, 5))
        self.input_path = tk.StringVar()
        self.input_entry = ttk.Entry(parent, textvariable=self.input_path, width=40, font=("Arial", 9))
        self.input_entry.grid(row=row, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(0, 5))
        self.input_button = ttk.Button(parent, text="浏览", command=self.browse_input, width=8)
        self.input_button.grid(row=row, column=2, pady=(0, 5))
        row += 1
        
        # === 输出路径（根据模式变化） ===
        self.output_label = ttk.Label(parent, text="输出文件:", font=("Arial", 9))
        self.output_label.grid(row=row, column=0, sticky=tk.W, pady=(0, 5), padx=(0, 5))
        self.output_path = tk.StringVar()
        self.output_entry = ttk.Entry(parent, textvariable=self.output_path, width=40, font=("Arial", 9))
        self.output_entry.grid(row=row, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(0, 5))
        self.output_button = ttk.Button(parent, text="浏览", command=self.browse_output, width=8)
        self.output_button.grid(row=row, column=2, pady=(0, 5))
        row += 1
        
        # === 密码输入（合并） ===
        ttk.Label(parent, text="密码:", font=("Arial", 9)).grid(row=row, column=0, sticky=tk.W,pady=(0, 5), padx=(0, 5))
        self.password = tk.StringVar()
        self.password_entry = ttk.Entry(parent, textvariable=self.password, show="*", width=40, font=("Arial", 9))
        self.password_entry.grid(row=row, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(0, 5))
        # 绑定密码输入事件，实时显示密码强度
        self.password.trace_add("write", lambda *args: self.update_password_strength())
        row += 1
        
        # === 密码强度提示（仅在压缩模式下显示） ===
        self.password_hint = ttk.Label(
            parent, 
            text="要求:长度>12，含大小写字母+数字+特殊字符",
            font=("Arial", 7),
            foreground="gray"
        )
        self.password_strength_label = ttk.Label(parent, text="", font=("Arial", 8))
        # 默认显示，在解压模式下隐藏
        self.password_hint.grid(row=row, column=1, sticky=tk.W, padx=(0, 5), pady=2)
        self.password_strength_label.grid(row=row, column=1, sticky=tk.E, padx=(0, 5), pady=2)
        row += 1
        
        # === 忽略规则配置（仅在压缩模式下显示） ===
        ttk.Label(parent, text="忽略规则:", font=("Arial", 9)).grid(row=row, column=0, sticky=tk.W, pady=(0, 0), padx=(0, 5))
        self.ignore_patterns = tk.StringVar()
        self.ignore_patterns.set("logs,*.pdb,obj,build,bin,out,temp,cache,logs,__pycache__,*.log,*.log.*")
        self.ignore_entry = ttk.Entry(parent, textvariable=self.ignore_patterns, width=40, font=("Arial", 9))
        self.ignore_entry.grid(row=row, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(0, 0))
        ttk.Label(parent, text="如: logs,*.pdb", font=("Arial", 7), foreground="gray").grid(row=row, column=2, sticky=tk.W, padx=(0, 5), pady=(0, 0))
        row += 1
        
        # === 状态标签 ===
        self.status_label = ttk.Label(parent, text="", font=("Arial", 8), foreground="gray")
        self.status_label.grid(row=row, column=1, sticky=tk.W, padx=(0, 5), pady=(0, 2))
        row += 1
        
        # === 进度条（确定型） ===
        self.progress = ttk.Progressbar(
            parent, 
            mode='determinate',
            length=300
        )
        self.progress.grid(row=row, column=1, pady=(0, 0),padx=(0, 5), sticky=(tk.W, tk.E))
        
        # === 进度百分比标签 ===
        self.progress_label = ttk.Label(parent, text="", font=("Arial", 8))
        self.progress_label.grid(row=row, column=2, padx=(5, 0), pady=(0, 0))
        row += 1

        # === 按钮框架 ===
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=row, column=0, columnspan=3, pady=(0, 5))
        
        # === 执行按钮（合并） ===
        self.execute_button = ttk.Button(
            button_frame, 
            text="开始执行", 
            command=self.execute_action
        )
        self.execute_button.pack(side=tk.LEFT, padx=(0, 5),pady=(5, 0))
        
        # === 取消按钮 ===
        self.cancel_button = ttk.Button(
            button_frame,
            text="取消",
            command=self.cancel_action,
            state='disabled'
        )
        self.cancel_button.pack(side=tk.LEFT,pady=(5, 0))
        row += 1
        
        # 初始化UI状态
        self.on_mode_change()
    
    def setup_compress_tab(self, parent):
        """设置压缩标签页（已弃用，保留用于兼容）"""
        pass
    
    def setup_decompress_tab(self, parent):
        """设置解压标签页（已弃用，保留用于兼容）"""
        pass
    
    def on_mode_change(self):
        """模式切换时的UI更新"""
        mode = self.mode.get()
        
        if mode == "compress":
            # 压缩模式
            self.input_label.config(text="选择文件夹:")
            self.input_button.config(command=self.browse_input_folder)
            self.output_label.config(text="输出文件:")
            self.output_button.config(command=self.browse_output_file)
            #self.execute_button.config(text="开始压缩加密")
            
            # 显示密码强度提示
            #self.password_hint.grid()
            self.password_strength_label.grid()
            # 显示忽略规则输入框
            self.ignore_entry.grid()
        else:
            # 解压模式
            self.input_label.config(text="选择fz文件:")
            self.input_button.config(command=self.browse_input_file)
            self.output_label.config(text="输出文件夹:")
            self.output_button.config(command=self.browse_output_folder)
            #self.execute_button.config(text="开始解密解压")
            
            # 隐藏密码强度提示
            #self.password_hint.grid_remove()
            self.password_strength_label.grid_remove()
            # 隐藏忽略规则输入框
            self.ignore_entry.grid_remove()
    
    def browse_input_folder(self):
        """浏览选择文件夹（压缩模式）"""
        folder = filedialog.askdirectory(title="选择要压缩的文件夹")
        if folder:
            self.input_path.set(folder)
            # 自动设置输出文件名
            if not self.output_path.get():
                folder_name = os.path.basename(folder)
                default_file = os.path.join(folder, f"{folder_name}.fz")
                self.output_path.set(default_file)
    
    def browse_input_file(self):
        """浏览选择fz文件（解压模式）"""
        filename = filedialog.askopenfilename(
            title="选择fz文件",
            filetypes=[("FZ文件", "*.fz"), ("所有文件", "*.*")]
        )
        if filename:
            self.input_path.set(filename)
            # 自动设置输出文件夹（在目标文件夹中创建新文件夹）
            if not self.output_path.get():
                base_name = os.path.splitext(os.path.basename(filename))[0]
                parent_dir = os.path.dirname(filename)
                # 在父目录中创建一个新的文件夹
                default_folder = os.path.join(parent_dir, f"{base_name}_extracted")
                self.output_path.set(default_folder)
    
    def browse_input(self):
        """统一的输入浏览方法（根据模式调用不同方法）"""
        if self.mode.get() == "compress":
            self.browse_input_folder()
        else:
            self.browse_input_file()
    
    def browse_output_file(self):
        """浏览选择输出文件（压缩模式）"""
        filename = filedialog.asksaveasfilename(
            title="保存为",
            defaultextension=".fz",
            filetypes=[("FZ文件", "*.fz"), ("所有文件", "*.*")]
        )
        if filename:
            self.output_path.set(filename)
    
    def browse_output_folder(self):
        """浏览选择输出文件夹（解压模式，会在该文件夹中创建新文件夹）"""
        folder = filedialog.askdirectory(title="选择输出目录（将在其中创建新文件夹）")
        if folder:
            # 如果已经有输入文件，使用输入文件名作为新文件夹名
            input_file = self.input_path.get()
            if input_file:
                base_name = os.path.splitext(os.path.basename(input_file))[0]
                new_folder = os.path.join(folder, f"{base_name}_extracted")
            else:
                # 否则使用默认名称
                new_folder = os.path.join(folder, "extracted")
            self.output_path.set(new_folder)
    
    def browse_output(self):
        """统一的输出浏览方法（根据模式调用不同方法）"""
        if self.mode.get() == "compress":
            self.browse_output_file()
        else:
            self.browse_output_folder()
    
    def validate_password(self, password):
        """
        验证密码强度
        
        要求:
        - 长度大于12
        - 包含大写字母
        - 包含小写字母
        - 包含数字
        - 包含特殊字符
        """
        if len(password) <= 12:
            return False, "密码长度必须大于12个字符"
        
        if not re.search(r'[A-Z]', password):
            return False, "密码必须包含至少一个大写字母"
        
        if not re.search(r'[a-z]', password):
            return False, "密码必须包含至少一个小写字母"
        
        if not re.search(r'\d', password):
            return False, "密码必须包含至少一个数字"
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
            return False, "密码必须包含至少一个特殊字符"
        
        return True, "密码强度合格"
    
    def update_password_strength(self):
        """更新密码强度显示（仅在压缩模式下）"""
        if self.mode.get() != "compress":
            return
        
        password = self.password.get()
        if not password:
            self.password_strength_label.config(text="", foreground="")
            return
        
        is_valid, message = self.validate_password(password)
        if is_valid:
            self.password_strength_label.config(text="[OK] 密码强度合格", foreground="green")
        else:
            self.password_strength_label.config(text=f"[!] {message}", foreground="red")
    
    def validate_inputs(self):
        """验证输入（根据模式）"""
        mode = self.mode.get()
        
        if mode == "compress":
            # 压缩模式验证
            if not self.input_path.get():
                messagebox.showerror("错误", "请选择要压缩的文件夹")
                return False
            
            if not os.path.exists(self.input_path.get()):
                messagebox.showerror("错误", "选择的文件夹不存在")
                return False
            
            if not self.output_path.get():
                messagebox.showerror("错误", "请指定输出文件")
                return False
            
            password = self.password.get()
            if not password:
                messagebox.showerror("错误", "请输入加密密码")
                return False
            
            # 验证密码强度
            is_valid, message = self.validate_password(password)
            if not is_valid:
                result = messagebox.askyesno(
                    "密码强度不符合要求",
                    f"{message}\n\n是否仍要继续使用此密码？\n（强烈建议使用强密码以确保安全）",
                    icon='warning'
                )
                if not result:
                    return False
            
            return True
        else:
            # 解压模式验证
            if not self.input_path.get():
                messagebox.showerror("错误", "请选择fz文件")
                return False
            
            if not os.path.exists(self.input_path.get()):
                messagebox.showerror("错误", "选择的文件不存在")
                return False
            
            if not self.output_path.get():
                messagebox.showerror("错误", "请指定输出文件夹")
                return False
            
            if not self.password.get():
                messagebox.showerror("错误", "请输入解密密码")
                return False
            
            return True
    
    def cancel_action(self):
        """取消当前操作"""
        if self.worker_thread and self.worker_thread.is_alive():
            self.cancel_flag.set()
            self.status_label.config(text="正在取消操作...", foreground="orange")
            self.cancel_button.config(state='disabled')
    
    def update_progress(self, current, total, status=""):
        """更新进度条（线程安全）"""
        def update():
            if total > 0:
                percentage = int((current / total) * 100)
                self.progress['value'] = percentage
                self.progress_label.config(text=f"{percentage}%")
            else:
                self.progress['value'] = current
            
            if status:
                self.status_label.config(text=status, foreground="black")
        
        self.root.after(0, update)
    
    def execute_action(self):
        """执行操作（根据模式执行压缩或解压）"""
        if not self.validate_inputs():
            return
        
        mode = self.mode.get()
        self.execute_button.config(state='disabled')
        self.cancel_button.config(state='normal')
        self.cancel_flag.clear()
        
        # 重置进度条
        self.progress['value'] = 0
        self.progress_label.config(text="0%")
        self.status_label.config(text="准备开始...", foreground="black")
        
        if mode == "compress":
            print("=" * 60)
            print("开始压缩加密...")
            
            def compress_thread():
                try:
                    folder_path = self.input_path.get()
                    output_file = self.output_path.get()
                    password = self.password.get()
                    ignore_patterns = self.ignore_patterns.get()
                    
                    compress_folder(
                        folder_path, 
                        output_file, 
                        password,
                        progress_callback=self.update_progress,
                        cancel_flag=self.cancel_flag,
                        ignore_patterns=ignore_patterns
                    )
                    
                    if not self.cancel_flag.is_set():
                        self.root.after(0, lambda: self.action_success(output_file, "压缩"))
                except InterruptedError:
                    self.root.after(0, lambda: self.action_cancelled("压缩"))
                except Exception as e:
                    print(f"压缩失败: {e}")
                    self.root.after(0, lambda: self.action_failed(str(e), "压缩"))
            
            self.worker_thread = threading.Thread(target=compress_thread, daemon=True)
            self.worker_thread.start()
        else:
            print("=" * 60)
            print("开始解密解压...")
            
            def decompress_thread():
                try:
                    input_file = self.input_path.get()
                    output_path_str = self.output_path.get()
                    password = self.password.get()
                    
                    # 确保输出路径是在目标目录中新建的文件夹
                    output_path = Path(output_path_str)
                    parent_dir = output_path.parent
                    
                    # 如果父目录存在且输出路径已存在且不为空，创建带时间戳的新文件夹
                    if parent_dir.exists() and output_path.exists() and output_path.is_dir():
                        if any(output_path.iterdir()):
                            # 文件夹已存在且不为空，创建新文件夹
                            from datetime import datetime
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            input_base = os.path.splitext(os.path.basename(input_file))[0]
                            output_folder = parent_dir / f"{input_base}_extracted_{timestamp}"
                            print(f"目标文件夹已存在且不为空，创建新文件夹: {output_folder}")
                        else:
                            # 文件夹为空，可以使用
                            output_folder = output_path
                    elif parent_dir.exists():
                        # 父目录存在，输出路径不存在，会创建新文件夹
                        output_folder = output_path
                        print(f"将在父目录中创建新文件夹: {output_folder}")
                    else:
                        # 父目录不存在，创建它
                        parent_dir.mkdir(parents=True, exist_ok=True)
                        output_folder = output_path
                        print(f"已创建父目录，将在其中创建新文件夹: {output_folder}")
                    
                    decompress_fz(
                        input_file, 
                        str(output_folder), 
                        password,
                        progress_callback=self.update_progress,
                        cancel_flag=self.cancel_flag
                    )
                    
                    if not self.cancel_flag.is_set():
                        self.root.after(0, lambda: self.action_success(str(output_folder), "解压"))
                except InterruptedError:
                    self.root.after(0, lambda: self.action_cancelled("解压"))
                except Exception as e:
                    print(f"解压失败: {e}")
                    self.root.after(0, lambda: self.action_failed(str(e), "解压"))
            
            self.worker_thread = threading.Thread(target=decompress_thread, daemon=True)
            self.worker_thread.start()
    
    def action_success(self, output_path, action_name):
        """操作成功"""
        self.progress['value'] = 100
        self.progress_label.config(text="100%")
        self.status_label.config(text=f"{action_name}完成！", foreground="green")
        self.execute_button.config(state='normal')
        self.cancel_button.config(state='disabled')
        print(f"{action_name}完成！输出: {output_path}")
        messagebox.showinfo("成功", f"{action_name}完成！\n输出: {output_path}")
    
    def action_failed(self, error_msg, action_name):
        """操作失败"""
        self.progress['value'] = 0
        self.progress_label.config(text="0%")
        self.status_label.config(text=f"{action_name}失败", foreground="red")
        self.execute_button.config(state='normal')
        self.cancel_button.config(state='disabled')
        print(f"{action_name}失败: {error_msg}")
        messagebox.showerror("错误", f"{action_name}失败:\n{error_msg}")
    
    def action_cancelled(self, action_name):
        """操作已取消"""
        self.progress['value'] = 0
        self.progress_label.config(text="0%")
        self.status_label.config(text=f"{action_name}已取消", foreground="orange")
        self.execute_button.config(state='normal')
        self.cancel_button.config(state='disabled')
        print(f"{action_name}已取消")
        messagebox.showinfo("提示", f"{action_name}操作已取消")


def main():
    """主函数"""
    root = tk.Tk()
    app = FolderZipGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()

