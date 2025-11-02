# -*- coding: utf-8 -*-
"""
Git上传客户端 - 图形界面
支持GitHub和Gitee平台的代码提交功能
"""
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path
import json

# 导入我们的git上传模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from gitUpload import upload_file_to_git, upload_folder_to_git, get_client_factory, list_user_repos, test_user_token, list_repo_branches


class GitUploadGUI:
    """
    Git上传客户端的图形界面类
    """
    
    def __init__(self, root):
        """
        初始化GUI界面
        
        Args:
            root: Tkinter根窗口
        """
        self.root = root
        self.root.title("Git上传客户端")
        self.root.geometry("750x600")
        self.root.resizable(True, True)
        
        # 设置中文字体支持
        self._set_fonts()
        
        # 创建主题样式
        self.style = ttk.Style()
        self._setup_style()
        
        # 上传任务状态
        self.upload_thread = None
        self.cancel_event = threading.Event()
        
        # 创建界面
        self._create_widgets()
        
        # 加载配置
        self._load_config()
    
    def _set_fonts(self):
        """
        设置中文字体
        """
        # 尝试设置中文字体，确保中文显示正常
        try:
            # Windows系统
            if sys.platform.startswith('win'):
                self.default_font = ('微软雅黑', 10)
                self.title_font = ('微软雅黑', 12, 'bold')
            # macOS系统
            elif sys.platform == 'darwin':
                self.default_font = ('PingFang SC', 10)
                self.title_font = ('PingFang SC', 12, 'bold')
            # Linux系统
            else:
                self.default_font = ('SimHei', 10)
                self.title_font = ('SimHei', 12, 'bold')
        except:
            # 回退到默认字体
            self.default_font = ('Arial', 10)
            self.title_font = ('Arial', 12, 'bold')
    
    def _setup_style(self):
        """
        设置界面样式
        """
        try:
            # 使用ttk主题
            self.style.theme_use('clam')
            
            # 配置各种控件样式
            self.style.configure('TLabel', font=self.default_font)
            self.style.configure('TButton', font=self.default_font)
            self.style.configure('TEntry', font=self.default_font)
            self.style.configure('TCombobox', font=self.default_font)
            self.style.configure('TRadiobutton', font=self.default_font)
            
            # 设置标题标签样式
            self.style.configure('Title.TLabel', font=self.title_font, foreground='#2c3e50')
            
            # 设置按钮样式
            self.style.configure('Primary.TButton', foreground='#ffffff', background='#3498db')
            self.style.map('Primary.TButton', background=[('active', '#2980b9')])
            
            self.style.configure('Danger.TButton', foreground='#ffffff', background='#e74c3c')
            self.style.map('Danger.TButton', background=[('active', '#c0392b')])
            
            self.style.configure('Success.TButton', foreground='#ffffff', background='#2ecc71')
            self.style.map('Success.TButton', background=[('active', '#27ae60')])
        except:
            # 如果主题设置失败，忽略错误
            pass
    
    def _create_widgets(self):
        """
        创建所有GUI控件
        """
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 1. 平台选择区域
        self._create_platform_section(main_frame)
        
        # 2. 认证信息区域
        self._create_auth_section(main_frame)
        
        # 3. 仓库信息区域
        self._create_repo_section(main_frame)
        
        # 4. 上传选项区域
        self._create_upload_section(main_frame)
        
        # 5. 日志输出区域
        self._create_log_section(main_frame)
        
        # 6. 按钮区域
        self._create_button_section(main_frame)
    
    def _create_platform_section(self, parent):
        """
        创建平台选择区域
        """
        section = ttk.LabelFrame(parent, text="平台选择", padding=10)
        section.pack(fill=tk.X, pady=(0, 15))
        
        # 平台选择
        self.platform_var = tk.StringVar(value="github")
        
        github_radio = ttk.Radiobutton(
            section, text="GitHub", variable=self.platform_var, value="github",
            command=self._on_platform_change
        )
        github_radio.pack(side=tk.LEFT, padx=10)
        
        gitee_radio = ttk.Radiobutton(
            section, text="Gitee", variable=self.platform_var, value="gitee",
            command=self._on_platform_change
        )
        gitee_radio.pack(side=tk.LEFT, padx=10)
    
    def _create_auth_section(self, parent):
        """
        创建认证信息区域
        """
        section = ttk.LabelFrame(parent, text="认证信息", padding=10)
        section.pack(fill=tk.X, pady=(0, 15))
        
        # 用户名
        ttk.Label(section, text="用户名:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(section, width=40)
        self.username_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        # 访问令牌
        ttk.Label(section, text="访问令牌:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.token_frame = ttk.Frame(section)
        self.token_frame.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        self.token_var = tk.StringVar()
        self.token_entry = ttk.Entry(self.token_frame, width=35, textvariable=self.token_var, show="*")
        self.token_entry.pack(side=tk.LEFT)
        
        # 测试令牌按钮
        self.test_token_button = ttk.Button(
            self.token_frame, text="测试", command=self._test_token,
            width=8
        )
        self.test_token_button.pack(side=tk.LEFT, padx=(5, 0))
        
        # 显示/隐藏令牌按钮
        self.show_token_var = tk.BooleanVar(value=False)
        self.toggle_token_button = ttk.Checkbutton(
            section, text="显示令牌", variable=self.show_token_var,
            command=self._toggle_token_visibility
        )
        self.toggle_token_button.grid(row=1, column=2, sticky=tk.W, padx=5)
    
    def _create_repo_section(self, parent):
        """
        创建仓库信息区域
        """
        section = ttk.LabelFrame(parent, text="仓库信息", padding=10)
        section.pack(fill=tk.X, pady=(0, 15))
        
        # 仓库名称（改为下拉框）
        ttk.Label(section, text="仓库名:").grid(row=0, column=0, sticky=tk.W, pady=5)
        repo_frame = ttk.Frame(section)
        repo_frame.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        self.repo_var = tk.StringVar()
        self.repo_combo = ttk.Combobox(repo_frame, textvariable=self.repo_var, width=37, state='normal')
        self.repo_combo.pack(side=tk.LEFT)
        
        # 获取仓库按钮
        self.fetch_repos_button = ttk.Button(
            repo_frame, text="获取仓库", command=self._fetch_repos,
            width=10
        )
        self.fetch_repos_button.pack(side=tk.LEFT, padx=(5, 0))
        
        # 分支名称（改为下拉框）
        ttk.Label(section, text="分支名:").grid(row=1, column=0, sticky=tk.W, pady=5)
        branch_frame = ttk.Frame(section)
        branch_frame.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        self.branch_var = tk.StringVar(value="main")  # 默认GitHub分支
        self.branch_combo = ttk.Combobox(branch_frame, textvariable=self.branch_var, width=37, state='normal')
        self.branch_combo.pack(side=tk.LEFT)
        
        # 获取分支按钮
        self.fetch_branches_button = ttk.Button(
            branch_frame, text="获取分支", command=self._fetch_branches,
            width=10
        )
        self.fetch_branches_button.pack(side=tk.LEFT, padx=(5, 0))
        
        # 测试连接按钮
        self.test_conn_button = ttk.Button(
            section, text="测试连接", command=self._test_connection,
            style="Primary.TButton"
        )
        self.test_conn_button.grid(row=1, column=2, sticky=tk.W, padx=5)
    
    def _create_upload_section(self, parent):
        """
        创建上传选项区域
        """
        section = ttk.LabelFrame(parent, text="上传选项", padding=10)
        section.pack(fill=tk.X, pady=(0, 15))
        
        # 上传类型选择
        self.upload_type_var = tk.StringVar(value="file")
        
        file_radio = ttk.Radiobutton(
            section, text="上传文件", variable=self.upload_type_var, value="file",
            command=self._on_upload_type_change
        )
        file_radio.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        folder_radio = ttk.Radiobutton(
            section, text="上传文件夹", variable=self.upload_type_var, value="folder",
            command=self._on_upload_type_change
        )
        folder_radio.grid(row=0, column=1, sticky=tk.W, pady=5, padx=10)
        
        # 本地路径
        ttk.Label(section, text="本地路径:").grid(row=1, column=0, sticky=tk.W, pady=5)
        path_frame = ttk.Frame(section)
        path_frame.grid(row=1, column=1, sticky=tk.W+tk.E, pady=5, padx=5, columnspan=2)
        
        self.local_path_var = tk.StringVar()
        self.local_path_entry = ttk.Entry(path_frame, width=50, textvariable=self.local_path_var)
        self.local_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.browse_button = ttk.Button(
            path_frame, text="浏览...", command=self._browse_path,
            width=10
        )
        self.browse_button.pack(side=tk.LEFT, padx=5)
        
        # 远程路径
        ttk.Label(section, text="远程路径:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.git_path_var = tk.StringVar()
        self.git_path_entry = ttk.Entry(section, width=50, textvariable=self.git_path_var)
        self.git_path_entry.grid(row=2, column=1, sticky=tk.W+tk.E, pady=5, padx=5, columnspan=2)
        
        # 提交信息
        ttk.Label(section, text="提交信息:").grid(row=3, column=0, sticky=tk.NW, pady=5)
        self.message_text = scrolledtext.ScrolledText(section, width=50, height=3, wrap=tk.WORD)
        self.message_text.grid(row=3, column=1, sticky=tk.W+tk.E+tk.N+tk.S, pady=5, padx=5, columnspan=2)
        self.message_text.insert(tk.END, "上传文件")
    
    def _create_log_section(self, parent):
        """
        创建日志输出区域
        """
        section = ttk.LabelFrame(parent, text="操作日志", padding=10)
        section.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(section, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
    
    def _create_button_section(self, parent):
        """
        创建按钮区域
        """
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 左侧按钮
        left_frame = ttk.Frame(button_frame)
        left_frame.pack(side=tk.LEFT)
        
        # 保存配置按钮
        self.save_config_button = ttk.Button(
            left_frame, text="保存配置", command=self._save_config,
            style="Primary.TButton"
        )
        self.save_config_button.pack(side=tk.LEFT, padx=5)
        
        # 右侧按钮
        right_frame = ttk.Frame(button_frame)
        right_frame.pack(side=tk.RIGHT)
        
        # 取消按钮
        self.cancel_button = ttk.Button(
            right_frame, text="取消", command=self._cancel_upload,
            style="Danger.TButton", state=tk.DISABLED
        )
        self.cancel_button.pack(side=tk.RIGHT, padx=5)
        
        # 上传按钮
        self.upload_button = ttk.Button(
            right_frame, text="开始上传", command=self._start_upload,
            style="Success.TButton"
        )
        self.upload_button.pack(side=tk.RIGHT, padx=5)
    
    def _on_platform_change(self):
        """
        当平台选择改变时更新默认分支
        """
        if self.platform_var.get() == "github":
            self.branch_var.set("main")
        else:  # gitee
            self.branch_var.set("master")
    
    def _toggle_token_visibility(self):
        """
        切换令牌显示/隐藏
        """
        if self.show_token_var.get():
            self.token_entry.config(show="")
        else:
            self.token_entry.config(show="*")
    
    def _test_token(self):
        """
        测试令牌和用户名是否有效
        """
        # 获取输入信息
        platform = self.platform_var.get()
        token = self.token_var.get()
        username = self.username_entry.get()
        
        # 验证输入
        if not token:
            messagebox.showerror("错误", "请输入访问令牌")
            return
        
        if not username:
            messagebox.showerror("错误", "请输入用户名")
            return
        
        # 清空日志
        self._clear_log()
        self._append_log(f"正在测试 {platform} 令牌和用户名...")
        
        # 禁用按钮
        self.test_token_button.config(state=tk.DISABLED)
        
        # 在单独线程中测试令牌
        def test_token_thread():
            try:
                user_info = test_user_token(platform, token, username)
                
                # 显示成功信息
                self._append_log(f"✅ 令牌和用户名验证成功！")
                self._append_log(f"  - 用户名: {user_info.get('login', user_info.get('name', ''))}")
                self._append_log(f"  - 显示名称: {user_info.get('name', '无')}")
                
                # 如果返回的用户名与输入不一致，给出提示
                api_username = user_info.get('login', '')
                if api_username and api_username.lower() != username.lower():
                    self._append_log(f"  ⚠️  注意: API返回的用户名是 '{api_username}'，与输入不一致")
                
                messagebox.showinfo("验证成功", f"令牌和用户名验证成功！\n用户名: {api_username or username}")
                
            except Exception as e:
                error_msg = str(e)
                self._append_log(f"❌ 验证失败: {error_msg}")
                messagebox.showerror("验证失败", f"令牌或用户名无效:\n{error_msg}")
            finally:
                # 恢复按钮状态
                self.root.after(0, lambda: self.test_token_button.config(state=tk.NORMAL))
        
        # 启动线程
        threading.Thread(target=test_token_thread, daemon=True).start()
    
    def _fetch_repos(self):
        """
        获取用户的所有仓库列表
        """
        # 获取输入信息
        platform = self.platform_var.get()
        token = self.token_var.get()
        username = self.username_entry.get()
        
        # 验证输入
        if not token:
            messagebox.showerror("错误", "请输入访问令牌")
            return
        
        if not username:
            messagebox.showerror("错误", "请输入用户名")
            return
        
        # 清空日志
        self._clear_log()
        self._append_log(f"正在获取 {platform} 仓库列表...")
        
        # 禁用按钮
        self.fetch_repos_button.config(state=tk.DISABLED)
        
        # 在单独线程中获取仓库列表
        def fetch_repos_thread():
            try:
                repos = list_user_repos(platform, token, username)
                
                if not repos:
                    self._append_log("⚠️  未找到任何仓库")
                    messagebox.showinfo("提示", "未找到任何仓库")
                    return
                
                # 提取仓库名称
                repo_names = []
                for repo in repos:
                    repo_name = repo.get('name', '')
                    if repo_name:
                        repo_names.append(repo_name)
                
                # 更新下拉框
                self.root.after(0, lambda: self._update_repo_combo(repo_names))
                
                # 显示成功信息
                self._append_log(f"✅ 成功获取 {len(repo_names)} 个仓库")
                self._append_log(f"  仓库列表已更新到下拉框中")
                
            except Exception as e:
                error_msg = str(e)
                self._append_log(f"❌ 获取仓库列表失败: {error_msg}")
                messagebox.showerror("错误", f"获取仓库列表失败:\n{error_msg}")
            finally:
                # 恢复按钮状态
                self.root.after(0, lambda: self.fetch_repos_button.config(state=tk.NORMAL))
        
        # 启动线程
        threading.Thread(target=fetch_repos_thread, daemon=True).start()
    
    def _update_repo_combo(self, repo_names):
        """
        更新仓库下拉框的值
        
        Args:
            repo_names: 仓库名称列表
        """
        self.repo_combo['values'] = repo_names
        if repo_names and not self.repo_var.get():
            # 如果当前没有选中值，默认选择第一个
            self.repo_var.set(repo_names[0])
    
    def _fetch_branches(self):
        """
        获取仓库的所有分支列表
        """
        # 获取输入信息
        platform = self.platform_var.get()
        token = self.token_var.get()
        username = self.username_entry.get()
        repo = self.repo_var.get()
        
        # 验证输入
        if not token:
            messagebox.showerror("错误", "请输入访问令牌")
            return
        
        if not username:
            messagebox.showerror("错误", "请输入用户名")
            return
        
        if not repo:
            messagebox.showerror("错误", "请先选择或输入仓库名")
            return
        
        # 清空日志
        self._clear_log()
        self._append_log(f"正在获取 {platform} 仓库 '{repo}' 的分支列表...")
        
        # 禁用按钮
        self.fetch_branches_button.config(state=tk.DISABLED)
        
        # 在单独线程中获取分支列表
        def fetch_branches_thread():
            try:
                branches = list_repo_branches(platform, token, username, repo)
                
                if not branches:
                    self._append_log("⚠️  未找到任何分支")
                    messagebox.showinfo("提示", "未找到任何分支")
                    return
                
                # 提取分支名称
                branch_names = []
                for branch in branches:
                    branch_name = branch.get('name', '')
                    if branch_name:
                        branch_names.append(branch_name)
                
                # 更新下拉框（传入分支名称列表）
                self.root.after(0, lambda: self._update_branch_combo(branch_names, platform))
                
                # 显示成功信息
                self._append_log(f"✅ 成功获取 {len(branch_names)} 个分支")
                self._append_log(f"  分支列表已更新到下拉框中")
                
            except Exception as e:
                error_msg = str(e)
                self._append_log(f"❌ 获取分支列表失败: {error_msg}")
                messagebox.showerror("错误", f"获取分支列表失败:\n{error_msg}")
            finally:
                # 恢复按钮状态
                self.root.after(0, lambda: self.fetch_branches_button.config(state=tk.NORMAL))
        
        # 启动线程
        threading.Thread(target=fetch_branches_thread, daemon=True).start()
    
    def _update_branch_combo(self, branch_names, platform=None):
        """
        更新分支下拉框的值
        
        Args:
            branch_names: 分支名称列表
            platform: 平台名称（可选，如果不提供则从self获取）
        """
        self.branch_combo['values'] = branch_names
        
        if not branch_names:
            return
        
        # 获取当前分支值
        current_value = self.branch_var.get()
        
        # 如果当前没有选中值，或者当前值不在新列表中，则自动选择
        if not current_value or current_value not in branch_names:
            # 优先选择 master 分支（如果有的话）
            if 'master' in branch_names:
                self.branch_var.set('master')
            # 如果没有 master，根据平台选择默认分支
            elif platform:
                default_branch = 'main' if platform == 'github' else 'master'
                if default_branch in branch_names:
                    self.branch_var.set(default_branch)
                else:
                    # 如果默认分支也不存在，选择第一个
                    self.branch_var.set(branch_names[0])
            else:
                # 没有平台信息，直接选择第一个
                self.branch_var.set(branch_names[0])
    
    def _on_upload_type_change(self):
        """
        当上传类型改变时更新界面
        """
        upload_type = self.upload_type_var.get()
        if upload_type == "file":
            self.message_text.delete(1.0, tk.END)
            self.message_text.insert(tk.END, "上传文件")
        else:  # folder
            self.message_text.delete(1.0, tk.END)
            self.message_text.insert(tk.END, "上传文件夹")
    
    def _browse_path(self):
        """
        浏览选择本地文件或文件夹
        """
        if self.upload_type_var.get() == "file":
            # 选择文件
            file_path = filedialog.askopenfilename(title="选择要上传的文件")
            if file_path:
                self.local_path_var.set(file_path)
                # 自动填充远程路径（如果为空）
                if not self.git_path_var.get():
                    self.git_path_var.set(os.path.basename(file_path))
        else:
            # 选择文件夹
            folder_path = filedialog.askdirectory(title="选择要上传的文件夹")
            if folder_path:
                self.local_path_var.set(folder_path)
                # 自动填充远程路径（如果为空）
                if not self.git_path_var.get():
                    self.git_path_var.set(os.path.basename(folder_path))
    
    def _test_connection(self):
        """
        测试与Git仓库的连接
        """
        # 获取输入信息
        platform = self.platform_var.get()
        token = self.token_var.get()
        username = self.username_entry.get()
        repo = self.repo_var.get()
        
        # 验证输入
        if not self._validate_inputs(include_path=False):
            return
        
        # 清空日志
        self._clear_log()
        self._append_log(f"正在测试与 {platform} 的连接...")
        
        # 在单独线程中测试连接
        def test_connection_thread():
            try:
                # 创建客户端
                client_class = get_client_factory(platform)
                client = client_class(token, username)
                
                # 获取仓库信息
                repo_info = client.get_repo_info(repo)
                
                # 显示成功信息
                self._append_log(f"✅ 连接成功！仓库 '{repo_info['name']}' 信息获取成功")
                self._append_log(f"  - 描述: {repo_info.get('description', '无')}")
                self._append_log(f"  - 星标数: {repo_info.get('stargazers_count', 0)}")
                self._append_log(f"  - 创建时间: {repo_info.get('created_at', '')}")
                
            except Exception as e:
                self._append_log(f"❌ 连接失败: {str(e)}")
        
        # 启动线程
        threading.Thread(target=test_connection_thread).start()
    
    def _start_upload(self):
        """
        开始上传文件或文件夹
        """
        # 验证输入
        if not self._validate_inputs():
            return
        
        # 获取输入信息
        platform = self.platform_var.get()
        token = self.token_var.get()
        username = self.username_entry.get()
        repo = self.repo_var.get()
        branch = self.branch_var.get()
        local_path = self.local_path_var.get()
        git_path = self.git_path_var.get()
        message = self.message_text.get(1.0, tk.END).strip()
        upload_type = self.upload_type_var.get()
        
        # 清空日志
        self._clear_log()
        self._append_log(f"开始上传到 {platform}...")
        self._append_log(f"  - 仓库: {username}/{repo}")
        self._append_log(f"  - 分支: {branch}")
        
        # 更新按钮状态
        self.upload_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.NORMAL)
        self.test_conn_button.config(state=tk.DISABLED)
        self.save_config_button.config(state=tk.DISABLED)
        
        # 重置取消事件
        self.cancel_event.clear()
        
        # 在单独线程中执行上传
        def upload_thread():
            try:
                if upload_type == "file":
                    # 上传单个文件
                    self._append_log(f"  - 上传文件: {local_path} -> {git_path}")
                    result = upload_file_to_git(
                        platform, token, username, repo,
                        local_path, git_path, message, branch
                    )
                    self._append_log(f"✅ 文件上传成功！")
                    self._append_log(f"  - 提交SHA: {result.get('commit', {}).get('sha', '')[:7]}")
                    
                else:
                    # 上传文件夹
                    self._append_log(f"  - 上传文件夹: {local_path} -> {git_path}")
                    self._append_log("  开始逐个上传文件...")
                    
                    results = upload_folder_to_git(
                        platform, token, username, repo,
                        local_path, git_path, message, branch
                    )
                    
                    self._append_log(f"✅ 文件夹上传完成！")
                    self._append_log(f"  - 成功上传文件数: {len(results)}")
                    
            except Exception as e:
                self._append_log(f"❌ 上传失败: {str(e)}")
            finally:
                # 恢复按钮状态
                self.root.after(0, lambda: self.upload_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.cancel_button.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.test_conn_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.save_config_button.config(state=tk.NORMAL))
        
        # 启动上传线程
        self.upload_thread = threading.Thread(target=upload_thread)
        self.upload_thread.daemon = True
        self.upload_thread.start()
    
    def _cancel_upload(self):
        """
        取消上传操作
        """
        if self.upload_thread and self.upload_thread.is_alive():
            self._append_log("⏹️ 正在取消上传操作...")
            self.cancel_event.set()
    
    def _validate_inputs(self, include_path=True):
        """
        验证输入信息
        
        Args:
            include_path: 是否验证路径输入
            
        Returns:
            是否验证通过
        """
        # 验证基本信息
        if not self.token_var.get():
            messagebox.showerror("错误", "请输入访问令牌")
            return False
        
        if not self.username_entry.get():
            messagebox.showerror("错误", "请输入用户名")
            return False
        
        if not self.repo_var.get():
            messagebox.showerror("错误", "请输入或选择仓库名")
            return False
        
        if not self.branch_var.get():
            messagebox.showerror("错误", "请输入分支名")
            return False
        
        # 验证路径（如果需要）
        if include_path:
            if not self.local_path_var.get():
                messagebox.showerror("错误", "请选择本地文件或文件夹")
                return False
            
            # 检查路径是否存在
            if not os.path.exists(self.local_path_var.get()):
                messagebox.showerror("错误", "指定的本地路径不存在")
                return False
            
            # 检查路径类型是否匹配
            upload_type = self.upload_type_var.get()
            if upload_type == "file" and not os.path.isfile(self.local_path_var.get()):
                messagebox.showerror("错误", "指定的路径不是文件")
                return False
            elif upload_type == "folder" and not os.path.isdir(self.local_path_var.get()):
                messagebox.showerror("错误", "指定的路径不是文件夹")
                return False
            
            # 验证提交信息
            if not self.message_text.get(1.0, tk.END).strip():
                messagebox.showerror("错误", "请输入提交信息")
                return False
        
        return True
    
    def _append_log(self, message):
        """
        向日志窗口添加信息
        
        Args:
            message: 要添加的日志信息
        """
        def append():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)  # 滚动到底部
            self.log_text.config(state=tk.DISABLED)
        
        # 在主线程中更新UI
        self.root.after(0, append)
    
    def _clear_log(self):
        """
        清空日志窗口
        """
        def clear():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state=tk.DISABLED)
        
        # 在主线程中更新UI
        self.root.after(0, clear)
    
    def _load_config(self):
        """
        从配置文件加载设置
        """
        try:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "git_upload_config.json")
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                    # 加载配置
                    if "platform" in config:
                        self.platform_var.set(config["platform"])
                    
                    if "username" in config:
                        self.username_entry.insert(0, config["username"])
                    
                    if "token" in config:
                        self.token_var.set(config["token"])
                    
                    if "repo" in config:
                        self.repo_var.set(config["repo"])
                    
                    if "branch" in config:
                        self.branch_var.set(config["branch"])
                    
                    # 更新默认分支
                    self._on_platform_change()
                    
        except Exception as e:
            # 配置加载失败不影响程序运行
            self._append_log(f"配置加载失败: {str(e)}")
    
    def _save_config(self):
        """
        保存设置到配置文件
        """
        try:
            # 获取配置
            config = {
                "platform": self.platform_var.get(),
                "username": self.username_entry.get(),
                "token": self.token_var.get(),  # 注意：这里会保存令牌到文件
                "repo": self.repo_var.get(),
                "branch": self.branch_var.get()
            }
            
            # 保存到文件
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "git_upload_config.json")
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            
            messagebox.showinfo("成功", "配置已保存")
            self._append_log("✅ 配置已保存到 git_upload_config.json")
            
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {str(e)}")


def main():
    """
    主函数
    """
    # 创建Tkinter窗口
    root = tk.Tk()
    
    # 设置窗口图标（可选）
    try:
        # 这里可以添加图标
        pass
    except:
        pass
    
    # 创建应用实例
    app = GitUploadGUI(root)
    
    # 添加窗口关闭事件处理
    def on_closing():
        # 如果正在上传，询问是否取消
        if app.upload_thread and app.upload_thread.is_alive():
            if messagebox.askyesno("确认退出", "正在上传中，确定要退出吗？"):
                app._cancel_upload()
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # 启动主循环
    root.mainloop()


if __name__ == "__main__":
    main()