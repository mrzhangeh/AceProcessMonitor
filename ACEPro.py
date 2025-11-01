import psutil
import time
import sys
import ctypes
import threading
from tkinter import Tk, Text, Scrollbar, Frame, Button, Label, END, DISABLED, NORMAL
from tkinter import font as tkfont
from typing import List

# 配置参数
TARGET_PROCESSES = ["SGuard64.exe", "SGuardSvc64.exe"]
CHECK_INTERVAL = 180  # 检查间隔（秒）
FIRST_DELAY = 180  # 首次检测延迟（秒）
TARGET_CPU = None  # 目标CPU核心（None自动选择最后一个）


class ProcessMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ACE进程限制器")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # 设置字体
        self.font = tkfont.Font(family="SimHei", size=10)
        
        # 状态变量
        self.running = True
        self.first_detection = True
        
        # 创建界面组件
        self.create_widgets()
        
        # 启动监控线程
        self.monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        self.monitor_thread.start()

    def create_widgets(self):
        # 顶部标签
        header = Label(
            self.root, 
            text="ACE进程限制器 - 监控进程: " + ", ".join(TARGET_PROCESSES),
            font=tkfont.Font(family="SimHei", size=12, weight="bold")
        )
        header.pack(pady=10, fill="x", padx=10)
        
        # 日志区域
        log_frame = Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = Text(log_frame, wrap="word", font=self.font, state=DISABLED)
        self.log_text.pack(side="left", fill="both", expand=True)
        
        scrollbar = Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        # 状态条
        self.status_var = Label(self.root, text="就绪 - 等待监控开始", bd=1, relief="sunken", anchor="w")
        self.status_var.pack(side="bottom", fill="x")
        
        # 控制按钮
        btn_frame = Frame(self.root)
        btn_frame.pack(pady=10)
        
        self.stop_btn = Button(
            btn_frame, 
            text="停止监控", 
            command=self.stop_monitoring,
            font=self.font,
            width=15,
            bg="#ff4444",
            fg="white"
        )
        self.stop_btn.pack()

    def add_log(self, message, is_success=True):
        """添加日志到文本区域"""
        time_str = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{time_str}] {message}\n"
        
        self.log_text.config(state=NORMAL)
        self.log_text.insert(END, log_entry)
        self.log_text.see(END)  # 滚动到最新日志
        self.log_text.config(state=DISABLED)
        
        # 更新状态条
        self.status_var.config(text=message)

    def get_target_priority(self):
        """获取目标优先级"""
        if psutil.WINDOWS:
            return psutil.IDLE_PRIORITY_CLASS
        else:
            self.add_log("错误：仅支持Windows系统", False)
            self.stop_monitoring()
            return None

    def get_target_core(self):
        """获取目标CPU核心"""
        if TARGET_CPU is not None:
            return [TARGET_CPU]
        cpu_count = psutil.cpu_count(logical=True)
        return [cpu_count - 1] if cpu_count > 0 else [0]

    def adjust_process(self, proc: psutil.Process, target_pri: int, target_core: List[int]):
        """调整进程优先级和CPU亲和性"""
        try:
            # 设置优先级
            if proc.nice() != target_pri:
                proc.nice(target_pri)
                self.add_log(f"已调整 {proc.name()} (PID: {proc.pid}) 优先级为 {target_pri}")
            
            # 设置CPU亲和性
            if proc.cpu_affinity() != target_core:
                proc.cpu_affinity(target_core)
                self.add_log(f"已调整 {proc.name()} (PID: {proc.pid}) CPU亲和性为 {target_core}")
            
            return True
        except psutil.AccessDenied:
            self.add_log(f"权限不足，无法调整进程 {proc.name()} (PID: {proc.pid})", False)
            return False
        except psutil.NoSuchProcess:
            self.add_log(f"进程已结束: {proc.name()} (PID: {proc.pid})")
            return False
        except Exception as e:
            self.add_log(f"调整进程出错: {str(e)}", False)
            return False

    def monitor_processes(self):
        """监控并限制目标进程"""
        target_pri = self.get_target_priority()
        if target_pri is None:
            return
            
        target_core = self.get_target_core()
        
        self.add_log(f"开始监控进程: {', '.join(TARGET_PROCESSES)}")
        self.add_log(f"目标配置: 优先级={target_pri}，CPU亲和性={target_core}")
        self.add_log(f"检查间隔: {CHECK_INTERVAL}秒，首次延迟: {FIRST_DELAY}秒")

        while self.running:
            try:
                # 遍历目标进程
                for pname in TARGET_PROCESSES:
                    for proc in psutil.process_iter(['pid', 'name']):
                        try:
                            if proc.info['name'] != pname:
                                continue

                            # 检查当前状态
                            current_pri = proc.nice()
                            current_affinity = proc.cpu_affinity()
                            need_adjust = (current_pri != target_pri) or (current_affinity != target_core)

                            if need_adjust:
                                self.add_log(f"需要调整: {pname} (PID: {proc.pid})")
                                self.add_log(f"  当前: 优先级={current_pri}, CPU亲和性={current_affinity}")
                                self.add_log(f"  目标: 优先级={target_pri}, CPU亲和性={target_core}")

                                # 首次检测延迟处理
                                if self.first_detection:
                                    self.add_log(f"首次检测到，{FIRST_DELAY}秒后进行限制...")
                                    # 倒计时显示
                                    for i in range(FIRST_DELAY, 0, -10):
                                        if not self.running:
                                            return
                                        self.status_var.config(text=f"首次检测到，{i}秒后进行限制...")
                                        time.sleep(10)
                                    
                                    self.first_detection = False

                                # 执行调整
                                self.adjust_process(proc, target_pri, target_core)
                                time.sleep(5)
                            else:
                                self.add_log(f"无需调整: {pname} (PID: {proc.pid})")

                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            self.add_log(f"跳过进程 {pname}: {str(e)}")
                        except Exception as e:
                            self.add_log(f"处理进程时出错: {str(e)}", False)

                self.add_log(f"本轮检查结束，{CHECK_INTERVAL}秒后再次检查...")
                
                # 等待期间更新状态
                for i in range(CHECK_INTERVAL, 0, -10):
                    if not self.running:
                        return
                    self.status_var.config(text=f"等待下次检查: {i}秒")
                    time.sleep(10)

            except Exception as e:
                self.add_log(f"监控线程出错: {str(e)}", False)
                time.sleep(10)

    def stop_monitoring(self):
        """停止监控并退出程序"""
        self.running = False
        self.add_log("正在停止监控...")
        self.status_var.config(text="已停止监控，即将退出")
        self.stop_btn.config(state=DISABLED, text="退出中...")
        
        # 延迟关闭，确保线程结束
        self.root.after(2000, self.root.destroy)


def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if __name__ == "__main__":
    # 检查管理员权限
    if not is_admin():
        # 尝试以管理员权限重启
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
        except:
            print("请以管理员权限运行程序")
            sys.exit(1)

    # 启动GUI
    root = Tk()
    # 确保中文显示正常
    root.option_add("*Font", "SimHei 10")
    app = ProcessMonitorGUI(root)
    root.mainloop()
