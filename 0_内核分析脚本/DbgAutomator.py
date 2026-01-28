from pykd import *
import sys
import re
import time

def execute_dbg_command(command, silent_fail=True):
    try:
        result = dbgCommand(command)
        if not result:
            return f"[INFO] 命令 '{command}' 执行成功，但无输出"
        output = result.strip()
        if not output:
            return f"[INFO] 命令 '{command}' 执行成功，但无有效输出"
        return output
    except Exception as e:
        return f"[SKIP] 命令 '{command}' 无法在用户态执行或失败: {str(e)}"

def basic_crash_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 1. 基础异常分析 (!analyze -v) =====")
    result = execute_dbg_command("!analyze -v")
    print(result)
    
    print(f"\n{time.strftime('%H:%M:%S')} ===== 2. 异常记录 (.exr -1) =====")
    # .exr -1 显示最近发生的异常代码、参数及发生地址
    print(execute_dbg_command(".exr -1", silent_fail=True))

def system_and_process_info():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 3. 进程与环境信息 =====")
    print(f"\n-- 当前进程状态 (|) --")
    print(execute_dbg_command("|", silent_fail=True))
    
    print(f"\n-- PEB (Process Environment Block) 详细信息 --")
    print(execute_dbg_command("!peb", silent_fail=True))
    
    print(f"\n-- 环境变量 --")
    print(execute_dbg_command("!envvar", silent_fail=True))
    
    print(f"\n-- 操作系统版本与时间 --")
    print(execute_dbg_command("vertarget", silent_fail=True))

def thread_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 4. 线程分析 =====")
    print(f"\n-- 所有线程列表 (~) --")
    print(execute_dbg_command("~", silent_fail=True))
    
    print(f"\n-- 当前线程 TEB (Thread Environment Block) --")
    print(execute_dbg_command("!teb", silent_fail=True))
    
    print(f"\n-- 锁资源/临界区检查 (!locks) --")
    # 用户态 !locks 查看死锁情况
    print(execute_dbg_command("!locks", silent_fail=True))

def memory_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 5. 内存与堆分析 =====")
    print(f"\n-- 虚拟内存布局摘要 (!address -summary) --")
    print(execute_dbg_command("!address -summary", silent_fail=True))
    
    print(f"\n-- 堆统计信息 (!heap -s) --")
    print(execute_dbg_command("!heap -s", silent_fail=True))
    
    print(f"\n-- 模块加载列表 (lm) --")
    print(execute_dbg_command("lm", silent_fail=True))

def stack_trace_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 6. 调用堆栈分析 =====")
    # kv: 带符号和参数的栈回溯
    stack_output = execute_dbg_command("kv", silent_fail=True)
    print(stack_output)
    
    print(f"\n-- 当前寄存器状态 (r) --")
    print(execute_dbg_command("r", silent_fail=True))
    
    print(f"\n-- 所有线程堆栈概览 (~* k) --")
    print(execute_dbg_command("~* k 10", silent_fail=True))

def handle_leak_check():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 7. 句柄分析 (!handle) =====")
    # 统计当前进程句柄
    print(execute_dbg_command("!handle 0 3", silent_fail=True))

def run_user_analysis():
    print("="*60)
    print(f"用户态 Dump 分析脚本启动")
    print(f"执行时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    basic_crash_analysis()
    system_and_process_info()
    thread_analysis()
    memory_analysis()
    handle_leak_check()
    stack_trace_analysis()
    
    print(f"\n{time.strftime('%H:%M:%S')} ===== 分析完成 =====")

if __name__ == "__main__":
    # 自动识别模式
    run_user_analysis()